# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""PostgresTenancyStore — Postgres-backed implementation of TenancyStore.

Mirrors :class:`InMemoryTenancyStore` byte-for-byte at the SDK boundary;
the difference is durability and concurrency. Schema lives in
``spec/reference/postgres.sql``.

Every operation that touches more than one row runs inside a
``BEGIN``/``COMMIT`` block so the spec's atomicity guarantees
(membership + tuple together, accept-with-pre-tuples, transferOwnership)
are backed by a real database transaction.

Connection handling: this store accepts any object that quacks like a
psycopg3 connection — ``cursor()``, ``commit()``, ``rollback()``.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Sequence

from flametrench_ids import decode as _decode, encode as _encode, generate as _generate

from .errors import (
    AlreadyTerminalError,
    DuplicateMembershipError,
    ForbiddenError,
    IdentifierBindingRequiredError,
    IdentifierMismatchError,
    InvitationExpiredError,
    InvitationNotPendingError,
    NotFoundError,
    OrgSlugConflictError,
    PreconditionError,
    RoleHierarchyError,
    SoleOwnerError,
)
from .types import (
    AcceptInvitationResult,
    CreateOrgResult,
    Invitation,
    InvitationStatus,
    Membership,
    Organization,
    Page,
    PreTuple,
    Role,
    Status,
    TransferOwnershipResult,
    Tuple,
)

_UNIQUE_VIOLATION = "23505"

# Re-export the in-memory sentinel so callers can pass partial inputs.
class _Unset:
    """Sentinel for partial-update parameters per ADR 0011."""

    _instance: "_Unset | None" = None

    def __new__(cls) -> "_Unset":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "_UNSET"


_UNSET = _Unset()

_SLUG_PATTERN = __import__("re").compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

_ADMIN_RANK = {"owner": 4, "admin": 3, "member": 2, "guest": 1}


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def _wire_to_uuid(wire_id: str) -> str:
    return _decode(wire_id).uuid


def _validate_slug(slug: str) -> None:
    if not _SLUG_PATTERN.match(slug):
        raise PreconditionError(
            f"Slug {slug!r} does not match the spec pattern "
            "(DNS-label-style: 1-63 lowercase ASCII chars or digits or hyphens, "
            "no leading/trailing hyphen)",
            reason="org_slug_format",
        )


def _is_unique_violation(exc: Exception, constraint: str | None = None) -> bool:
    sqlstate = getattr(exc, "sqlstate", None) or getattr(getattr(exc, "diag", None), "sqlstate", None)
    if sqlstate != _UNIQUE_VIOLATION:
        return False
    if constraint is None:
        return True
    name = getattr(getattr(exc, "diag", None), "constraint_name", None)
    return name == constraint


# ─── Row → entity mappers ───

_ORG_COLS = "id, status, name, slug, created_at, updated_at"
_MEM_COLS = (
    "id, usr_id, org_id, role, status, replaces, invited_by, removed_by, "
    "created_at, updated_at"
)
_INV_COLS = (
    "id, org_id, identifier, role, status, pre_tuples, invited_by, invited_user_id, "
    "created_at, expires_at, terminal_at, terminal_by"
)
_TUP_COLS = (
    "id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by"
)


def _row_to_org(row: Sequence[Any]) -> Organization:
    return Organization(
        id=_encode("org", str(row[0])),
        status=Status(row[1]),
        created_at=row[4] if isinstance(row[4], datetime) else datetime.fromisoformat(str(row[4])),
        updated_at=row[5] if isinstance(row[5], datetime) else datetime.fromisoformat(str(row[5])),
        name=row[2],
        slug=row[3],
    )


def _row_to_mem(row: Sequence[Any]) -> Membership:
    return Membership(
        id=_encode("mem", str(row[0])),
        usr_id=_encode("usr", str(row[1])),
        org_id=_encode("org", str(row[2])),
        role=Role(row[3]),
        status=Status(row[4]),
        replaces=_encode("mem", str(row[5])) if row[5] is not None else None,
        invited_by=_encode("usr", str(row[6])) if row[6] is not None else None,
        removed_by=_encode("usr", str(row[7])) if row[7] is not None else None,
        created_at=row[8] if isinstance(row[8], datetime) else datetime.fromisoformat(str(row[8])),
        updated_at=row[9] if isinstance(row[9], datetime) else datetime.fromisoformat(str(row[9])),
    )


def _row_to_inv(row: Sequence[Any]) -> Invitation:
    raw_pre = row[5]
    pre_tuples_data: list[Any]
    if raw_pre is None:
        pre_tuples_data = []
    elif isinstance(raw_pre, list):
        pre_tuples_data = raw_pre
    elif isinstance(raw_pre, dict):
        pre_tuples_data = [raw_pre]
    else:
        decoded = json.loads(raw_pre) if isinstance(raw_pre, (str, bytes)) else None
        pre_tuples_data = decoded if isinstance(decoded, list) else []
    pre = [
        PreTuple(
            relation=str(pt.get("relation", "")),
            object_type=str(pt.get("object_type", pt.get("objectType", ""))),
            object_id=str(pt.get("object_id", pt.get("objectId", ""))),
        )
        for pt in pre_tuples_data
        if isinstance(pt, dict)
    ]
    return Invitation(
        id=_encode("inv", str(row[0])),
        org_id=_encode("org", str(row[1])),
        identifier=str(row[2]),
        role=Role(row[3]),
        status=InvitationStatus(row[4]),
        pre_tuples=pre,
        invited_by=_encode("usr", str(row[6])),
        invited_user_id=_encode("usr", str(row[7])) if row[7] is not None else None,
        created_at=row[8] if isinstance(row[8], datetime) else datetime.fromisoformat(str(row[8])),
        expires_at=row[9] if isinstance(row[9], datetime) else datetime.fromisoformat(str(row[9])),
        terminal_at=(
            row[10] if isinstance(row[10], datetime)
            else (datetime.fromisoformat(str(row[10])) if row[10] is not None else None)
        ),
        terminal_by=_encode("usr", str(row[11])) if row[11] is not None else None,
    )


def _row_to_tup(row: Sequence[Any]) -> Tuple:
    return Tuple(
        subject_type=str(row[1]),
        subject_id=_encode("usr", str(row[2])),
        relation=str(row[3]),
        object_type=str(row[4]),
        object_id=str(row[5]),
    )


class PostgresTenancyStore:
    """Postgres-backed TenancyStore. See module docstring."""

    UNSET: "_Unset" = _UNSET

    def __init__(
        self,
        connection: Any,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._conn = connection
        self._clock = clock or _default_clock

    def _now(self) -> datetime:
        return self._clock()

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        """Run the wrapped block inside an explicit transaction.

        Uses psycopg3's ``connection.transaction()`` context manager
        rather than ``commit()``/``rollback()`` directly. This is
        correct under BOTH ``autocommit=False`` (the default) AND
        ``autocommit=True``: under autocommit=True, the bare
        commit-on-success / rollback-on-error pattern would NOT hold
        ``FOR UPDATE`` row locks across statements, breaking the
        atomicity guarantees the spec requires for changeRole,
        acceptInvitation, transferOwnership, and revokeOrg cascade.
        ``transaction()`` issues an explicit ``BEGIN``/``COMMIT``
        regardless of the connection's autocommit setting.
        """
        with self._conn.transaction():
            yield self._conn

    # ─── Organizations ───

    def create_org(
        self,
        creator: str,
        *,
        name: str | None = None,
        slug: str | None = None,
    ) -> CreateOrgResult:
        if slug is not None:
            _validate_slug(slug)
        now = self._now()
        org_uuid = _decode(_generate("org")).uuid
        mem_uuid = _decode(_generate("mem")).uuid
        tup_uuid = _decode(_generate("tup")).uuid
        creator_uuid = _wire_to_uuid(creator)
        with self._tx() as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        INSERT INTO org (id, status, name, slug, created_at, updated_at)
                        VALUES (%s, 'active', %s, %s, %s, %s)
                        RETURNING {_ORG_COLS}
                        """,
                        (org_uuid, name, slug, now, now),
                    )
                    org_row = cur.fetchone()
            except Exception as exc:
                if slug is not None and _is_unique_violation(exc, "org_slug_unique"):
                    raise OrgSlugConflictError(slug) from exc
                raise
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO mem (id, usr_id, org_id, role, status, created_at, updated_at)
                    VALUES (%s, %s, %s, 'owner', 'active', %s, %s)
                    RETURNING {_MEM_COLS}
                    """,
                    (mem_uuid, creator_uuid, org_uuid, now, now),
                )
                mem_row = cur.fetchone()
                cur.execute(
                    """
                    INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)
                    VALUES (%s, 'usr', %s, 'owner', 'org', %s, %s, %s)
                    """,
                    (tup_uuid, creator_uuid, org_uuid, now, creator_uuid),
                )
        assert org_row is not None and mem_row is not None
        return CreateOrgResult(
            org=_row_to_org(org_row),
            owner_membership=_row_to_mem(mem_row),
        )

    def get_org(self, org_id: str) -> Organization:
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT {_ORG_COLS} FROM org WHERE id = %s", (_wire_to_uuid(org_id),))
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"Organization {org_id} not found")
        return _row_to_org(row)

    def update_org(
        self,
        org_id: str,
        *,
        name: object = _UNSET,
        slug: object = _UNSET,
    ) -> Organization:
        with self._tx() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT {_ORG_COLS} FROM org WHERE id = %s FOR UPDATE",
                    (_wire_to_uuid(org_id),),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"Organization {org_id} not found")
                if row[1] == Status.REVOKED.value:
                    raise AlreadyTerminalError(f"Org {org_id} is revoked; cannot update")
                new_name = row[2] if isinstance(name, _Unset) else name
                new_slug = row[3] if isinstance(slug, _Unset) else slug
                if not isinstance(slug, _Unset) and new_slug is not None:
                    _validate_slug(new_slug)  # type: ignore[arg-type]
                try:
                    cur.execute(
                        f"""
                        UPDATE org SET name = %s, slug = %s, updated_at = %s
                        WHERE id = %s
                        RETURNING {_ORG_COLS}
                        """,
                        (new_name, new_slug, self._now(), _wire_to_uuid(org_id)),
                    )
                    updated = cur.fetchone()
                except Exception as exc:
                    if new_slug is not None and _is_unique_violation(exc, "org_slug_unique"):
                        raise OrgSlugConflictError(new_slug) from exc  # type: ignore[arg-type]
                    raise
        assert updated is not None
        return _row_to_org(updated)

    def _transition_org(self, org_id: str, to: Status) -> Organization:
        with self._tx() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT {_ORG_COLS} FROM org WHERE id = %s FOR UPDATE",
                    (_wire_to_uuid(org_id),),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"Organization {org_id} not found")
                if row[1] == Status.REVOKED.value:
                    raise AlreadyTerminalError(f"Org {org_id} is revoked; cannot transition")
                if row[1] == to.value:
                    raise AlreadyTerminalError(f"Org {org_id} is already {to.value}")
                cur.execute(
                    f"""
                    UPDATE org SET status = %s, updated_at = %s WHERE id = %s
                    RETURNING {_ORG_COLS}
                    """,
                    (to.value, self._now(), _wire_to_uuid(org_id)),
                )
                updated = cur.fetchone()
        assert updated is not None
        return _row_to_org(updated)

    def suspend_org(self, org_id: str) -> Organization:
        return self._transition_org(org_id, Status.SUSPENDED)

    def reinstate_org(self, org_id: str) -> Organization:
        with self._tx() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT {_ORG_COLS} FROM org WHERE id = %s FOR UPDATE",
                    (_wire_to_uuid(org_id),),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"Organization {org_id} not found")
                if row[1] != Status.SUSPENDED.value:
                    raise PreconditionError(
                        f"Org {org_id} is {row[1]}; only suspended orgs can be reinstated",
                        reason="invalid_transition",
                    )
                cur.execute(
                    f"""
                    UPDATE org SET status = 'active', updated_at = %s WHERE id = %s
                    RETURNING {_ORG_COLS}
                    """,
                    (self._now(), _wire_to_uuid(org_id)),
                )
                updated = cur.fetchone()
        assert updated is not None
        return _row_to_org(updated)

    def revoke_org(self, org_id: str) -> Organization:
        with self._tx() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT {_ORG_COLS} FROM org WHERE id = %s FOR UPDATE",
                    (_wire_to_uuid(org_id),),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"Organization {org_id} not found")
                if row[1] == Status.REVOKED.value:
                    raise AlreadyTerminalError(f"Org {org_id} is already revoked")
                now = self._now()
                org_uuid = _wire_to_uuid(org_id)
                cur.execute(
                    "DELETE FROM tup WHERE object_type = 'org' AND object_id = %s",
                    (org_uuid,),
                )
                cur.execute(
                    "UPDATE mem SET status = 'revoked', updated_at = %s "
                    "WHERE org_id = %s AND status = 'active'",
                    (now, org_uuid),
                )
                cur.execute(
                    f"""
                    UPDATE org SET status = 'revoked', updated_at = %s WHERE id = %s
                    RETURNING {_ORG_COLS}
                    """,
                    (now, org_uuid),
                )
                updated = cur.fetchone()
        assert updated is not None
        return _row_to_org(updated)

    # ─── Memberships ───

    def add_member(
        self,
        org_id: str,
        usr_id: str,
        role: Role,
        *,
        invited_by: str | None = None,
    ) -> Membership:
        with self._tx() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM org WHERE id = %s", (_wire_to_uuid(org_id),))
                org_row = cur.fetchone()
                if org_row is None:
                    raise NotFoundError(f"Organization {org_id} not found")
                if org_row[0] != Status.ACTIVE.value:
                    raise PreconditionError(
                        f"Cannot add member to {org_row[0]} org",
                        reason="org_not_active",
                    )
                mem_uuid = _decode(_generate("mem")).uuid
                tup_uuid = _decode(_generate("tup")).uuid
                now = self._now()
                usr_uuid = _wire_to_uuid(usr_id)
                org_uuid = _wire_to_uuid(org_id)
                invited_by_uuid = _wire_to_uuid(invited_by) if invited_by is not None else None
                try:
                    cur.execute(
                        f"""
                        INSERT INTO mem (id, usr_id, org_id, role, status, invited_by, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, 'active', %s, %s, %s)
                        RETURNING {_MEM_COLS}
                        """,
                        (mem_uuid, usr_uuid, org_uuid, role.value, invited_by_uuid, now, now),
                    )
                    mem_row = cur.fetchone()
                    cur.execute(
                        """
                        INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)
                        VALUES (%s, 'usr', %s, %s, 'org', %s, %s, %s)
                        """,
                        (tup_uuid, usr_uuid, role.value, org_uuid, now, invited_by_uuid),
                    )
                except Exception as exc:
                    if _is_unique_violation(exc):
                        raise DuplicateMembershipError(
                            f"User {usr_id} already has an active membership in {org_id}",
                        ) from exc
                    raise
        assert mem_row is not None
        return _row_to_mem(mem_row)

    def get_membership(self, mem_id: str) -> Membership:
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT {_MEM_COLS} FROM mem WHERE id = %s", (_wire_to_uuid(mem_id),))
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"Membership {mem_id} not found")
        return _row_to_mem(row)

    def list_members(
        self,
        org_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        status: Status | None = None,
    ) -> Page[Membership]:
        params: list[Any] = [_wire_to_uuid(org_id)]
        sql = f"SELECT {_MEM_COLS} FROM mem WHERE org_id = %s"
        if status is not None:
            sql += " AND status = %s"
            params.append(status.value)
        if cursor is not None:
            sql += " AND id > %s"
            params.append(_wire_to_uuid(cursor))
        sql += " ORDER BY id LIMIT %s"
        params.append(limit)
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        data = [_row_to_mem(r) for r in rows]
        next_cursor = data[-1].id if len(data) == limit and data else None
        return Page(data=data, next_cursor=next_cursor)

    def _lock_mem(self, conn: Any, mem_id: str) -> Sequence[Any]:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_MEM_COLS} FROM mem WHERE id = %s FOR UPDATE",
                (_wire_to_uuid(mem_id),),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"Membership {mem_id} not found")
        return row

    def _count_owners(self, conn: Any, org_uuid: str) -> int:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM mem WHERE org_id = %s AND role = 'owner' AND status = 'active'",
                (org_uuid,),
            )
            count = cur.fetchone()
        return int(count[0]) if count else 0

    def _rotate_membership(
        self,
        conn: Any,
        old: Sequence[Any],
        new_role: Role,
        *,
        removed_by: str | None,
    ) -> Membership:
        now = self._now()
        new_mem_uuid = _decode(_generate("mem")).uuid
        new_tup_uuid = _decode(_generate("tup")).uuid
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE mem SET status = 'revoked', updated_at = %s WHERE id = %s",
                (now, old[0]),
            )
            cur.execute(
                "DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = %s "
                "AND relation = %s AND object_type = 'org' AND object_id = %s",
                (old[1], old[3], old[2]),
            )
            cur.execute(
                f"""
                INSERT INTO mem (id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at)
                VALUES (%s, %s, %s, %s, 'active', %s, %s, %s, %s, %s)
                RETURNING {_MEM_COLS}
                """,
                (
                    new_mem_uuid, old[1], old[2], new_role.value,
                    old[0], old[6], removed_by, now, now,
                ),
            )
            new_row = cur.fetchone()
            cur.execute(
                """
                INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at)
                VALUES (%s, 'usr', %s, %s, 'org', %s, %s)
                """,
                (new_tup_uuid, old[1], new_role.value, old[2], now),
            )
        assert new_row is not None
        return _row_to_mem(new_row)

    def change_role(self, mem_id: str, new_role: Role) -> Membership:
        with self._tx() as conn:
            old = self._lock_mem(conn, mem_id)
            if old[4] != Status.ACTIVE.value:
                raise PreconditionError(
                    f"Membership {mem_id} is {old[4]}; only active memberships can change role",
                    reason="mem_not_active",
                )
            if old[3] == "owner" and new_role != Role.OWNER:
                if self._count_owners(conn, old[2]) == 1:
                    raise SoleOwnerError(
                        "Cannot change role of the sole active owner; transfer ownership first",
                    )
            return self._rotate_membership(conn, old, new_role, removed_by=None)

    def suspend_membership(self, mem_id: str) -> Membership:
        with self._tx() as conn:
            mem = self._lock_mem(conn, mem_id)
            if mem[4] != Status.ACTIVE.value:
                raise PreconditionError(
                    f"Membership {mem_id} is {mem[4]}; only active memberships can be suspended",
                    reason="mem_not_active",
                )
            if mem[3] == "owner" and self._count_owners(conn, mem[2]) == 1:
                raise SoleOwnerError(
                    "Cannot suspend the sole active owner; transfer ownership first",
                )
            now = self._now()
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = %s "
                    "AND relation = %s AND object_type = 'org' AND object_id = %s",
                    (mem[1], mem[3], mem[2]),
                )
                cur.execute(
                    f"""
                    UPDATE mem SET status = 'suspended', updated_at = %s WHERE id = %s
                    RETURNING {_MEM_COLS}
                    """,
                    (now, mem[0]),
                )
                row = cur.fetchone()
        assert row is not None
        return _row_to_mem(row)

    def reinstate_membership(self, mem_id: str) -> Membership:
        with self._tx() as conn:
            mem = self._lock_mem(conn, mem_id)
            if mem[4] != Status.SUSPENDED.value:
                raise PreconditionError(
                    f"Membership {mem_id} is {mem[4]}; only suspended memberships can be reinstated",
                    reason="invalid_transition",
                )
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM mem WHERE usr_id = %s AND org_id = %s AND status = 'active'",
                    (mem[1], mem[2]),
                )
                cnt = cur.fetchone()
                if cnt and int(cnt[0]) > 0:
                    raise DuplicateMembershipError(
                        "User has a separate active membership in this org; cannot reinstate",
                    )
                now = self._now()
                tup_uuid = _decode(_generate("tup")).uuid
                cur.execute(
                    f"""
                    UPDATE mem SET status = 'active', updated_at = %s WHERE id = %s
                    RETURNING {_MEM_COLS}
                    """,
                    (now, mem[0]),
                )
                row = cur.fetchone()
                cur.execute(
                    """
                    INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at)
                    VALUES (%s, 'usr', %s, %s, 'org', %s, %s)
                    """,
                    (tup_uuid, mem[1], mem[3], mem[2], now),
                )
        assert row is not None
        return _row_to_mem(row)

    def self_leave(
        self, mem_id: str, *, transfer_to: str | None = None,
    ) -> Membership:
        with self._tx() as conn:
            mem = self._lock_mem(conn, mem_id)
            if mem[4] != Status.ACTIVE.value:
                raise PreconditionError(
                    f"Membership {mem_id} is {mem[4]}; only active memberships can self-leave",
                    reason="mem_not_active",
                )
            if mem[3] == "owner" and self._count_owners(conn, mem[2]) == 1:
                if transfer_to is None:
                    raise SoleOwnerError(
                        "Cannot self-leave as sole active owner; pass transfer_to "
                        "to atomically transfer ownership",
                    )
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        SELECT {_MEM_COLS} FROM mem
                        WHERE usr_id = %s AND org_id = %s AND status = 'active'
                        FOR UPDATE
                        """,
                        (_wire_to_uuid(transfer_to), mem[2]),
                    )
                    target = cur.fetchone()
                if target is None:
                    raise NotFoundError(
                        f"transfer_to user {transfer_to} has no active membership in org",
                    )
                self._rotate_membership(conn, target, Role.OWNER, removed_by=None)
            now = self._now()
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = %s "
                    "AND relation = %s AND object_type = 'org' AND object_id = %s",
                    (mem[1], mem[3], mem[2]),
                )
                cur.execute(
                    f"""
                    UPDATE mem SET status = 'revoked', removed_by = NULL, updated_at = %s
                    WHERE id = %s
                    RETURNING {_MEM_COLS}
                    """,
                    (now, mem[0]),
                )
                row = cur.fetchone()
        assert row is not None
        return _row_to_mem(row)

    def admin_remove(self, mem_id: str, admin_usr_id: str) -> Membership:
        with self._tx() as conn:
            target = self._lock_mem(conn, mem_id)
            if target[4] != Status.ACTIVE.value:
                raise PreconditionError(
                    f"Target membership {mem_id} is {target[4]}",
                    reason="mem_not_active",
                )
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT usr_id, role, status FROM mem "
                    "WHERE usr_id = %s AND org_id = %s AND status = 'active'",
                    (_wire_to_uuid(admin_usr_id), target[2]),
                )
                admin = cur.fetchone()
            if admin is None:
                raise ForbiddenError(
                    f"User {admin_usr_id} has no active membership in target org",
                )
            if admin[1] not in ("owner", "admin"):
                raise ForbiddenError(
                    f"Role {admin[1]} is not permitted to remove members",
                )
            if target[3] == "owner":
                raise RoleHierarchyError(
                    "Owner removal requires transfer_ownership, not admin_remove",
                )
            admin_rank = _ADMIN_RANK.get(admin[1])
            target_rank = _ADMIN_RANK.get(target[3])
            if admin_rank is None or target_rank is None:
                raise PreconditionError(
                    "admin_remove operates only on owner/admin/member/guest roles",
                    reason="scope_mismatch",
                )
            if admin_rank < target_rank:
                raise RoleHierarchyError(
                    f"Role {admin[1]} cannot remove role {target[3]}",
                )
            now = self._now()
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = %s "
                    "AND relation = %s AND object_type = 'org' AND object_id = %s",
                    (target[1], target[3], target[2]),
                )
                cur.execute(
                    f"""
                    UPDATE mem SET status = 'revoked', removed_by = %s, updated_at = %s
                    WHERE id = %s
                    RETURNING {_MEM_COLS}
                    """,
                    (admin[0], now, target[0]),
                )
                row = cur.fetchone()
        assert row is not None
        return _row_to_mem(row)

    def transfer_ownership(
        self, org_id: str, from_mem_id: str, to_mem_id: str,
    ) -> TransferOwnershipResult:
        with self._tx() as conn:
            org_uuid = _wire_to_uuid(org_id)
            from_row = self._lock_mem(conn, from_mem_id)
            to_row = self._lock_mem(conn, to_mem_id)
            if from_row[4] != Status.ACTIVE.value:
                raise PreconditionError(
                    f"From membership is {from_row[4]}", reason="from_not_active",
                )
            if to_row[4] != Status.ACTIVE.value:
                raise PreconditionError(
                    f"To membership is {to_row[4]}", reason="to_not_active",
                )
            if str(from_row[2]) != org_uuid or str(to_row[2]) != org_uuid:
                raise PreconditionError(
                    f"Both memberships must belong to {org_id}", reason="org_mismatch",
                )
            if from_row[3] != "owner":
                raise PreconditionError(
                    "From membership must hold the owner role", reason="from_not_owner",
                )
            if from_row[1] == to_row[1]:
                raise PreconditionError(
                    "Cannot transfer ownership to self", reason="self_transfer",
                )
            to_membership = self._rotate_membership(conn, to_row, Role.OWNER, removed_by=None)
            from_membership = self._rotate_membership(conn, from_row, Role.MEMBER, removed_by=None)
        return TransferOwnershipResult(
            from_membership=from_membership,
            to_membership=to_membership,
        )

    # ─── Invitations ───

    def create_invitation(
        self,
        org_id: str,
        identifier: str,
        role: Role,
        invited_by: str,
        expires_at: datetime,
        *,
        pre_tuples: list[PreTuple] | None = None,
    ) -> Invitation:
        org = self.get_org(org_id)
        if org.status != Status.ACTIVE:
            raise PreconditionError(
                f"Cannot create invitation for {org.status.value} org",
                reason="org_not_active",
            )
        now = self._now()
        if expires_at <= now:
            raise PreconditionError("expires_at must be in the future", reason="past_expiration")
        inv_uuid = _decode(_generate("inv")).uuid
        pre_payload = json.dumps([
            {"relation": pt.relation, "object_type": pt.object_type, "object_id": pt.object_id}
            for pt in (pre_tuples or [])
        ])
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO inv (id, org_id, identifier, role, status, pre_tuples, invited_by, created_at, expires_at)
                VALUES (%s, %s, %s, %s, 'pending', %s::jsonb, %s, %s, %s)
                RETURNING {_INV_COLS}
                """,
                (
                    inv_uuid, _wire_to_uuid(org_id), identifier, role.value,
                    pre_payload, _wire_to_uuid(invited_by), now, expires_at,
                ),
            )
            row = cur.fetchone()
        self._conn.commit()
        assert row is not None
        return _row_to_inv(row)

    def get_invitation(self, inv_id: str) -> Invitation:
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT {_INV_COLS} FROM inv WHERE id = %s", (_wire_to_uuid(inv_id),))
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"Invitation {inv_id} not found")
        return _row_to_inv(row)

    def list_invitations(
        self,
        org_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        status: InvitationStatus | None = None,
    ) -> Page[Invitation]:
        params: list[Any] = [_wire_to_uuid(org_id)]
        sql = f"SELECT {_INV_COLS} FROM inv WHERE org_id = %s"
        if status is not None:
            sql += " AND status = %s"
            params.append(status.value)
        if cursor is not None:
            sql += " AND id > %s"
            params.append(_wire_to_uuid(cursor))
        sql += " ORDER BY id LIMIT %s"
        params.append(limit)
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        data = [_row_to_inv(r) for r in rows]
        next_cursor = data[-1].id if len(data) == limit and data else None
        return Page(data=data, next_cursor=next_cursor)

    def accept_invitation(
        self,
        inv_id: str,
        *,
        as_usr_id: str | None = None,
        accepting_identifier: str | None = None,
    ) -> AcceptInvitationResult:
        with self._tx() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT {_INV_COLS} FROM inv WHERE id = %s FOR UPDATE",
                    (_wire_to_uuid(inv_id),),
                )
                inv_row = cur.fetchone()
            if inv_row is None:
                raise NotFoundError(f"Invitation {inv_id} not found")
            if inv_row[4] != InvitationStatus.PENDING.value:
                raise InvitationNotPendingError(
                    f"Invitation {inv_id} is {inv_row[4]}, not pending",
                )
            now = self._now()
            expires_at = (
                inv_row[9] if isinstance(inv_row[9], datetime)
                else datetime.fromisoformat(str(inv_row[9]))
            )
            if now > expires_at:
                raise InvitationExpiredError(
                    f"Invitation {inv_id} expired at {expires_at.isoformat()}",
                )
            # ADR 0009.
            if as_usr_id is not None:
                if accepting_identifier is None:
                    raise IdentifierBindingRequiredError()
                if accepting_identifier != inv_row[2]:
                    raise IdentifierMismatchError(accepting_identifier, str(inv_row[2]))
            usr_uuid = _wire_to_uuid(as_usr_id) if as_usr_id is not None else _decode(_generate("usr")).uuid
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM mem WHERE usr_id = %s AND org_id = %s AND status = 'active'",
                    (usr_uuid, inv_row[1]),
                )
                cnt = cur.fetchone()
            if cnt and int(cnt[0]) > 0:
                raise DuplicateMembershipError(
                    "User already has an active membership in this org",
                )
            mem_uuid = _decode(_generate("mem")).uuid
            tup_uuid = _decode(_generate("tup")).uuid
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO mem (id, usr_id, org_id, role, status, invited_by, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, 'active', %s, %s, %s)
                    RETURNING {_MEM_COLS}
                    """,
                    (mem_uuid, usr_uuid, inv_row[1], inv_row[3], inv_row[6], now, now),
                )
                mem_row = cur.fetchone()
                cur.execute(
                    """
                    INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at)
                    VALUES (%s, 'usr', %s, %s, 'org', %s, %s)
                    """,
                    (tup_uuid, usr_uuid, inv_row[3], inv_row[1], now),
                )
            materialized: list[Tuple] = []
            raw_pre = inv_row[5]
            pre_list: list[Any]
            if raw_pre is None:
                pre_list = []
            elif isinstance(raw_pre, list):
                pre_list = raw_pre
            else:
                decoded = json.loads(raw_pre) if isinstance(raw_pre, (str, bytes)) else None
                pre_list = decoded if isinstance(decoded, list) else []
            for pt in pre_list:
                if not isinstance(pt, dict):
                    continue
                relation = str(pt.get("relation", ""))
                object_type = str(pt.get("object_type", pt.get("objectType", "")))
                object_id = str(pt.get("object_id", pt.get("objectId", "")))
                pt_tup_uuid = _decode(_generate("tup")).uuid
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at)
                        VALUES (%s, 'usr', %s, %s, %s, %s, %s)
                        """,
                        (pt_tup_uuid, usr_uuid, relation, object_type, object_id, now),
                    )
                materialized.append(Tuple(
                    subject_type="usr",
                    subject_id=_encode("usr", usr_uuid),
                    relation=relation,
                    object_type=object_type,
                    object_id=object_id,
                ))
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE inv SET status = 'accepted', terminal_at = %s, terminal_by = %s, invited_user_id = %s
                    WHERE id = %s
                    RETURNING {_INV_COLS}
                    """,
                    (now, usr_uuid, usr_uuid, inv_row[0]),
                )
                inv_out = cur.fetchone()
        assert inv_out is not None and mem_row is not None
        return AcceptInvitationResult(
            invitation=_row_to_inv(inv_out),
            membership=_row_to_mem(mem_row),
            materialized_tuples=materialized,
        )

    def decline_invitation(
        self, inv_id: str, *, as_usr_id: str | None = None,
    ) -> Invitation:
        with self._tx() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status FROM inv WHERE id = %s FOR UPDATE",
                    (_wire_to_uuid(inv_id),),
                )
                row = cur.fetchone()
            if row is None:
                raise NotFoundError(f"Invitation {inv_id} not found")
            if row[1] != InvitationStatus.PENDING.value:
                raise InvitationNotPendingError(f"Invitation {inv_id} is {row[1]}")
            now = self._now()
            by = _wire_to_uuid(as_usr_id) if as_usr_id is not None else None
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE inv SET status = 'declined', terminal_at = %s, terminal_by = %s
                    WHERE id = %s
                    RETURNING {_INV_COLS}
                    """,
                    (now, by, row[0]),
                )
                updated = cur.fetchone()
        assert updated is not None
        return _row_to_inv(updated)

    def revoke_invitation(self, inv_id: str, admin_usr_id: str) -> Invitation:
        with self._tx() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status FROM inv WHERE id = %s FOR UPDATE",
                    (_wire_to_uuid(inv_id),),
                )
                row = cur.fetchone()
            if row is None:
                raise NotFoundError(f"Invitation {inv_id} not found")
            if row[1] != InvitationStatus.PENDING.value:
                raise InvitationNotPendingError(f"Invitation {inv_id} is {row[1]}")
            now = self._now()
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE inv SET status = 'revoked', terminal_at = %s, terminal_by = %s
                    WHERE id = %s
                    RETURNING {_INV_COLS}
                    """,
                    (now, _wire_to_uuid(admin_usr_id), row[0]),
                )
                updated = cur.fetchone()
        assert updated is not None
        return _row_to_inv(updated)

    # ─── Tuple accessors ───

    def list_tuples_for_subject(
        self, subject_type: str, subject_id: str,
    ) -> list[Tuple]:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {_TUP_COLS} FROM tup "
                "WHERE subject_type = %s AND subject_id = %s",
                (subject_type, _wire_to_uuid(subject_id)),
            )
            rows = cur.fetchall()
        return [_row_to_tup(r) for r in rows]

    def list_tuples_for_object(
        self, object_type: str, object_id: str, *, relation: str | None = None,
    ) -> list[Tuple]:
        params: list[Any] = [object_type, object_id]
        sql = f"SELECT {_TUP_COLS} FROM tup WHERE object_type = %s AND object_id = %s"
        if relation is not None:
            sql += " AND relation = %s"
            params.append(relation)
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [_row_to_tup(r) for r in rows]
