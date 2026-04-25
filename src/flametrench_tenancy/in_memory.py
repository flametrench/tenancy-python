# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Reference in-memory TenancyStore implementation.

Behaviorally spec-conformant for every transition:
- revoke-and-re-add with ``replaces`` chain on role changes,
- atomic accept-with-pre-tuples,
- sole-owner protection on all relevant paths,
- shadow tuple set kept in lockstep with mem.status so the mem_/tup_
  duality cannot drift.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from flametrench_ids import generate

from .errors import (
    AlreadyTerminalError,
    DuplicateMembershipError,
    ForbiddenError,
    InvitationExpiredError,
    InvitationNotPendingError,
    NotFoundError,
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


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def _tuple_key(t: Tuple) -> str:
    return f"{t.subject_type}|{t.subject_id}|{t.relation}|{t.object_type}|{t.object_id}"


def _membership_tuple(m: Membership) -> Tuple:
    return Tuple(
        subject_type="usr",
        subject_id=m.usr_id,
        relation=m.role.value,
        object_type="org",
        object_id=m.org_id,
    )


class InMemoryTenancyStore:
    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._orgs: dict[str, Organization] = {}
        self._memberships: dict[str, Membership] = {}
        self._invitations: dict[str, Invitation] = {}
        self._tuple_keys: set[str] = set()
        self._clock = clock or _default_clock

    # ─── Helpers ───

    def _now(self) -> datetime:
        return self._clock()

    def _insert_tuple(self, t: Tuple) -> None:
        self._tuple_keys.add(_tuple_key(t))

    def _delete_tuple(self, t: Tuple) -> None:
        self._tuple_keys.discard(_tuple_key(t))

    def _count_active_owners(self, org_id: str) -> int:
        return sum(
            1
            for m in self._memberships.values()
            if m.org_id == org_id
            and m.status == Status.ACTIVE
            and m.role == Role.OWNER
        )

    def _find_active_membership(
        self, usr_id: str, org_id: str
    ) -> Membership | None:
        for m in self._memberships.values():
            if (
                m.usr_id == usr_id
                and m.org_id == org_id
                and m.status == Status.ACTIVE
            ):
                return m
        return None

    def _require_org(self, org_id: str) -> Organization:
        org = self._orgs.get(org_id)
        if org is None:
            raise NotFoundError(f"Organization {org_id} not found")
        return org

    def _require_membership(self, mem_id: str) -> Membership:
        m = self._memberships.get(mem_id)
        if m is None:
            raise NotFoundError(f"Membership {mem_id} not found")
        return m

    @staticmethod
    def _paginate(
        all_items: list, cursor: str | None, limit: int
    ):  # type: ignore[type-arg]
        if cursor is not None:
            start = 0
            for i, item in enumerate(all_items):
                if item.id > cursor:
                    start = i
                    break
                start = i + 1
        else:
            start = 0
        slice_ = all_items[start : start + limit]
        next_cursor = (
            slice_[-1].id
            if (start + limit) < len(all_items) and len(slice_) > 0
            else None
        )
        return Page(data=slice_, next_cursor=next_cursor)

    # ─── Organizations ───

    def create_org(self, creator: str) -> CreateOrgResult:
        now = self._now()
        org = Organization(
            id=generate("org"),
            status=Status.ACTIVE,
            created_at=now,
            updated_at=now,
        )
        owner_membership = Membership(
            id=generate("mem"),
            usr_id=creator,
            org_id=org.id,
            role=Role.OWNER,
            status=Status.ACTIVE,
            replaces=None,
            invited_by=None,
            removed_by=None,
            created_at=now,
            updated_at=now,
        )
        self._orgs[org.id] = org
        self._memberships[owner_membership.id] = owner_membership
        self._insert_tuple(_membership_tuple(owner_membership))
        return CreateOrgResult(org=org, owner_membership=owner_membership)

    def get_org(self, org_id: str) -> Organization:
        return self._require_org(org_id)

    def _transition_org(self, org_id: str, to: Status) -> Organization:
        org = self._require_org(org_id)
        if org.status == to:
            raise AlreadyTerminalError(f"Org {org_id} is already {to.value}")
        if org.status == Status.REVOKED:
            raise AlreadyTerminalError(
                f"Org {org_id} is revoked; cannot transition"
            )
        updated = org.with_status(to, self._now())
        self._orgs[org_id] = updated
        return updated

    def suspend_org(self, org_id: str) -> Organization:
        return self._transition_org(org_id, Status.SUSPENDED)

    def reinstate_org(self, org_id: str) -> Organization:
        org = self._require_org(org_id)
        if org.status != Status.SUSPENDED:
            raise PreconditionError(
                f"Org {org_id} is {org.status.value}; only suspended orgs can be reinstated",
                reason="invalid_transition",
            )
        return self._transition_org(org_id, Status.ACTIVE)

    def revoke_org(self, org_id: str) -> Organization:
        org = self._require_org(org_id)
        if org.status == Status.REVOKED:
            raise AlreadyTerminalError(f"Org {org_id} is already revoked")
        now = self._now()
        for mid, m in list(self._memberships.items()):
            if m.org_id == org_id and m.status == Status.ACTIVE:
                self._delete_tuple(_membership_tuple(m))
                self._memberships[mid] = m.replace(
                    status=Status.REVOKED, updated_at=now
                )
        updated = org.with_status(Status.REVOKED, now)
        self._orgs[org_id] = updated
        return updated

    # ─── Memberships ───

    def add_member(
        self, org_id: str, usr_id: str, role: Role, *, invited_by: str | None = None
    ) -> Membership:
        org = self._require_org(org_id)
        if org.status != Status.ACTIVE:
            raise PreconditionError(
                f"Cannot add member to {org.status.value} org",
                reason="org_not_active",
            )
        if self._find_active_membership(usr_id, org_id) is not None:
            raise DuplicateMembershipError(
                f"User {usr_id} already has an active membership in {org_id}"
            )
        now = self._now()
        mem = Membership(
            id=generate("mem"),
            usr_id=usr_id,
            org_id=org_id,
            role=role,
            status=Status.ACTIVE,
            replaces=None,
            invited_by=invited_by,
            removed_by=None,
            created_at=now,
            updated_at=now,
        )
        self._memberships[mem.id] = mem
        self._insert_tuple(_membership_tuple(mem))
        return mem

    def get_membership(self, mem_id: str) -> Membership:
        return self._require_membership(mem_id)

    def list_members(
        self,
        org_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        status: Status | None = None,
    ) -> Page[Membership]:
        all_ = sorted(
            (
                m
                for m in self._memberships.values()
                if m.org_id == org_id and (status is None or m.status == status)
            ),
            key=lambda m: m.id,
        )
        return self._paginate(all_, cursor, limit)

    def change_role(self, mem_id: str, new_role: Role) -> Membership:
        old = self._require_membership(mem_id)
        if old.status != Status.ACTIVE:
            raise PreconditionError(
                f"Membership {mem_id} is {old.status.value}; only active memberships can change role",
                reason="mem_not_active",
            )
        if (
            old.role == Role.OWNER
            and new_role != Role.OWNER
            and self._count_active_owners(old.org_id) == 1
        ):
            raise SoleOwnerError(
                "Cannot change role of the sole active owner; transfer ownership first",
            )
        now = self._now()
        revoked = old.replace(status=Status.REVOKED, updated_at=now)
        self._memberships[old.id] = revoked
        self._delete_tuple(_membership_tuple(old))

        fresh = Membership(
            id=generate("mem"),
            usr_id=old.usr_id,
            org_id=old.org_id,
            role=new_role,
            status=Status.ACTIVE,
            replaces=old.id,
            invited_by=old.invited_by,
            removed_by=None,
            created_at=now,
            updated_at=now,
        )
        self._memberships[fresh.id] = fresh
        self._insert_tuple(_membership_tuple(fresh))
        return fresh

    def suspend_membership(self, mem_id: str) -> Membership:
        mem = self._require_membership(mem_id)
        if mem.status != Status.ACTIVE:
            raise PreconditionError(
                f"Membership {mem_id} is {mem.status.value}; only active memberships can be suspended",
                reason="mem_not_active",
            )
        if (
            mem.role == Role.OWNER
            and self._count_active_owners(mem.org_id) == 1
        ):
            raise SoleOwnerError(
                "Cannot suspend the sole active owner; transfer ownership first",
            )
        now = self._now()
        updated = mem.replace(status=Status.SUSPENDED, updated_at=now)
        self._memberships[mem_id] = updated
        self._delete_tuple(_membership_tuple(mem))
        return updated

    def reinstate_membership(self, mem_id: str) -> Membership:
        mem = self._require_membership(mem_id)
        if mem.status != Status.SUSPENDED:
            raise PreconditionError(
                f"Membership {mem_id} is {mem.status.value}; only suspended memberships can be reinstated",
                reason="invalid_transition",
            )
        if self._find_active_membership(mem.usr_id, mem.org_id) is not None:
            raise DuplicateMembershipError(
                f"User {mem.usr_id} has a separate active membership in {mem.org_id}; cannot reinstate"
            )
        now = self._now()
        updated = mem.replace(status=Status.ACTIVE, updated_at=now)
        self._memberships[mem_id] = updated
        self._insert_tuple(_membership_tuple(updated))
        return updated

    def self_leave(
        self, mem_id: str, *, transfer_to: str | None = None
    ) -> Membership:
        mem = self._require_membership(mem_id)
        if mem.status != Status.ACTIVE:
            raise PreconditionError(
                f"Membership {mem_id} is {mem.status.value}; only active memberships can self-leave",
                reason="mem_not_active",
            )
        if (
            mem.role == Role.OWNER
            and self._count_active_owners(mem.org_id) == 1
        ):
            if transfer_to is None:
                raise SoleOwnerError(
                    "Cannot self-leave as sole active owner; pass transfer_to to atomically transfer ownership",
                )
            target = self._find_active_membership(transfer_to, mem.org_id)
            if target is None:
                raise NotFoundError(
                    f"transfer_to user {transfer_to} has no active membership in {mem.org_id}",
                )
            # Promote target to owner; this creates a second active owner so
            # the subsequent self-revoke does not trip the sole-owner guard.
            self.change_role(target.id, Role.OWNER)
        now = self._now()
        revoked = mem.replace(status=Status.REVOKED, removed_by=None, updated_at=now)
        self._memberships[mem.id] = revoked
        self._delete_tuple(_membership_tuple(mem))
        return revoked

    def admin_remove(self, mem_id: str, admin_usr_id: str) -> Membership:
        target = self._require_membership(mem_id)
        if target.status != Status.ACTIVE:
            raise PreconditionError(
                f"Target membership {mem_id} is {target.status.value}",
                reason="mem_not_active",
            )
        admin = self._find_active_membership(admin_usr_id, target.org_id)
        if admin is None:
            raise ForbiddenError(
                f"User {admin_usr_id} has no active membership in {target.org_id}",
            )
        if admin.role not in (Role.OWNER, Role.ADMIN):
            raise ForbiddenError(
                f"Role {admin.role.value} is not permitted to remove members",
            )
        if target.role == Role.OWNER:
            raise RoleHierarchyError(
                "Owner removal requires transfer_ownership, not admin_remove",
            )
        admin_rank = admin.role.admin_rank()
        target_rank = target.role.admin_rank()
        if admin_rank is None or target_rank is None:
            raise PreconditionError(
                "admin_remove operates only on owner/admin/member/guest roles",
                reason="scope_mismatch",
            )
        if admin_rank < target_rank:
            raise RoleHierarchyError(
                f"Role {admin.role.value} cannot remove role {target.role.value}",
            )
        now = self._now()
        revoked = target.replace(
            status=Status.REVOKED, removed_by=admin.usr_id, updated_at=now
        )
        self._memberships[target.id] = revoked
        self._delete_tuple(_membership_tuple(target))
        return revoked

    def transfer_ownership(
        self, org_id: str, from_mem_id: str, to_mem_id: str
    ) -> TransferOwnershipResult:
        from_mem = self._require_membership(from_mem_id)
        to_mem = self._require_membership(to_mem_id)
        if from_mem.status != Status.ACTIVE:
            raise PreconditionError(
                f"From membership {from_mem_id} is {from_mem.status.value}",
                reason="from_not_active",
            )
        if to_mem.status != Status.ACTIVE:
            raise PreconditionError(
                f"To membership {to_mem_id} is {to_mem.status.value}",
                reason="to_not_active",
            )
        if from_mem.org_id != org_id or to_mem.org_id != org_id:
            raise PreconditionError(
                f"Both memberships must belong to {org_id}",
                reason="org_mismatch",
            )
        if from_mem.role != Role.OWNER:
            raise PreconditionError(
                "From membership must hold the owner role",
                reason="from_not_owner",
            )
        if from_mem.usr_id == to_mem.usr_id:
            raise PreconditionError(
                "Cannot transfer ownership to self", reason="self_transfer"
            )
        # Promote target first so the donor is no longer the sole active
        # owner when we demote them.
        to_membership = self.change_role(to_mem.id, Role.OWNER)
        from_membership = self.change_role(from_mem.id, Role.MEMBER)
        return TransferOwnershipResult(
            from_membership=from_membership, to_membership=to_membership
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
        org = self._require_org(org_id)
        if org.status != Status.ACTIVE:
            raise PreconditionError(
                f"Cannot create invitation for {org.status.value} org",
                reason="org_not_active",
            )
        now = self._now()
        if expires_at <= now:
            raise PreconditionError(
                "expires_at must be in the future", reason="past_expiration"
            )
        inv = Invitation(
            id=generate("inv"),
            org_id=org_id,
            identifier=identifier,
            role=role,
            status=InvitationStatus.PENDING,
            pre_tuples=list(pre_tuples or []),
            invited_by=invited_by,
            invited_user_id=None,
            created_at=now,
            expires_at=expires_at,
            terminal_at=None,
            terminal_by=None,
        )
        self._invitations[inv.id] = inv
        return inv

    def get_invitation(self, inv_id: str) -> Invitation:
        inv = self._invitations.get(inv_id)
        if inv is None:
            raise NotFoundError(f"Invitation {inv_id} not found")
        return inv

    def list_invitations(
        self,
        org_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        status: InvitationStatus | None = None,
    ) -> Page[Invitation]:
        all_ = sorted(
            (
                i
                for i in self._invitations.values()
                if i.org_id == org_id and (status is None or i.status == status)
            ),
            key=lambda i: i.id,
        )
        return self._paginate(all_, cursor, limit)

    def accept_invitation(
        self, inv_id: str, *, as_usr_id: str | None = None
    ) -> AcceptInvitationResult:
        inv = self.get_invitation(inv_id)
        if inv.status != InvitationStatus.PENDING:
            raise InvitationNotPendingError(
                f"Invitation {inv_id} is {inv.status.value}, not pending",
            )
        now = self._now()
        if now > inv.expires_at:
            raise InvitationExpiredError(
                f"Invitation {inv_id} expired at {inv.expires_at.isoformat()}"
            )
        usr_id = as_usr_id if as_usr_id is not None else generate("usr")
        if self._find_active_membership(usr_id, inv.org_id) is not None:
            raise DuplicateMembershipError(
                f"User {usr_id} already has an active membership in {inv.org_id}"
            )
        membership = Membership(
            id=generate("mem"),
            usr_id=usr_id,
            org_id=inv.org_id,
            role=inv.role,
            status=Status.ACTIVE,
            replaces=None,
            invited_by=inv.invited_by,
            removed_by=None,
            created_at=now,
            updated_at=now,
        )
        self._memberships[membership.id] = membership
        self._insert_tuple(_membership_tuple(membership))

        materialized: list[Tuple] = []
        for pt in inv.pre_tuples:
            t = Tuple(
                subject_type="usr",
                subject_id=usr_id,
                relation=pt.relation,
                object_type=pt.object_type,
                object_id=pt.object_id,
            )
            self._insert_tuple(t)
            materialized.append(t)

        updated_inv = inv.transition_terminal(
            status=InvitationStatus.ACCEPTED,
            at=now,
            by=usr_id,
            invited_user_id=usr_id,
        )
        self._invitations[inv.id] = updated_inv

        return AcceptInvitationResult(
            invitation=updated_inv,
            membership=membership,
            materialized_tuples=materialized,
        )

    def decline_invitation(
        self, inv_id: str, *, as_usr_id: str | None = None
    ) -> Invitation:
        inv = self.get_invitation(inv_id)
        if inv.status != InvitationStatus.PENDING:
            raise InvitationNotPendingError(
                f"Invitation {inv_id} is {inv.status.value}, not pending",
            )
        updated = inv.transition_terminal(
            status=InvitationStatus.DECLINED,
            at=self._now(),
            by=as_usr_id,
        )
        self._invitations[inv.id] = updated
        return updated

    def revoke_invitation(self, inv_id: str, admin_usr_id: str) -> Invitation:
        inv = self.get_invitation(inv_id)
        if inv.status != InvitationStatus.PENDING:
            raise InvitationNotPendingError(
                f"Invitation {inv_id} is {inv.status.value}, not pending",
            )
        updated = inv.transition_terminal(
            status=InvitationStatus.REVOKED,
            at=self._now(),
            by=admin_usr_id,
        )
        self._invitations[inv.id] = updated
        return updated

    # ─── Tuple accessors ───

    def list_tuples_for_subject(
        self, subject_type: str, subject_id: str
    ) -> list[Tuple]:
        prefix = f"{subject_type}|{subject_id}|"
        results: list[Tuple] = []
        for key in self._tuple_keys:
            if not key.startswith(prefix):
                continue
            parts = key.split("|")
            if len(parts) != 5:
                continue
            st, sid, rel, ot, oid = parts
            results.append(
                Tuple(
                    subject_type=st,
                    subject_id=sid,
                    relation=rel,
                    object_type=ot,
                    object_id=oid,
                )
            )
        return results

    def list_tuples_for_object(
        self, object_type: str, object_id: str, *, relation: str | None = None
    ) -> list[Tuple]:
        results: list[Tuple] = []
        for key in self._tuple_keys:
            parts = key.split("|")
            if len(parts) != 5:
                continue
            st, sid, rel, ot, oid = parts
            if ot != object_type or oid != object_id:
                continue
            if relation is not None and rel != relation:
                continue
            results.append(
                Tuple(
                    subject_type=st,
                    subject_id=sid,
                    relation=rel,
                    object_type=ot,
                    object_id=oid,
                )
            )
        return results
