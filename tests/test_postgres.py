# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for PostgresTenancyStore.

Gated on TENANCY_POSTGRES_URL — when the env var is unset the entire
module is skipped, mirroring the Node and PHP suites.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import pytest
from flametrench_ids import decode, generate

from flametrench_tenancy import (
    AlreadyTerminalError,
    DuplicateMembershipError,
    InvitationNotPendingError,
    InvitationStatus,
    NotFoundError,
    OrgSlugConflictError,
    PreconditionError,
    PreTuple,
    Role,
    RoleHierarchyError,
    SoleOwnerError,
    Status,
)

POSTGRES_URL = os.environ.get("TENANCY_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="TENANCY_POSTGRES_URL not set; PostgresTenancyStore tests skipped.",
)

if POSTGRES_URL is not None:
    import psycopg

    from flametrench_tenancy.postgres import PostgresTenancyStore

SCHEMA_SQL = Path(__file__).parent.joinpath("postgres-schema.sql").read_text()


@pytest.fixture
def conn() -> Iterator[Any]:
    assert POSTGRES_URL is not None
    c = psycopg.connect(POSTGRES_URL, autocommit=False)
    try:
        with c.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            cur.execute(SCHEMA_SQL)
        c.commit()
        yield c
    finally:
        c.close()


@pytest.fixture
def store(conn: Any) -> "PostgresTenancyStore":
    return PostgresTenancyStore(conn)


def _register_user(conn: Any, wire: str) -> None:
    with conn.cursor() as cur:
        cur.execute("INSERT INTO usr (id, status) VALUES (%s, 'active')", (decode(wire).uuid,))
    conn.commit()


@pytest.fixture
def alice(conn: Any) -> str:
    u = generate("usr")
    _register_user(conn, u)
    return u


@pytest.fixture
def bob(conn: Any) -> str:
    u = generate("usr")
    _register_user(conn, u)
    return u


@pytest.fixture
def carol(conn: Any) -> str:
    u = generate("usr")
    _register_user(conn, u)
    return u


# ─── createOrg ───

def test_create_org_with_owner_membership_and_tuple(store, alice):
    result = store.create_org(alice)
    assert result.org.status == Status.ACTIVE
    assert result.owner_membership.role == Role.OWNER
    assert result.owner_membership.usr_id == alice
    tuples = store.list_tuples_for_subject("usr", alice)
    assert len(tuples) == 1
    assert tuples[0].relation == "owner"


def test_create_org_persists_name_and_slug(store, alice):
    result = store.create_org(alice, name="Acme", slug="acme")
    fetched = store.get_org(result.org.id)
    assert fetched.name == "Acme"
    assert fetched.slug == "acme"


def test_create_org_duplicate_slug_raises(store, alice, bob):
    store.create_org(alice, slug="shared")
    with pytest.raises(OrgSlugConflictError):
        store.create_org(bob, slug="shared")


def test_create_org_malformed_slug_raises(store, alice):
    with pytest.raises(PreconditionError):
        store.create_org(alice, slug="AcmeInc")


# ─── updateOrg ───

def test_update_org_partial_name_only(store, alice):
    result = store.create_org(alice, name="Old", slug="old-slug")
    updated = store.update_org(result.org.id, name="New")
    assert updated.name == "New"
    assert updated.slug == "old-slug"


def test_update_org_explicit_null_clears_slug(store, alice):
    result = store.create_org(alice, slug="to-clear")
    updated = store.update_org(result.org.id, slug=None)
    assert updated.slug is None


def test_update_org_revoked_raises(store, alice):
    result = store.create_org(alice, name="RIP")
    store.revoke_org(result.org.id)
    with pytest.raises(AlreadyTerminalError):
        store.update_org(result.org.id, name="Whatever")


# ─── add_member / change_role ───

def test_add_member_creates_tuple(store, alice, bob):
    result = store.create_org(alice)
    mem = store.add_member(result.org.id, bob, Role.MEMBER, invited_by=alice)
    assert mem.role == Role.MEMBER
    assert mem.invited_by == alice
    assert len(store.list_tuples_for_subject("usr", bob)) == 1


def test_duplicate_member_raises(store, alice, bob):
    result = store.create_org(alice)
    store.add_member(result.org.id, bob, Role.MEMBER)
    with pytest.raises(DuplicateMembershipError):
        store.add_member(result.org.id, bob, Role.ADMIN)


def test_change_role_atomic(store, alice, bob):
    result = store.create_org(alice)
    bob_mem = store.add_member(result.org.id, bob, Role.MEMBER)
    new_mem = store.change_role(bob_mem.id, Role.ADMIN)
    assert new_mem.replaces == bob_mem.id
    assert new_mem.role == Role.ADMIN
    old = store.get_membership(bob_mem.id)
    assert old.status == Status.REVOKED
    tuples = store.list_tuples_for_subject("usr", bob)
    assert len(tuples) == 1
    assert tuples[0].relation == "admin"


def test_change_role_sole_owner_blocked(store, alice):
    result = store.create_org(alice)
    with pytest.raises(SoleOwnerError):
        store.change_role(result.owner_membership.id, Role.MEMBER)


# ─── suspend / reinstate ───

def test_suspend_membership_removes_tuple_reinstate_restores(store, alice, bob):
    result = store.create_org(alice)
    bob_mem = store.add_member(result.org.id, bob, Role.MEMBER)
    store.suspend_membership(bob_mem.id)
    assert store.list_tuples_for_subject("usr", bob) == []
    store.reinstate_membership(bob_mem.id)
    assert len(store.list_tuples_for_subject("usr", bob)) == 1


# ─── self_leave ───

def test_self_leave_non_owner_no_transfer(store, alice, bob):
    result = store.create_org(alice)
    bob_mem = store.add_member(result.org.id, bob, Role.MEMBER)
    left = store.self_leave(bob_mem.id)
    assert left.status == Status.REVOKED
    assert left.removed_by is None


def test_self_leave_sole_owner_with_transfer(store, alice, bob):
    result = store.create_org(alice)
    store.add_member(result.org.id, bob, Role.MEMBER)
    left = store.self_leave(result.owner_membership.id, transfer_to=bob)
    assert left.status == Status.REVOKED
    assert store.list_tuples_for_subject("usr", alice) == []
    bob_tuples = store.list_tuples_for_subject("usr", bob)
    assert len(bob_tuples) == 1
    assert bob_tuples[0].relation == "owner"


def test_self_leave_sole_owner_no_transfer_blocked(store, alice):
    result = store.create_org(alice)
    with pytest.raises(SoleOwnerError):
        store.self_leave(result.owner_membership.id)


# ─── admin_remove ───

def test_admin_remove_records_remover(store, alice, bob):
    result = store.create_org(alice)
    bob_mem = store.add_member(result.org.id, bob, Role.MEMBER)
    removed = store.admin_remove(bob_mem.id, admin_usr_id=alice)
    assert removed.removed_by == alice


def test_admin_remove_cannot_remove_owner(store, alice, bob):
    result = store.create_org(alice)
    store.add_member(result.org.id, bob, Role.ADMIN)
    with pytest.raises(RoleHierarchyError):
        store.admin_remove(result.owner_membership.id, admin_usr_id=bob)


# ─── transfer_ownership ───

def test_transfer_ownership_atomic(store, alice, bob):
    result = store.create_org(alice)
    bob_mem = store.add_member(result.org.id, bob, Role.ADMIN)
    out = store.transfer_ownership(result.org.id, result.owner_membership.id, bob_mem.id)
    assert out.from_membership.role == Role.MEMBER
    assert out.to_membership.role == Role.OWNER
    alice_tuples = store.list_tuples_for_subject("usr", alice)
    assert [t.relation for t in alice_tuples] == ["member"]
    bob_tuples = store.list_tuples_for_subject("usr", bob)
    assert [t.relation for t in bob_tuples] == ["owner"]


# ─── Invitations ───

def test_accept_invitation_materializes_pre_tuples(store, alice, carol):
    result = store.create_org(alice)
    project_id = "0190f2a8-1b3c-7abc-8123-456789abcdef"
    inv = store.create_invitation(
        org_id=result.org.id,
        identifier="carol@example.com",
        role=Role.GUEST,
        invited_by=alice,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        pre_tuples=[PreTuple(relation="viewer", object_type="proj", object_id=project_id)],
    )
    out = store.accept_invitation(
        inv.id, as_usr_id=carol, accepting_identifier="carol@example.com",
    )
    assert len(out.materialized_tuples) == 1
    assert out.invitation.status == InvitationStatus.ACCEPTED
    assert out.invitation.terminal_by == carol
    carol_tuples = store.list_tuples_for_subject("usr", carol)
    assert len(carol_tuples) == 2
    viewer = next(t for t in carol_tuples if t.relation == "viewer")
    assert viewer.object_id == project_id


def test_accept_invitation_non_pending_rejected(store, alice, bob, carol):
    result = store.create_org(alice)
    inv = store.create_invitation(
        org_id=result.org.id,
        identifier="x@y",
        role=Role.MEMBER,
        invited_by=alice,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    store.accept_invitation(inv.id, as_usr_id=bob, accepting_identifier="x@y")
    with pytest.raises(InvitationNotPendingError):
        store.accept_invitation(inv.id, as_usr_id=carol, accepting_identifier="x@y")


def test_decline_invitation_terminal(store, alice, bob):
    result = store.create_org(alice)
    inv = store.create_invitation(
        org_id=result.org.id,
        identifier="x@y",
        role=Role.MEMBER,
        invited_by=alice,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    declined = store.decline_invitation(inv.id, as_usr_id=bob)
    assert declined.status == InvitationStatus.DECLINED
    assert declined.terminal_by == bob


def test_revoke_invitation_terminal(store, alice):
    result = store.create_org(alice)
    inv = store.create_invitation(
        org_id=result.org.id,
        identifier="x@y",
        role=Role.MEMBER,
        invited_by=alice,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    revoked = store.revoke_invitation(inv.id, admin_usr_id=alice)
    assert revoked.status == InvitationStatus.REVOKED
    assert revoked.terminal_by == alice


# ─── Org revoke cascade ───

def test_revoke_org_cascades(store, alice, bob):
    result = store.create_org(alice)
    store.add_member(result.org.id, bob, Role.MEMBER)
    store.revoke_org(result.org.id)
    assert store.get_org(result.org.id).status == Status.REVOKED
    assert store.list_tuples_for_subject("usr", alice) == []
    assert store.list_tuples_for_subject("usr", bob) == []


# ─── Listing ───

def test_list_members_paginates(store, conn, alice, bob, carol):
    result = store.create_org(alice)
    extra1 = generate("usr")
    extra2 = generate("usr")
    _register_user(conn, extra1)
    _register_user(conn, extra2)
    for u in (bob, carol, extra1, extra2):
        store.add_member(result.org.id, u, Role.MEMBER)
    page1 = store.list_members(result.org.id, limit=2)
    assert len(page1.data) == 2
    assert page1.next_cursor is not None
    page2 = store.list_members(result.org.id, cursor=page1.next_cursor, limit=10)
    all_ids = {m.id for m in page1.data} | {m.id for m in page2.data}
    assert len(all_ids) == 5  # alice + 4 added


# ─── NotFound paths ───

def test_unknown_ids_raise_not_found(store):
    with pytest.raises(NotFoundError):
        store.get_org(generate("org"))
    with pytest.raises(NotFoundError):
        store.get_membership(generate("mem"))
    with pytest.raises(NotFoundError):
        store.get_invitation(generate("inv"))


# ─── Outer-transaction nesting (ADR 0013) ───

def test_create_org_cooperates_with_outer_transaction(store, conn, alice):
    nested = PostgresTenancyStore(conn)
    with conn.transaction():
        result = nested.create_org(alice, name="Outer", slug="outer")
    fetched = store.get_org(result.org.id)
    assert fetched.name == "Outer"


def test_outer_rollback_undoes_inner_create_org(store, conn, alice):
    nested = PostgresTenancyStore(conn)
    org_id = None
    try:
        with conn.transaction():
            result = nested.create_org(alice, slug="will-rollback")
            org_id = result.org.id
            raise RuntimeError("force rollback")
    except RuntimeError:
        pass
    with pytest.raises(NotFoundError):
        store.get_org(org_id)


def test_outer_can_commit_after_first_rolls_back_savepoint(store, conn, alice, bob, carol):
    # Seed a slug so the next createOrg with the same slug conflicts.
    store.create_org(bob, slug="taken")
    with conn.transaction():
        nested = PostgresTenancyStore(conn)
        with pytest.raises(OrgSlugConflictError):
            nested.create_org(alice, slug="taken")
        survivor = nested.create_org(carol, slug="survivor")
    assert store.get_org(survivor.org.id).slug == "survivor"
