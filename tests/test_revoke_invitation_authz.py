# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""revoke_invitation is subject to admin authorization on the invitation's org.

Runs against InMemoryTenancyStore and, when TENANCY_POSTGRES_URL is set,
PostgresTenancyStore. Every refusal also asserts the invitation is left
exactly as it was (still pending, no terminal fields).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest
from flametrench_ids import decode, generate

from flametrench_tenancy import (
    ForbiddenError,
    InMemoryTenancyStore,
    InvitationNotPendingError,
    InvitationStatus,
    Role,
)

POSTGRES_URL = os.environ.get("TENANCY_POSTGRES_URL")
SCHEMA_SQL = Path(__file__).parent.joinpath("postgres-schema.sql").read_text()
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def pg_conn() -> Iterator[Any]:
    if POSTGRES_URL is None:
        pytest.skip("TENANCY_POSTGRES_URL not set; PostgresTenancyStore tests skipped.")
    import psycopg

    c = psycopg.connect(POSTGRES_URL, autocommit=False)
    try:
        with c.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            cur.execute(SCHEMA_SQL)
        c.commit()
        yield c
    finally:
        c.close()


@pytest.fixture(params=["memory", "postgres"])
def env(request: Any) -> tuple[Any, Callable[[], str]]:
    """(store, new_user) — new_user registers a usr row where needed."""
    if request.param == "memory":
        return InMemoryTenancyStore(clock=lambda: T0), lambda: generate("usr")
    from flametrench_tenancy.postgres import PostgresTenancyStore

    conn = request.getfixturevalue("pg_conn")

    def new_user() -> str:
        u = generate("usr")
        with conn.cursor() as cur:
            cur.execute("INSERT INTO usr (id, status) VALUES (%s, 'active')", (decode(u).uuid,))
        conn.commit()
        return u

    return PostgresTenancyStore(conn, clock=lambda: T0), new_user


def _invite(store: Any, org_id: str, invited_by: str) -> Any:
    return store.create_invitation(
        org_id, "invitee@example.com", Role.MEMBER, invited_by, T0 + timedelta(days=1)
    )


def _assert_untouched(store: Any, before: Any) -> None:
    after = store.get_invitation(before.id)
    assert after.status == InvitationStatus.PENDING
    assert after.terminal_at is None
    assert after.terminal_by is None
    assert after == before


def test_plain_member_forbidden_and_invitation_untouched(env: Any) -> None:
    store, new_user = env
    alice, bob = new_user(), new_user()
    org = store.create_org(alice).org
    store.add_member(org.id, bob, Role.MEMBER)
    inv = _invite(store, org.id, alice)
    with pytest.raises(ForbiddenError):
        store.revoke_invitation(inv.id, bob)
    _assert_untouched(store, inv)


@pytest.mark.parametrize("role", [Role.GUEST, Role.VIEWER, Role.EDITOR])
def test_other_non_admin_roles_forbidden(env: Any, role: Role) -> None:
    store, new_user = env
    alice, carol = new_user(), new_user()
    org = store.create_org(alice).org
    store.add_member(org.id, carol, role)
    inv = _invite(store, org.id, alice)
    with pytest.raises(ForbiddenError):
        store.revoke_invitation(inv.id, carol)
    _assert_untouched(store, inv)


def test_non_member_forbidden_and_invitation_untouched(env: Any) -> None:
    store, new_user = env
    alice, stranger = new_user(), new_user()
    org = store.create_org(alice).org
    inv = _invite(store, org.id, alice)
    with pytest.raises(ForbiddenError):
        store.revoke_invitation(inv.id, stranger)
    _assert_untouched(store, inv)


def test_owner_of_another_org_forbidden(env: Any) -> None:
    store, new_user = env
    alice, mallory = new_user(), new_user()
    org = store.create_org(alice).org
    store.create_org(mallory)
    inv = _invite(store, org.id, alice)
    with pytest.raises(ForbiddenError):
        store.revoke_invitation(inv.id, mallory)
    _assert_untouched(store, inv)


def test_admin_elsewhere_member_here_forbidden(env: Any) -> None:
    store, new_user = env
    alice, dave = new_user(), new_user()
    store.create_org(dave)
    org_b = store.create_org(alice).org
    store.add_member(org_b.id, dave, Role.MEMBER)
    inv = _invite(store, org_b.id, alice)
    with pytest.raises(ForbiddenError):
        store.revoke_invitation(inv.id, dave)
    _assert_untouched(store, inv)


def test_suspended_admin_membership_forbidden(env: Any) -> None:
    store, new_user = env
    alice, carol = new_user(), new_user()
    org = store.create_org(alice).org
    mem = store.add_member(org.id, carol, Role.ADMIN)
    store.suspend_membership(mem.id)
    inv = _invite(store, org.id, alice)
    with pytest.raises(ForbiddenError):
        store.revoke_invitation(inv.id, carol)
    _assert_untouched(store, inv)


def test_reinstated_admin_membership_succeeds(env: Any) -> None:
    store, new_user = env
    alice, carol = new_user(), new_user()
    org = store.create_org(alice).org
    mem = store.add_member(org.id, carol, Role.ADMIN)
    store.suspend_membership(mem.id)
    store.reinstate_membership(mem.id)
    inv = _invite(store, org.id, alice)
    assert store.revoke_invitation(inv.id, carol).terminal_by == carol


def test_owner_succeeds_with_terminal_by(env: Any) -> None:
    store, new_user = env
    alice = new_user()
    org = store.create_org(alice).org
    inv = _invite(store, org.id, alice)
    revoked = store.revoke_invitation(inv.id, alice)
    assert revoked.status == InvitationStatus.REVOKED
    assert revoked.terminal_by == alice
    assert store.get_invitation(inv.id).status == InvitationStatus.REVOKED


def test_admin_succeeds_with_terminal_by(env: Any) -> None:
    store, new_user = env
    alice, carol = new_user(), new_user()
    org = store.create_org(alice).org
    store.add_member(org.id, carol, Role.ADMIN)
    inv = _invite(store, org.id, alice)
    revoked = store.revoke_invitation(inv.id, carol)
    assert revoked.status == InvitationStatus.REVOKED
    assert revoked.terminal_by == carol


def test_authorization_is_checked_before_status(env: Any) -> None:
    """A caller without authority gets ForbiddenError even for a
    non-pending invitation, so it learns nothing about its state."""
    store, new_user = env
    alice, bob = new_user(), new_user()
    org = store.create_org(alice).org
    store.add_member(org.id, bob, Role.MEMBER)
    inv = _invite(store, org.id, alice)
    store.revoke_invitation(inv.id, alice)
    with pytest.raises(ForbiddenError):
        store.revoke_invitation(inv.id, bob)
    with pytest.raises(InvitationNotPendingError):
        store.revoke_invitation(inv.id, alice)
    assert store.get_invitation(inv.id).terminal_by == alice
