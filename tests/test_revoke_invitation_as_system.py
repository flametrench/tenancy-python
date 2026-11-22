# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""revoke_invitation_as_system revokes a pending invitation with no actor.

ADR 0028 rules 6-10. Runs against InMemoryTenancyStore and, when
TENANCY_POSTGRES_URL is set, PostgresTenancyStore.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest
from flametrench_ids import decode, generate

from flametrench_tenancy import (
    InMemoryTenancyStore,
    InvitationNotPendingError,
    InvitationStatus,
    NotFoundError,
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


def test_pending_invitation_revoked_with_no_actor(env: Any) -> None:
    store, new_user = env
    alice = new_user()
    org = store.create_org(alice).org
    inv = _invite(store, org.id, alice)
    revoked = store.revoke_invitation_as_system(inv.id)
    assert revoked.status == InvitationStatus.REVOKED
    assert revoked.terminal_at == T0
    assert revoked.terminal_by is None
    assert store.get_invitation(inv.id) == revoked


def test_non_pending_invitation_refused_and_unchanged(env: Any) -> None:
    store, new_user = env
    alice = new_user()
    org = store.create_org(alice).org
    inv = _invite(store, org.id, alice)
    first = store.revoke_invitation_as_system(inv.id)
    with pytest.raises(InvitationNotPendingError):
        store.revoke_invitation_as_system(inv.id)
    assert store.get_invitation(inv.id) == first


def test_unknown_invitation_not_found(env: Any) -> None:
    store, _ = env
    with pytest.raises(NotFoundError):
        store.revoke_invitation_as_system(generate("inv"))
