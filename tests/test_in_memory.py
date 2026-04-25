# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for InMemoryTenancyStore.

Mirrors the most load-bearing PHP/Node test cases: sole-owner protection,
the mem_/tup_ duality, role hierarchy on admin_remove, atomic invitation
acceptance with pre-tuple materialization, and ownership transfer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from flametrench_ids import generate

from flametrench_tenancy import (
    AlreadyTerminalError,
    DuplicateMembershipError,
    ForbiddenError,
    InMemoryTenancyStore,
    InvitationExpiredError,
    InvitationNotPendingError,
    InvitationStatus,
    PreTuple,
    PreconditionError,
    Role,
    RoleHierarchyError,
    SoleOwnerError,
    Status,
)


@pytest.fixture
def store() -> InMemoryTenancyStore:
    return InMemoryTenancyStore()


@pytest.fixture
def alice() -> str:
    return generate("usr")


@pytest.fixture
def bob() -> str:
    return generate("usr")


@pytest.fixture
def carol() -> str:
    return generate("usr")


def _future(seconds: int = 3600) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


class TestCreateOrg:
    def test_creates_org_with_owner_membership_and_owner_tuple(
        self, store: InMemoryTenancyStore, alice: str
    ) -> None:
        result = store.create_org(alice)
        assert result.org.status == Status.ACTIVE
        assert result.owner_membership.role == Role.OWNER
        assert result.owner_membership.usr_id == alice

        # mem_/tup_ duality: an owner tuple shadows the active membership.
        tuples = store.list_tuples_for_subject("usr", alice)
        assert len(tuples) == 1
        assert tuples[0].relation == "owner"
        assert tuples[0].object_id == result.org.id


class TestRevokeOrgCascades:
    def test_revoke_org_cascades_to_memberships_and_tuples(
        self, store: InMemoryTenancyStore, alice: str, bob: str
    ) -> None:
        result = store.create_org(alice)
        store.add_member(result.org.id, bob, Role.MEMBER)
        store.revoke_org(result.org.id)

        # All active memberships are revoked and the matching tuples gone.
        assert store.list_tuples_for_subject("usr", alice) == []
        assert store.list_tuples_for_subject("usr", bob) == []
        org = store.get_org(result.org.id)
        assert org.status == Status.REVOKED


class TestAddMember:
    def test_rejects_duplicate_active_membership(
        self, store: InMemoryTenancyStore, alice: str, bob: str
    ) -> None:
        result = store.create_org(alice)
        store.add_member(result.org.id, bob, Role.MEMBER)
        with pytest.raises(DuplicateMembershipError):
            store.add_member(result.org.id, bob, Role.ADMIN)


class TestSoleOwnerProtection:
    def test_change_role_blocks_sole_owner_demotion(
        self, store: InMemoryTenancyStore, alice: str
    ) -> None:
        result = store.create_org(alice)
        with pytest.raises(SoleOwnerError):
            store.change_role(result.owner_membership.id, Role.MEMBER)

    def test_suspend_blocks_sole_owner(
        self, store: InMemoryTenancyStore, alice: str
    ) -> None:
        result = store.create_org(alice)
        with pytest.raises(SoleOwnerError):
            store.suspend_membership(result.owner_membership.id)

    def test_self_leave_requires_transfer_for_sole_owner(
        self, store: InMemoryTenancyStore, alice: str
    ) -> None:
        result = store.create_org(alice)
        with pytest.raises(SoleOwnerError):
            store.self_leave(result.owner_membership.id)

    def test_self_leave_with_transfer_promotes_target_then_revokes_self(
        self, store: InMemoryTenancyStore, alice: str, bob: str
    ) -> None:
        result = store.create_org(alice)
        store.add_member(result.org.id, bob, Role.MEMBER)
        revoked = store.self_leave(
            result.owner_membership.id, transfer_to=bob
        )
        assert revoked.status == Status.REVOKED
        # Bob now holds an active owner membership.
        bob_tuples = store.list_tuples_for_subject("usr", bob)
        assert any(t.relation == "owner" for t in bob_tuples)


class TestChangeRoleSemantics:
    def test_revokes_old_inserts_new_with_replaces_chain(
        self, store: InMemoryTenancyStore, alice: str, bob: str
    ) -> None:
        result = store.create_org(alice)
        bob_mem = store.add_member(result.org.id, bob, Role.MEMBER)
        new_mem = store.change_role(bob_mem.id, Role.ADMIN)

        old = store.get_membership(bob_mem.id)
        assert old.status == Status.REVOKED
        assert new_mem.status == Status.ACTIVE
        assert new_mem.replaces == bob_mem.id
        assert new_mem.role == Role.ADMIN

        # tup_ swap: the old member tuple is gone, the new admin tuple exists.
        bob_tuples = store.list_tuples_for_subject("usr", bob)
        assert len(bob_tuples) == 1
        assert bob_tuples[0].relation == "admin"


class TestAdminRemoveHierarchy:
    def test_admin_can_remove_member(
        self, store: InMemoryTenancyStore, alice: str, bob: str, carol: str
    ) -> None:
        result = store.create_org(alice)  # alice is owner
        admin_mem = store.add_member(result.org.id, bob, Role.ADMIN)
        target_mem = store.add_member(result.org.id, carol, Role.MEMBER)
        revoked = store.admin_remove(target_mem.id, bob)
        assert revoked.status == Status.REVOKED
        assert revoked.removed_by == bob

    def test_admin_can_remove_peer_admin(
        self, store: InMemoryTenancyStore, alice: str, bob: str, carol: str
    ) -> None:
        # Per spec: "higher rank removes lower OR EQUAL rank" — admins can
        # remove peer admins. Owner stays the only undeposable role.
        result = store.create_org(alice)
        store.add_member(result.org.id, bob, Role.ADMIN)
        peer_mem = store.add_member(result.org.id, carol, Role.ADMIN)
        revoked = store.admin_remove(peer_mem.id, bob)
        assert revoked.status == Status.REVOKED

    def test_admin_cannot_remove_owner(
        self, store: InMemoryTenancyStore, alice: str, bob: str
    ) -> None:
        result = store.create_org(alice)
        store.add_member(result.org.id, bob, Role.ADMIN)
        with pytest.raises(RoleHierarchyError):
            store.admin_remove(result.owner_membership.id, bob)

    def test_non_admin_member_cannot_admin_remove(
        self, store: InMemoryTenancyStore, alice: str, bob: str, carol: str
    ) -> None:
        result = store.create_org(alice)
        store.add_member(result.org.id, bob, Role.MEMBER)
        target_mem = store.add_member(result.org.id, carol, Role.MEMBER)
        with pytest.raises(ForbiddenError):
            store.admin_remove(target_mem.id, bob)


class TestTransferOwnership:
    def test_swaps_owner_and_target_atomically(
        self, store: InMemoryTenancyStore, alice: str, bob: str
    ) -> None:
        result = store.create_org(alice)
        bob_mem = store.add_member(result.org.id, bob, Role.MEMBER)
        out = store.transfer_ownership(
            result.org.id, result.owner_membership.id, bob_mem.id
        )
        # Bob is now owner; alice is now member.
        assert out.to_membership.role == Role.OWNER
        assert out.to_membership.usr_id == bob
        assert out.from_membership.role == Role.MEMBER
        assert out.from_membership.usr_id == alice

        # Tuple shadow set reflects the swap.
        alice_tuples = store.list_tuples_for_subject("usr", alice)
        bob_tuples = store.list_tuples_for_subject("usr", bob)
        assert any(t.relation == "member" for t in alice_tuples)
        assert any(t.relation == "owner" for t in bob_tuples)

    def test_rejects_self_transfer(
        self, store: InMemoryTenancyStore, alice: str
    ) -> None:
        result = store.create_org(alice)
        with pytest.raises(PreconditionError):
            store.transfer_ownership(
                result.org.id,
                result.owner_membership.id,
                result.owner_membership.id,
            )


class TestInvitations:
    def test_accept_invitation_atomically_creates_mem_and_materializes_pretuples(
        self, store: InMemoryTenancyStore, alice: str
    ) -> None:
        result = store.create_org(alice)
        project_id = generate("org")[4:]  # bare hex for project
        inv = store.create_invitation(
            org_id=result.org.id,
            identifier="newbie@example.com",
            role=Role.MEMBER,
            invited_by=alice,
            expires_at=_future(),
            pre_tuples=[
                PreTuple(relation="editor", object_type="proj", object_id=project_id),
            ],
        )
        out = store.accept_invitation(inv.id)
        assert out.invitation.status == InvitationStatus.ACCEPTED
        assert out.membership.role == Role.MEMBER
        # Both the membership tuple AND the pre-tuple were materialized.
        new_user_tuples = store.list_tuples_for_subject(
            "usr", out.membership.usr_id
        )
        assert len(new_user_tuples) == 2
        relations = {t.relation for t in new_user_tuples}
        assert relations == {"member", "editor"}

    def test_accept_expired_invitation_raises(
        self, store: InMemoryTenancyStore, alice: str
    ) -> None:
        result = store.create_org(alice)
        # Invitation that expired 1 second ago — go through the back door
        # by stashing it directly. The normal create path forbids past dates.
        from datetime import datetime, timedelta, timezone as tz

        inv = store.create_invitation(
            org_id=result.org.id,
            identifier="late@example.com",
            role=Role.MEMBER,
            invited_by=alice,
            expires_at=datetime.now(tz.utc) + timedelta(seconds=2),
        )
        # Manually rewind expires_at into the past via dataclass replace.
        from dataclasses import replace

        store._invitations[inv.id] = replace(  # type: ignore[attr-defined]
            store._invitations[inv.id],  # type: ignore[attr-defined]
            expires_at=datetime.now(tz.utc) - timedelta(seconds=1),
        )
        with pytest.raises(InvitationExpiredError):
            store.accept_invitation(inv.id)

    def test_decline_terminal_then_redecline_raises(
        self, store: InMemoryTenancyStore, alice: str
    ) -> None:
        result = store.create_org(alice)
        inv = store.create_invitation(
            org_id=result.org.id,
            identifier="x@example.com",
            role=Role.MEMBER,
            invited_by=alice,
            expires_at=_future(),
        )
        store.decline_invitation(inv.id)
        with pytest.raises(InvitationNotPendingError):
            store.decline_invitation(inv.id)


class TestOrgLifecycle:
    def test_revoke_then_revoke_again_raises(
        self, store: InMemoryTenancyStore, alice: str
    ) -> None:
        result = store.create_org(alice)
        store.revoke_org(result.org.id)
        with pytest.raises(AlreadyTerminalError):
            store.revoke_org(result.org.id)

    def test_suspend_then_reinstate_round_trip(
        self, store: InMemoryTenancyStore, alice: str
    ) -> None:
        result = store.create_org(alice)
        store.suspend_org(result.org.id)
        org = store.get_org(result.org.id)
        assert org.status == Status.SUSPENDED
        store.reinstate_org(result.org.id)
        org = store.get_org(result.org.id)
        assert org.status == Status.ACTIVE
