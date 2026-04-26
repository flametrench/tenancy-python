# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""TenancyStore — every tenancy backend implements this contract.

Atomicity guarantees per the Flametrench v0.1 specification:

- ``change_role`` updates the old mem, inserts a new mem, deletes the
  old tuple, inserts the new tuple — all in one transaction.
- ``accept_invitation`` creates a user if needed, inserts mem, inserts
  the membership tuple, expands pre_tuples into tuples, transitions the
  invitation — all in one transaction.
- ``transfer_ownership`` demotes the old owner's mem, promotes the
  target, swaps both tuples — one transaction.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

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


@runtime_checkable
class TenancyStore(Protocol):
    # ─── Organizations ───
    def create_org(self, creator: str) -> CreateOrgResult: ...
    def get_org(self, org_id: str) -> Organization: ...
    def suspend_org(self, org_id: str) -> Organization: ...
    def reinstate_org(self, org_id: str) -> Organization: ...
    def revoke_org(self, org_id: str) -> Organization: ...

    # ─── Memberships ───
    def add_member(
        self, org_id: str, usr_id: str, role: Role, *, invited_by: str | None = None
    ) -> Membership: ...

    def get_membership(self, mem_id: str) -> Membership: ...

    def list_members(
        self,
        org_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        status: Status | None = None,
    ) -> Page[Membership]: ...

    def change_role(self, mem_id: str, new_role: Role) -> Membership: ...

    def suspend_membership(self, mem_id: str) -> Membership: ...

    def reinstate_membership(self, mem_id: str) -> Membership: ...

    def self_leave(
        self, mem_id: str, *, transfer_to: str | None = None
    ) -> Membership: ...

    def admin_remove(self, mem_id: str, admin_usr_id: str) -> Membership: ...

    def transfer_ownership(
        self, org_id: str, from_mem_id: str, to_mem_id: str
    ) -> TransferOwnershipResult: ...

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
    ) -> Invitation: ...

    def get_invitation(self, inv_id: str) -> Invitation: ...

    def list_invitations(
        self,
        org_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        status: InvitationStatus | None = None,
    ) -> Page[Invitation]: ...

    def accept_invitation(
        self,
        inv_id: str,
        *,
        as_usr_id: str | None = None,
        accepting_identifier: str | None = None,
    ) -> AcceptInvitationResult:
        """Accept a pending invitation.

        Per ADR 0009, identifier binding is enforced inside the SDK:

        - If ``as_usr_id`` is provided, ``accepting_identifier`` is REQUIRED.
          The SDK byte-compares it to ``invitation.identifier``;
          mismatch raises :class:`IdentifierMismatchError`, omission
          raises :class:`IdentifierBindingRequiredError`.
        - If ``as_usr_id is None`` (mint-new-user path), the SDK creates
          a fresh ``usr_`` and ``accepting_identifier`` is not consulted.

        The host MUST source ``accepting_identifier`` from the
        authenticated session context, NOT from a request body.
        """
        ...

    def decline_invitation(
        self, inv_id: str, *, as_usr_id: str | None = None
    ) -> Invitation: ...

    def revoke_invitation(self, inv_id: str, admin_usr_id: str) -> Invitation: ...

    # ─── Tuple accessors ───
    def list_tuples_for_subject(
        self, subject_type: str, subject_id: str
    ) -> list[Tuple]: ...

    def list_tuples_for_object(
        self, object_type: str, object_id: str, *, relation: str | None = None
    ) -> list[Tuple]: ...
