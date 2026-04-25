# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Tenancy entity types.

Frozen dataclasses for cross-language parity with the readonly classes
used in the PHP and Node SDKs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Generic, TypeVar

T = TypeVar("T")


class Role(str, Enum):
    """The six built-in relations registered in Flametrench v0.1.

    Applications MAY register custom relation names (matching
    ``^[a-z_]{2,32}$``) for their own domain objects, but membership
    roles MUST be drawn from this enum so cross-SDK tenancy semantics
    stay byte-identical.
    """

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    GUEST = "guest"
    VIEWER = "viewer"
    EDITOR = "editor"

    def admin_rank(self) -> int | None:
        """The admin-hierarchy ranking used by the admin_remove precondition.

        Higher rank removes lower or equal rank. Viewer/editor are
        object-scoped and do not participate; they return None.
        """
        return {
            Role.OWNER: 4,
            Role.ADMIN: 3,
            Role.MEMBER: 2,
            Role.GUEST: 1,
        }.get(self)


class Status(str, Enum):
    """Lifecycle status shared by organizations and memberships."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class InvitationStatus(str, Enum):
    """The five-state invitation lifecycle.

    ``PENDING`` is the only non-terminal state; the other four are
    terminal and immutable once entered.
    """

    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class Organization:
    id: str
    status: Status
    created_at: datetime
    updated_at: datetime

    def with_status(self, status: Status, updated_at: datetime) -> "Organization":
        return Organization(
            id=self.id,
            status=status,
            created_at=self.created_at,
            updated_at=updated_at,
        )


@dataclass(frozen=True)
class Membership:
    id: str
    usr_id: str
    org_id: str
    role: Role
    status: Status
    replaces: str | None
    invited_by: str | None
    removed_by: str | None
    created_at: datetime
    updated_at: datetime

    def replace(
        self,
        *,
        status: Status | None = None,
        removed_by: str | None | object = ...,
        updated_at: datetime | None = None,
    ) -> "Membership":
        """Return a copy with selected fields overridden.

        Use the sentinel ``...`` for ``removed_by`` to keep the existing
        value; pass ``None`` explicitly to clear it.
        """
        return Membership(
            id=self.id,
            usr_id=self.usr_id,
            org_id=self.org_id,
            role=self.role,
            status=status if status is not None else self.status,
            replaces=self.replaces,
            invited_by=self.invited_by,
            removed_by=self.removed_by if removed_by is ... else removed_by,  # type: ignore[arg-type]
            created_at=self.created_at,
            updated_at=updated_at if updated_at is not None else self.updated_at,
        )


@dataclass(frozen=True)
class Tuple:
    """An authorization tuple. ``subject_type`` is always ``"usr"`` in v0.1."""

    subject_type: str
    subject_id: str
    relation: str
    object_type: str
    object_id: str


@dataclass(frozen=True)
class PreTuple:
    """A resource-scoped grant pre-declared on an invitation.

    Materialized as a ``tup_`` row at accept time with the accepting
    user as the subject.
    """

    relation: str
    object_type: str
    object_id: str


@dataclass(frozen=True)
class Invitation:
    id: str
    org_id: str
    identifier: str
    role: Role
    status: InvitationStatus
    pre_tuples: list[PreTuple]
    invited_by: str
    invited_user_id: str | None
    created_at: datetime
    expires_at: datetime
    terminal_at: datetime | None
    terminal_by: str | None

    def transition_terminal(
        self,
        status: InvitationStatus,
        at: datetime,
        by: str | None,
        invited_user_id: str | None = None,
    ) -> "Invitation":
        return Invitation(
            id=self.id,
            org_id=self.org_id,
            identifier=self.identifier,
            role=self.role,
            status=status,
            pre_tuples=self.pre_tuples,
            invited_by=self.invited_by,
            invited_user_id=invited_user_id if invited_user_id is not None else self.invited_user_id,
            created_at=self.created_at,
            expires_at=self.expires_at,
            terminal_at=at,
            terminal_by=by,
        )


@dataclass(frozen=True)
class Page(Generic[T]):
    data: list[T]
    next_cursor: str | None


@dataclass(frozen=True)
class CreateOrgResult:
    org: Organization
    owner_membership: Membership


@dataclass(frozen=True)
class TransferOwnershipResult:
    from_membership: Membership
    to_membership: Membership


@dataclass(frozen=True)
class AcceptInvitationResult:
    invitation: Invitation
    membership: Membership
    materialized_tuples: list[Tuple]
