# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""flametrench-tenancy — organizations, memberships, and invitations.

The spec-normative tenancy layer for Flametrench v0.1. See the upstream
specification at
https://github.com/flametrench/spec/blob/main/docs/tenancy.md.

The mem_/tup_ duality is load-bearing: every active membership has a
corresponding owner|admin|member|... tuple in the authorization layer.
This package keeps a shadow tuple set in lockstep with mem.status so the
duality cannot drift.
"""

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
    TenancyError,
)
from .in_memory import InMemoryTenancyStore
from .store import TenancyStore
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

__all__ = [
    "AcceptInvitationResult",
    "AlreadyTerminalError",
    "CreateOrgResult",
    "DuplicateMembershipError",
    "ForbiddenError",
    "IdentifierBindingRequiredError",
    "IdentifierMismatchError",
    "InMemoryTenancyStore",
    "Invitation",
    "InvitationExpiredError",
    "InvitationNotPendingError",
    "InvitationStatus",
    "Membership",
    "NotFoundError",
    "OrgSlugConflictError",
    "Organization",
    "Page",
    "PreTuple",
    "PreconditionError",
    "Role",
    "RoleHierarchyError",
    "SoleOwnerError",
    "Status",
    "TenancyError",
    "TenancyStore",
    "TransferOwnershipResult",
    "Tuple",
]

__version__ = "0.1.0"
