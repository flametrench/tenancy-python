# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Error types raised by the tenancy layer.

Every error carries a stable `code` matching the OpenAPI Error envelope.
"""

from __future__ import annotations


class TenancyError(Exception):
    """Base class for every tenancy-layer error."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class NotFoundError(TenancyError):
    """The requested entity does not exist."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="not_found")


class DuplicateMembershipError(TenancyError):
    """User already has an active membership in this org."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="conflict.duplicate_membership")


class SoleOwnerError(TenancyError):
    """Operation would leave the org without an active owner."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="forbidden.sole_owner")


class RoleHierarchyError(TenancyError):
    """An admin attempted to remove a peer or higher-ranked member."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="forbidden.role_hierarchy")


class ForbiddenError(TenancyError):
    """The acting user lacks the role required for this operation."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="forbidden")


class InvitationNotPendingError(TenancyError):
    """The invitation is not in the pending state and cannot transition."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="conflict.invitation_not_pending")


class InvitationExpiredError(TenancyError):
    """The invitation passed its expires_at and cannot be accepted."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="conflict.invitation_expired")


class AlreadyTerminalError(TenancyError):
    """The entity is already in a terminal state."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="already_terminal")


class PreconditionError(TenancyError):
    """A precondition for the requested transition was not met."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message, code=f"precondition.{reason}")
        self.reason = reason
