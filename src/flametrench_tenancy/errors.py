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


class IdentifierBindingRequiredError(PreconditionError):
    """``acceptInvitation`` was called with ``as_usr_id`` but no ``accepting_identifier``.

    Per ADR 0009, the SDK fails closed: callers MUST supply
    ``accepting_identifier`` whenever they assert an existing
    ``as_usr_id``. The mint-new-user path (``as_usr_id is None``) does
    not need this parameter.
    """

    def __init__(
        self,
        message: str = "accept_invitation requires accepting_identifier when as_usr_id is provided",
    ) -> None:
        super().__init__(message, reason="identifier_binding_required")


class IdentifierMismatchError(PreconditionError):
    """The supplied ``accepting_identifier`` does not match ``invitation.identifier``.

    Per ADR 0009, this byte-equality check is the SDK's contribution to
    closing the privilege-escalation primitive in spec#5: an attacker
    substituting a foreign ``usr_id`` will fail to also produce a
    matching identifier sourced from the authenticated session.
    """

    def __init__(self, accepting_identifier: str, invitation_identifier: str) -> None:
        super().__init__(
            f"accepting_identifier {accepting_identifier!r} does not match "
            f"invitation.identifier {invitation_identifier!r}",
            reason="identifier_mismatch",
        )
        self.accepting_identifier = accepting_identifier
        self.invitation_identifier = invitation_identifier
