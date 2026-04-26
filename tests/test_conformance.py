# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Flametrench v0.1 conformance suite — Python harness for tenancy.

Implements the state-machine fixture format defined in
spec/conformance/fixture.schema.json. Each test:

1. Pre-allocates fresh usr_ IDs for declared named users.
2. Creates a fresh InMemoryTenancyStore.
3. Walks the steps list. Each step's input has {name} references resolved
   against the variable map (declared users + previous captures). The
   step calls the matching operation; on success captures may extract
   values for later substitution; on expected error the step MUST throw.

Pseudo-ops recognized only by the harness (not part of the SDK surface):

- assert_subject_relations(subject_type, subject_id, relations[])
- assert_equal(actual, expected)

This file is the canonical reference implementation of the state-machine
harness contract. Other-language harnesses (Node, PHP, Java) follow the
same shape with camelCase / PascalCase / Map-of-record adaptations.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from flametrench_ids import generate

from flametrench_tenancy import (
    AlreadyTerminalError,
    DuplicateMembershipError,
    ForbiddenError,
    IdentifierBindingRequiredError,
    IdentifierMismatchError,
    InMemoryTenancyStore,
    InvitationExpiredError,
    InvitationNotPendingError,
    NotFoundError,
    PreTuple,
    PreconditionError,
    Role,
    RoleHierarchyError,
    SoleOwnerError,
    TenancyError,
)

_FIXTURES_DIR = Path(__file__).parent / "conformance" / "fixtures"

_VAR_PATTERN = re.compile(r"^\{([a-z_][a-z0-9_]*)\}$")


def _load_fixture(relative_path: str) -> dict[str, Any]:
    return json.loads((_FIXTURES_DIR / relative_path).read_text(encoding="utf-8"))


_ERROR_CLASSES: dict[str, type[Exception]] = {
    "SoleOwnerError": SoleOwnerError,
    "RoleHierarchyError": RoleHierarchyError,
    "ForbiddenError": ForbiddenError,
    "DuplicateMembershipError": DuplicateMembershipError,
    "InvitationNotPendingError": InvitationNotPendingError,
    "InvitationExpiredError": InvitationExpiredError,
    "PreconditionError": PreconditionError,
    "AlreadyTerminalError": AlreadyTerminalError,
    "NotFoundError": NotFoundError,
    "TenancyError": TenancyError,
    "IdentifierBindingRequiredError": IdentifierBindingRequiredError,
    "IdentifierMismatchError": IdentifierMismatchError,
}


def _resolve(value: Any, variables: dict[str, Any]) -> Any:
    """Recursively substitute {var} references in a value tree."""
    if isinstance(value, str):
        match = _VAR_PATTERN.match(value)
        if match:
            name = match.group(1)
            if name not in variables:
                raise KeyError(f"Unknown variable in fixture: {{{name}}}")
            return variables[name]
        return value
    if isinstance(value, list):
        return [_resolve(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: _resolve(v, variables) for k, v in value.items()}
    return value


def _walk_path(obj: Any, dotted_path: str) -> Any:
    """Walk a dotted path into a value (object attribute, dict key, or list index)."""
    current = obj
    for segment in dotted_path.split("."):
        if hasattr(current, segment):
            current = getattr(current, segment)
        elif isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            raise KeyError(
                f"Cannot resolve path segment '{segment}' on {type(current).__name__}"
            )
    return current


def _to_role(value: str) -> Role:
    return Role(value)


def _build_pre_tuples(values: list[dict[str, Any]] | None) -> list[PreTuple]:
    if not values:
        return []
    return [
        PreTuple(
            relation=v["relation"],
            object_type=v["object_type"],
            object_id=v["object_id"],
        )
        for v in values
    ]


def _invoke_op(
    store: InMemoryTenancyStore, op: str, args: dict[str, Any]
) -> Any:
    """Dispatch a fixture op name to the matching SDK or harness method."""
    if op == "create_org":
        return store.create_org(args["creator"])

    if op == "add_member":
        return store.add_member(
            args["org_id"],
            args["usr_id"],
            _to_role(args["role"]),
            invited_by=args.get("invited_by"),
        )

    if op == "change_role":
        return store.change_role(args["mem_id"], _to_role(args["new_role"]))

    if op == "suspend_membership":
        return store.suspend_membership(args["mem_id"])

    if op == "reinstate_membership":
        return store.reinstate_membership(args["mem_id"])

    if op == "self_leave":
        return store.self_leave(args["mem_id"], transfer_to=args.get("transfer_to"))

    if op == "admin_remove":
        return store.admin_remove(args["mem_id"], args["admin_usr_id"])

    if op == "transfer_ownership":
        return store.transfer_ownership(
            args["org_id"], args["from_mem_id"], args["to_mem_id"]
        )

    if op == "create_invitation":
        ttl_seconds = args.get("ttl_seconds", 86400)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        return store.create_invitation(
            org_id=args["org_id"],
            identifier=args["identifier"],
            role=_to_role(args["role"]),
            invited_by=args["invited_by"],
            expires_at=expires_at,
            pre_tuples=_build_pre_tuples(args.get("pre_tuples")),
        )

    if op == "accept_invitation":
        return store.accept_invitation(
            args["inv_id"],
            as_usr_id=args.get("as_usr_id"),
            accepting_identifier=args.get("accepting_identifier"),
        )

    if op == "decline_invitation":
        return store.decline_invitation(args["inv_id"], as_usr_id=args.get("as_usr_id"))

    if op == "revoke_invitation":
        return store.revoke_invitation(args["inv_id"], args["admin_usr_id"])

    if op == "suspend_org":
        return store.suspend_org(args["org_id"])

    if op == "reinstate_org":
        return store.reinstate_org(args["org_id"])

    if op == "revoke_org":
        return store.revoke_org(args["org_id"])

    # Harness-only assertion pseudo-ops.
    if op == "assert_subject_relations":
        tuples = store.list_tuples_for_subject(
            args["subject_type"], args["subject_id"]
        )
        actual = sorted(t.relation for t in tuples)
        expected = sorted(args["relations"])
        assert actual == expected, (
            f"assert_subject_relations: expected relations {expected}, got {actual} "
            f"for ({args['subject_type']}, {args['subject_id']})"
        )
        return None

    if op == "assert_equal":
        assert args["actual"] == args["expected"], (
            f"assert_equal: expected {args['expected']!r}, got {args['actual']!r}"
        )
        return None

    if op == "assert_invitation_status":
        inv = store.get_invitation(args["inv_id"])
        assert inv.status.value == args["expected_status"], (
            f"assert_invitation_status: expected {args['expected_status']!r}, "
            f"got {inv.status.value!r}"
        )
        return None

    raise RuntimeError(f"Unknown fixture op: {op}")


def _run_test(test: dict[str, Any]) -> None:
    store = InMemoryTenancyStore()
    variables: dict[str, Any] = {
        name: generate("usr") for name in test.get("users", [])
    }

    for step in test["steps"]:
        op = step["op"]
        resolved_input = _resolve(step["input"], variables)

        expected = step.get("expected")
        if expected and "error" in expected:
            error_class = _ERROR_CLASSES[expected["error"]]
            with pytest.raises(error_class):
                _invoke_op(store, op, resolved_input)
            return  # error step terminates the test

        result = _invoke_op(store, op, resolved_input)

        captures = step.get("captures")
        if captures:
            for name, path in captures.items():
                variables[name] = _walk_path(result, path)


def _collect_tests(relative_path: str) -> list[Any]:
    fixture = _load_fixture(relative_path)
    return [pytest.param(t, id=t["id"]) for t in fixture["tests"]]


# ─── tenancy.self_leave ───


@pytest.mark.parametrize("test_case", _collect_tests("tenancy/self-leave.json"))
def test_self_leave_conformance(test_case: dict[str, Any]) -> None:
    _run_test(test_case)


# ─── tenancy.change_role ───


@pytest.mark.parametrize("test_case", _collect_tests("tenancy/change-role.json"))
def test_change_role_conformance(test_case: dict[str, Any]) -> None:
    _run_test(test_case)


# ─── tenancy.transfer_ownership ───


@pytest.mark.parametrize(
    "test_case", _collect_tests("tenancy/transfer-ownership.json")
)
def test_transfer_ownership_conformance(test_case: dict[str, Any]) -> None:
    _run_test(test_case)


# ─── tenancy.admin_remove ───


@pytest.mark.parametrize("test_case", _collect_tests("tenancy/admin-remove.json"))
def test_admin_remove_conformance(test_case: dict[str, Any]) -> None:
    _run_test(test_case)


# ─── tenancy.accept_invitation ───


@pytest.mark.parametrize(
    "test_case", _collect_tests("tenancy/invitation-accept.json")
)
def test_accept_invitation_conformance(test_case: dict[str, Any]) -> None:
    _run_test(test_case)


# ─── tenancy.accept_invitation — identifier binding (ADR 0009) ───


@pytest.mark.parametrize(
    "test_case", _collect_tests("tenancy/invitation-accept-binding.json")
)
def test_accept_invitation_binding_conformance(test_case: dict[str, Any]) -> None:
    _run_test(test_case)
