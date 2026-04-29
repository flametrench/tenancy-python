# flametrench-tenancy

[![CI](https://github.com/flametrench/tenancy-python/actions/workflows/ci.yml/badge.svg)](https://github.com/flametrench/tenancy-python/actions/workflows/ci.yml)

Python SDK for the [Flametrench](https://github.com/flametrench/spec) tenancy specification: organizations, memberships (with the `mem_`/`tup_` duality), and atomic invitation acceptance.

**Status:** v0.2.0rc6 (release candidate). Includes the production-ready `PostgresTenancyStore` alongside the in-memory reference store. Per ADR 0013 the Postgres adapter cooperates with adopter-side outer transactions via savepoints when nested (psycopg3 `connection.transaction()` handles this automatically).

The same behavioral guarantees that gate `@flametrench/tenancy` (Node), `flametrench/tenancy` (PHP), and `dev.flametrench:tenancy` (Java) hold here:

- **Revoke-and-re-add** on role changes, with a `replaces` chain for audit history.
- **Sole-owner protection** on every path that could leave an org without an active owner (change_role, suspend_membership, self_leave).
- **Atomic invitation acceptance** — user creation, membership insertion, owner-role tuple, AND pre-tuple expansion all in one transition.
- **Role hierarchy** on `admin_remove` — admins cannot remove peers or higher-ranked members.
- **mem_/tup_ duality** — every active membership is shadowed by a corresponding `(usr, role, org)` tuple, kept in lockstep with `mem.status`.

```python
from datetime import datetime, timedelta, timezone

from flametrench_ids import generate
from flametrench_tenancy import InMemoryTenancyStore, PreTuple, Role

store = InMemoryTenancyStore()
alice = generate("usr")
result = store.create_org(alice)
print(result.org.id, result.owner_membership.role)  # → org_..., Role.OWNER

# Invite a new user and pre-attach an editor grant on a project.
project_id = generate("org")[4:]
inv = store.create_invitation(
    org_id=result.org.id,
    identifier="newbie@example.com",
    role=Role.MEMBER,
    invited_by=alice,
    expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    pre_tuples=[PreTuple(relation="editor", object_type="proj", object_id=project_id)],
)

out = store.accept_invitation(inv.id)
print(out.membership.role, out.materialized_tuples)
```

## Installation

```bash
pip install flametrench-tenancy
```

Requires Python 3.11+. Depends on `flametrench-ids` for usr_/org_/mem_/inv_ id generation.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Copyright 2026 NDC Digital, LLC.
