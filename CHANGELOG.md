# Changelog

All notable changes to `flametrench-tenancy` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.4.1] — 2026-06-07

### Fixed
- `list_orgs` query filter parameter (now optional in the Postgres and in-memory stores). The v0.4.0 build shipped with the query parameter input omitted, causing 3 conformance cases to fail. v0.4.1 restores it.

## [v0.4.0] — 2026-06-07

### Added
- `list_orgs` ([ADR 0025](https://github.com/flametrench/spec/blob/main/decisions/0025-list-orgs.md)) — paginated org enumeration (system-level). Both `InMemoryTenancyStore` and `PostgresTenancyStore` implement `list_orgs(*, cursor, limit, status)` with opaque id-ascending cursor, limit clamped to 200, and optional `status` filter. This is a v0.4 feature per the conformance fixture (`spec_version: 0.4.0`).

## [v0.3.0] — 2026-06-07

### Changed
- Bumped `flametrench-ids` dependency floor to `>=0.3.0` (required for the `pat` ID type introduced in ids v0.3.0).
- Version aligned to `0.3.0` to track the cohort release.

## [v0.2.0rc5] — 2026-04-27

### Fixed
- `PostgresTenancyStore.accept_invitation` (when materializing pre-tuples) and `list_tuples_for_object` now accept wire-format `object_id` values with app-defined prefixes (e.g. `proj_<32hex>`, `file_<32hex>`) in addition to bare 32-hex and canonical hyphenated UUIDs. Previously, an invitation carrying pre-tuples with wire-format prefixed IDs failed at acceptance time when binding to the UUID column. Closes [`spec#8`](https://github.com/flametrench/spec/issues/8).

## [v0.2.0rc4] — 2026-04-27

### Added
- `PostgresTenancyStore` (new module `flametrench_tenancy.postgres`) — a Postgres-backed `TenancyStore`. Mirrors `InMemoryTenancyStore` byte-for-byte at the SDK boundary; the difference is durability and concurrency.
  - Schema: `spec/reference/postgres.sql` (the `org`, `mem`, `inv`, `tup` tables, plus the v0.2 `org.name`/`org.slug` ADR 0011 columns).
  - Connection: accepts any psycopg3-compatible connection. `psycopg[binary]>=3.1` declared as the `postgres` extra — adopters using only the in-memory store don't pull it in.
  - Multi-statement ops (`createOrg` + owner membership + tuple, `changeRole` revoke-and-re-add, `acceptInvitation` with pre-tuples, `transferOwnership`) run inside a transaction.
  - Coverage: 25 integration tests, gated on `TENANCY_POSTGRES_URL`.

## [v0.2.0rc3] — 2026-04-26

ADR 0011 org metadata (`name` + `slug`) — partial-update sentinel, slug-format validation, conflict semantics. See [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.2.0rc1] — 2026-04-25

Initial v0.2 release-candidate.

For pre-rc history, see git tags.
