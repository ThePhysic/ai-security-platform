# Phase 2B API and schema delta

All Phase 1/2A health, readiness, public bearer, exact Host/Origin, error, request-ID,
idempotency and signed keyset-cursor contracts remain. API remains loopback-only.
Public request limit remains 16 KiB. No scan can select arbitrary scanner options.

## Public routes

| Route | Phase 2B behavior |
| --- | --- |
| `POST /api/v1/source-snapshots` | Existing server-verified immutable snapshot registration; unchanged |
| `POST /api/v1/scan-runs` | Existing body and `Idempotency-Key`, now `profile_id: security-v1` or `fake-v1`; 202 with stable original resource on semantic replay, 409 on conflicting key |
| `GET /api/v1/scan-runs/{id}` | Existing parent/independent scanner states plus per-scanner provenance and coverage |
| `GET /api/v1/scan-runs?project=UUID` | Existing bounded signed keyset history; unchanged |
| `GET /api/v1/scan-runs/{id}/findings` | Existing keyset/filter contract; findings additionally include safe evidence and `synthetic`; real results are false |
| `GET /api/v1/findings/{id}` | Finding, scanner ID, coverage, provenance, snapshot ID/manifest digest and parent status; unknown ID 404 |
| `GET /api/v1/scan-runs/{id}/export?format=json` | Sanitized version-1 JSON attachment with scan and findings; bounded 1000 findings, 409 beyond limit, no silent truncation; only JSON accepted |

New real intake returns 503 `scanner_unavailable` when disabled or no current matching
launcher exists. Replaying an already accepted operation remains idempotent; availability
does not create a replacement resource. Fingerprints and occurrence keys remain distinct.
Per-scanner errors use safe categories; coverage stores validated warning codes, counts,
source/scanned/unscanned files, exclusions, policy/suppression counters and explicit
completion booleans. No absolute local source paths or raw secrets are exported.

## Internal host capability protocol

These POST routes are excluded from public OpenAPI, require the independent launcher
bearer, reject browser Origin and forbid extra contract fields. The result route alone
has a 512 KiB request ceiling. It is a narrow polling protocol, not a Docker proxy.

| Suffix under `/internal/v1/launcher` | Contract |
| --- | --- |
| `/hello` | UUID launcher identity, registry SHA256 and G4 proof SHA256; mismatch 409; records current DB timestamp |
| `/next` | UUID launcher identity; returns one current fixed-profile invocation or null |
| `/recover` | UUID launcher identity; at most 100 previous running handoffs reconciled under ownership after host orphan cleanup |
| `/{id}/check` | Launcher UUID, generation and lease UUID; returns current true or 409 |
| `/{id}/result` | Same identity plus normalized adapter result or one allowlisted error code; validation 422, stale ownership 409; staging only |

Returned invocation: UUID invocation/job IDs, positive attempt generation, secret lease
UUID, opaque snapshot key, manifest SHA256, `semgrep-v1` or `trivy-v1`, and accepted
registry SHA256. Lease tokens are never logged. There are no paths, mounts, commands,
argument arrays or caller-selected image fields. The protocol assumes one trusted
host launcher; privileged bearer compromise is outside the untrusted-source boundary.

## Forward migration `0003_scanner_handoff`

Parent is `0002_orchestration`. No development reset or historical-row rewrite.

| Object | Delta and constraints |
| --- | --- |
| `scanner_runs.provenance` | JSONB object, default `{}`, maximum 4096 serialized bytes |
| `findings.evidence` | JSONB object, default `{}`, maximum 2048 serialized bytes |
| `findings.synthetic` | Non-null bool, default true preserves accepted fake history; real publications explicitly false |
| `scanner_invocations` | UUID primary key; composite FK `(job_id,generation)` to attempts; unique pair; current token; pending/running/returned state; launcher UUID; created timestamp; returned iff result present; result JSONB object at most 512 KiB |
| `launcher_capabilities` | UUID primary key; 64-hex registry/proof digests and DB seen timestamp |

Existing job/scanner/finding uniqueness, indexes, attempts, immutable snapshot identity,
atomic acceptance and audit semantics remain. Only current fenced publication can add
real findings. API result validation and worker publication validation are independent.
The invocation-generation unique index bounds attempt lookup. No new external queue,
scanner-output object store or vector index exists.

Retained development rows were counted before/after the guarded forward migration,
with a private custom-format backup; see `migration-evidence.json`. Fresh migration,
repeatable upgrade, schema drift checks and downgrade/re-upgrade execute only against
the disposable test database. Destructive downgrade requires both the explicit test
marker and exact `asp_phase1_test`/`asp_test` identities. Never downgrade retained data.
