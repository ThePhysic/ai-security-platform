# Approved Architecture, ADRs and Feasibility Register

Status: **Architecture APPROVED by the user. Implementation and validation remain separate.** Earlier `VALIDATE` stack choices are approved decisions with open implementation gates, not unresolved architecture approvals.

## Components

```text
src/ai_security_platform/
  api/          HTTP validation, local authentication, origins/hosts, errors
  domain/       typed contracts, lifecycle, finding identity, review rules
  storage/      SQLAlchemy models, sessions, repositories, transactions
  jobs/         claims, attempts, heartbeat, retries and recovery
  snapshots/    manifests, local publication, registration, scoped reads
  scanners/     versioned adapters and normalization; no Docker authority
  agent/        scoped tools, provider adapter, evidence validation
  reporting/    JSON, SARIF and policy evaluation
  cli/          operator workflow
runner/         separate trusted host launcher and fixed execution profiles
policies/       trusted rules/configuration and provenance
migrations/
tests/
evaluation/
web/            React/TypeScript/Vite, Phase 6 only
```

These are module boundaries, not one service per directory. API and ordinary workers share a package with separate entry points. Compose runs API, PostgreSQL and later workers, never with Docker authority. The trusted launcher runs explicitly on the host, outside API/worker containers. Only create modules in the phase that needs them; [09](09-PHASE1-SPECIFICATION.md) defines Phase 1's subset.

## ADR-01 — Runtime and persistence

**APPROVED.** Python 3.12, uv, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, Psycopg 3 and PostgreSQL. Pin compatible patches, packages and images during Phase 1. Start with synchronous DB sessions and synchronous DB-backed FastAPI handlers. Separate durable workers provide asynchronous execution. No scanner/model calls in HTTP transactions or request-scoped background tasks.

Use one session per request or short worker operation, reliable rollback/close, no import-time DB connection, and explicit migrations rather than migration-on-startup races. Readiness checks connectivity and expected schema revision. Avoid default Redis/Celery and extra async DB lifecycle complexity.

**G1 — OPEN, Phase 1:** reproducible lock, migrations, local authenticated API, restart persistence and network/logging tests. Exact patch/image selection is an implementation choice within this approved stack.

## ADR-02 — PostgreSQL orchestration and publication fencing

**APPROVED.** At-least-once execution using `FOR UPDATE SKIP LOCKED`, increasing attempt generation, fresh lease token, database-time expiry, independent heartbeats, bounded backoff/jitter and retries. No open transaction during scanner/model execution. Submission atomically creates the scan and required scanner jobs. [03](03-DATA-API-AND-WORKFLOW.md) owns detailed transaction invariants.

Fence all attempt-authoritative writes (findings, scanner/scan/triage state and completion audit events) against current ownership in the same publication transaction. Uniqueness alone cannot reject stale attempts inserting different findings. Worker IDs are diagnostics, not ownership. Compute/external calls may repeat; there is no exactly-once execution or provider billing guarantee.

Use one job per scanner execution and one per triage request, plus fixed aggregation logic rather than a general DAG. Preserve successful scanner results if another scanner fails. Lease loss stops work where possible; publication is rejected regardless of whether process termination succeeds.

**G2 — OPEN, Phase 2A:** real PostgreSQL multiprocess tests, duplicate submission, racing claims, 25 controlled crash/retry experiments, stale heartbeat/finding/state/audit rejection, retry exhaustion and bounded polling. No automatic queue replacement; any infrastructure change needs a new approved ADR.

## ADR-03 — Immutable local source snapshots

**APPROVED.** Acquisition is authorized; content remains untrusted. Local CLI copies regular file bytes into platform-owned staging, validates a canonical manifest, records provenance and inclusion policy, then atomically publishes. API accepts registered opaque IDs, never host paths, URLs or archives. Registration resolves IDs only under the configured spool and revalidates the manifest; caller hashes alone are not proof.

Reject traversal, symlinks, Windows reparse points/junctions, device/special files, alternate streams, unsafe hardlink handling and cross-platform name collisions. Never preserve source links; detect mutation during copying. No Git hooks/submodule fetch, package install or target execution. Immutable spool access, active-reference cleanup, disk quotas and raw-source retention are explicit requirements. Hashing proves identity, not authorization or safety.

**G3 — OPEN, Phase 2A:** Windows/path/mutation tests, manifest verification, spool permissions, atomic publication and CLI/API registration. Remote cloning and arbitrary archive ingestion are **DEFERRED**.

## ADR-04 — Trusted host-side scanner launcher

**APPROVED; SECURITY GATE OPEN.** Separate trusted host process owns Docker access and launches disposable Linux scanner containers with fixed profiles. No daemon socket, Windows named pipe, remote daemon credentials or equivalent authority reaches API, ordinary workers or scanners.

Launcher polls a narrow authenticated job interface. It accepts current job ID/generation/token and approved profile/snapshot IDs, deriving images, argv, mounts, limits and environment from trusted configuration. No arbitrary commands, image names, host paths, flags, plugins or URLs. Separate launcher capability credentials from ordinary API credentials; scanners receive neither. Scanner output cannot select subsequent launcher actions. The launcher is part of the trusted computing base, not a generic Docker proxy.

Each invocation uses non-root UID, dropped capabilities, no privilege escalation, read-only snapshot/rootfs, bounded temporary storage, CPU/memory/PID/output limits, disabled networking and a hard deadline. Capture bounded stdout/stderr without a writable host output bind. Mount only that snapshot and required trusted policies/DB inputs read-only. Use per-attempt identities, kill obsolete work, and reconcile orphan containers on launcher restart. Never attach a replacement attempt to an old container.

Prepare images, rules and vulnerability databases separately in a trusted network-enabled step with no source mounted. Validate actual Docker Desktop enforcement and Windows/Linux filesystem semantics. Containers alone are not a containment guarantee.

**G4 — OPEN, Phase 2B:** exact Windows/Docker Desktop boundary, denied egress, fixed mounts, privilege/resource enforcement, injection resistance, orphan cleanup and fenced result submission. Untrusted scanning is blocked until passed. If not deliverable, accept only approved controlled fixtures and fail closed; visibly disclose restricted mode. A failed gate does not authorize host subprocess scanning of untrusted input.

## ADR-05 — Adapters and policy authority

**APPROVED.** Semgrep SAST and Trivy dependency/secrets/selected configuration checks behind versioned adapters. Store independent outcomes and coverage; capture engine/image, adapter, rules/policy and database versions/digests. Preserve original severity; missing data remains UNKNOWN.

Policy files, cwd, environment, ignore behavior and secret rules are trusted configuration outside the target. Explicitly address `.gitignore`, `.semgrepignore`, inline suppression, Trivy config/ignore/secret files, plugins and telemetry. Default audit mode must not let target content silently suppress required findings. Document and version-test any reliance on internal flags. Show exclusions, timeouts, missing/stale DBs and truncation as coverage limits.

**G5 — OPEN, Phase 2B:** positive/clean fixtures, suppression/config poisoning, schema/path/output limits and offline coverage. Validate selected rule redistribution separately from engine licensing. No commercial-only scanning capability is assumed.

## ADR-06 — Agent and human authority

**APPROVED.** Small explicit bounded read-only tool loop, structured results, snapshot/line citation validation, abstention and step/token/byte/cost/time limits. Deterministic offline test provider and one separately opt-in hosted provider. No default agent framework/vector DB. Trusted provider adapter makes requests; the model has no general network tool.

Application code scopes tools to the triage run; model-selected roots are forbidden. No shell, arbitrary URLs, writes, dynamic plugins or automatic remediation. A designated acceptance scenario requires both finding inspection and source/context retrieval; call count alone is not a quality metric. Provider failure leaves scanner results intact. Human dispositions use optimistic concurrency and immutable revisions, separately from AI opinions.

**G6 — OPEN, Phase 3:** real retrieval, evidence/abstention checks, initial injection/confinement tests, trace redaction, hosted-consent enforcement and review conflicts. **G7 — OPEN, Phase 4:** expanded held-out adversarial/quality evaluation. Provider selection/privacy setup belongs to Phase 3 and does not block Phase 1.

## ADR-07 — Local access and privacy

**APPROVED.** Single-user local API with opaque bearer authentication, exact allowed browser origins, allowed Host values and loopback publication. PostgreSQL has no published port by default. All data endpoints authenticate; only coarse `/health` and `/ready` are public. Reject disallowed/null Origin. CLI without Origin still authenticates. No wildcard/reflective CORS, tenant isolation claim or project-ID-based pseudo-authorization.

Structured logging uses an allowlist and excludes bodies, source, authorization headers, DB URLs, keys and raw scanner/model output. Hosted source transmission needs explicit snapshot/run consent; secret findings default to location/rule/redacted metadata. Provider credentials exist only in the trusted provider component. Raw snapshot files and transient scanner output can contain secrets: restrict access and retention. Heuristic redaction is not a confidentiality proof.

**G1 (OPEN, Phase 1):** authentication/origin/host/logging. **G6 (OPEN, Phase 3):** hosted privacy boundary. **G9 (OPEN, Phase 6):** browser access/rendering. Public hosting and enterprise identity are **DEFERRED**.

## ADR-08 — Developer integration and UI

**APPROVED.** Minimal CLI in Phase 2A; complete workflow, SARIF and CI in Phase 5. Export works without GitHub upload. Upload depends on eligibility/configuration and explicit approval. Pin trusted actions, minimize tokens, disable checkout credential persistence and never execute target scripts in privileged workflows. Artifacts are the fallback.

Minimal React/TypeScript/Vite reporting follows backend/evaluation/integration gates in Phase 6. Metrics use persisted counts, coverage, dispositions and age. Do not equate finding disappearance with a confirmed fix or invent a composite risk score.

**G8 — OPEN, Phase 5:** clean-checkout CI/CLI, SARIF, recovery and workload evidence. **G9 — OPEN, Phase 6:** authenticated, accessible, safely rendered UI. **G10 — OPEN, Phase 7:** rebuild, restore and final hardening.

## ADR-09 — Scope and independent extensions

**APPROVED.** Phases 1–7 define the flagship. No default Redis, Celery, Kubernetes, vector DB, SIEM, automatic remediation or general workflow engine. Scope expansion requires separate authorization.

Phase 8 Prophet SOC simulation is **DEFERRED**, synthetic-only, separately authorized after Phase 7 and independently removable, with separate modules/schema/routes. The completed Matroid project remains a separate audit. Its Redis/BullMQ stack is not a flagship dependency.

## Risk and blocking register

| Risk | Severity | Owner/gate | Disposition |
|---|---|---|---|
| Parser/container escape or powerful launcher | High | `runner/`, G4 | Untrusted scanning blocked; controlled-fixture fallback |
| Stale results/state/audit publication | High | `jobs/` + `storage/`, G2 | Block real scanner integration until fenced writes pass |
| Snapshot escape/mutation/path ambiguity | High | `snapshots/`, G3 | Reject unsafe inputs; restrict spool |
| Suppression or missing offline coverage | High | `scanners/` + `policies/`, G5 | Poisoning tests and visible coverage |
| Source/secrets disclosed through model/reporting | High | `agent/` + `reporting/`, G6/G8 | Offline default, scoped consent, data minimization |
| Local browser access/active report content | High | `api/` + `web/`, G1/G9 | Auth, origins/hosts and safe rendering |
| Scope exceeds portfolio delivery capacity | Medium | All phase owners | One assigned phase at a time; keep extensions excluded |
| Dependency/image/rule compatibility | Medium | Integrating phase | Pin and validate before use; report capability limits |
| Source retention/disk exhaustion/restore mismatch | Medium | `snapshots/` + `storage/`, G3/G10 | Bound intake, protect active refs, restore DB/spool consistently |

No unresolved architecture issue blocks Phase 1. Explicit implementation authorization is absent. Inability to resolve dependencies or validate the runtime/DB prevents a passing Phase 1 gate and must be reported, not hidden by changing the stack.

## Evidence status and reference basis

Prior read-only review found Python 3.12/uv and Docker/Compose CLIs. WSL status returned access denied; daemon readiness, containment, dependency resolution and app behavior were not tested. No implementation gate has passed.

Reference basis from the prior review, not new runtime validation: [PostgreSQL locking](https://www.postgresql.org/docs/current/sql-select.html), [Docker security](https://docs.docker.com/engine/security/), [Semgrep CLI](https://docs.semgrep.dev/cli-reference), [Trivy configuration](https://trivy.dev/latest/docs/references/configuration/config-file/), [Trivy offline operation](https://github.com/aquasecurity/trivy/blob/main/docs/guide/advanced/air-gap.md), [GitHub Actions security](https://docs.github.com/en/actions/reference/security/secure-use), [GitHub code scanning](https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning). Revalidate version-dependent flags and eligibility in the integrating phase.
