# Data, API and Workflow Contracts

Status: **APPROVED planning contracts; implementation evidence OPEN.** Phase introduction is explicit below; this document does not authorize building all entities in Phase 1.

## Schema and constraints

Use UUID identifiers, timezone-aware UTC timestamps, bounded strings and explicit allowed-state checks. Store queryable fields as columns; use versioned JSON for manifests, coverage and bounded structured outputs. Application validators and DB constraints complement each other.

| Entity | Core fields and constraints | Introduce |
|---|---|---|
| `projects` | ID, display name, created_at; logical grouping, no remote credential or tenant claim | Phase 1 |
| `source_snapshots` | ID, project FK, manifest version/digest, content digest, provenance kind, inclusion-policy digest, relative spool key, file/byte counts, created_at, retention state; unique project/content/manifest identity | Phase 1 metadata; actual intake 2A |
| `scan_runs` | ID, project/snapshot FKs, approved profile ID, resolved profile digest, aggregate status, created/started/completed timestamps; snapshot must belong to same project | Phase 1 metadata; submission/lifecycle 2A |
| `audit_events` | ID, event type, object type/ID, trusted actor/component, request/scan/job correlation, created_at, allowlisted metadata; append-only application interface | Phase 1; job fields added 2A |
| `idempotency_requests` | Scope, key, canonical semantic-request hash, response resource ID, created_at; unique scope/key | 2A |
| `scanner_runs` | Scan FK, scanner/profile/adapter identity, status, original provenance, coverage/exclusions, winning attempt, timestamps; unique scan/scanner execution slot | 2A fake; real provenance 2B |
| `jobs` | Scanner-run or triage-run target (exactly one), operation, state, generation, attempts/max_attempts, next_attempt_at, lease token/expiry, worker ID, heartbeat, hard deadline, safe error code | 2A scanner; triage target Phase 3 |
| `job_attempts` | Job FK, generation, worker ID, start/end, outcome, safe error code; unique job/generation; optional bounded sanitized launcher result in 2B | 2A |
| `findings` | Scanner-run/scan FK, occurrence key/version, tracking fingerprint/version, rule/category/CWE, original and normalized severity, safe message, canonical path/range, package/version/advisory identity, evidence refs | 2A fake; full 2B |
| `triage_runs` | Finding/snapshot FK, independent status, agent/prompt/tool/provider versions, consent reference, validated output/citations, sanitized tool trace, usage/timing/failure metadata | Phase 3 |
| `hosted_consents` | Local operator, snapshot, triage request/config scope, allowed data categories, created/revoked timestamps; no secret material | Phase 3 |
| `reviews` + `review_revisions` | Current disposition/note/revision, immutable revisions with trusted reviewer/timestamp; unique finding/revision | Phase 3 |

Phase 1 has only projects, source snapshot metadata, scan metadata and audit tables. No public snapshot registration or scan submission exists yet; tests insert valid metadata through storage fixtures, not fake production seed data. Phase 2A adds jobs and atomic acceptance before exposing submission. This avoids accepting work with no durable consumer contract.

Use foreign keys and compound project/snapshot checks rather than trusting request fields. Phase 2A requires queued accepted work to have required scanner records/jobs. All review changes and corresponding revisions/audit entries commit atomically. Append-only audit is an application property, not tamper resistance against DB administrators.

Do not cascade-delete source or findings underneath active jobs/triage. Cleanup protects active references. Expired source remains represented as unavailable; evidence APIs report that condition rather than returning a different snapshot. Phase 7 restore pairs DB records with matching snapshot digests; no claim that a DB-only backup restores source.

## Lifecycles and coverage

- Scan: `queued -> running -> succeeded | partial | failed`.
- Scanner execution: `queued -> running -> succeeded | failed`; retries remain internal to its job.
- Job: `queued -> running -> succeeded | retry_pending | terminal_failed`; due retries are claimable without a separate required state-conversion service. Expired running leases are recoverable under the same row lock.
- Triage: `queued -> running -> succeeded | unavailable | failed`; abstention is a valid successful structured result, not a scan failure.

Aggregate under a locked scan row after updating the scanner outcome, with a consistent lock order for all paths. A scan remains active while required scanner executions are active. Once all are terminal, all successful gives `succeeded`, mixed outcomes gives `partial`, none successful gives `failed`. No triage/review change rewrites scanning outcome.

Coverage is a separate structured field: files considered/scanned/skipped, exclusions and reasons, parser/rule timeouts, database age, unsupported ecosystems, output truncation and warnings. `succeeded` means execution completed, not exhaustive coverage. Empty incomplete results are not a clean bill of health. Output-limit failures cannot silently publish a clean success; preserve earlier successful scanners and expose partial coverage explicitly.

## Durable acceptance and ownership invariants

1. Authenticate, parse the bounded request and canonicalize semantic fields. Resolve an existing idempotency key before checking current capacity or snapshot availability: same hash returns its original resource, mismatch returns 409. For a new request only, validate snapshot/project/profile and capacity, resolve the trusted profile and record its digest. Replays retain that resolution even if defaults change, the snapshot later expires or intake is currently full.
2. In one transaction, enforce unique idempotency scope/key and create scan, scanner executions, jobs and acceptance audit event. Return 202 only after commit. On a uniqueness race, read the winning request in a valid transaction: same hash returns the original resource; different hash returns 409. Lost HTTP responses do not lose work.
3. Claim eligible work under `FOR UPDATE SKIP LOCKED`, ordered by due time then ID. Increment attempts and generation, assign a fresh unpredictable token, set DB-time expiry and create attempt history in the same short transaction. Do not claim more work than can start. Do not hold DB locks/connections while executing.
4. Heartbeat with a conditional update requiring running state, generation/token match, unexpired lease and hard-deadline compliance. Expired ownership cannot be revived. Use fresh DB time, not a long transaction's cached timestamp. Lease loss/DB uncertainty stops work where possible.
5. Publication locks the job row and validates operation, generation/token, current state and unexpired lease. While holding that lock, insert findings, update scanner/scan/triage and job/attempt state, and append authoritative completion events in the same bounded transaction. Reclaimer takes the same lock, so it cannot reassign ownership during publication. A stale/expired attempt publishes nothing, including different finding keys.
6. Validate and bound results before the publication transaction. Enforce the finding/output cap so finalization stays short. If any publication write fails, roll back all of it. A retry may rerun scanning; unique constraints plus fencing prevent duplicate authoritative publication.
7. Recovery locks expired rows, closes the old attempt, and schedules bounded backoff or terminal failure. Recovery events are authorized by this locked state transition, not by the expired worker token. Submission, review and recovery have their own transaction authority; they are not fabricated worker completions.
8. Use one lock order across completion/recovery paths (job, scanner execution, parent scan; attempt changes follow owning job). Parallel scanner completions serialize parent aggregation. Test deadlock/retry behavior rather than assuming ordering is enough.

Trial heartbeat/lease values (e.g. 15s/60s) are implementation tuning inputs, not SLOs. Bound total attempt runtime and retry count independently; a heartbeat cannot keep a hung scanner alive indefinitely. Retry transient DB/runner/provider failures with capped backoff and jitter; reject permanent invalid input/configuration and unsupported output schemas without retry storms.

There is no exactly-once compute guarantee. Old and new attempts may overlap after partitions; only current ownership may publish. Hosted requests may be billed twice. No automatic GitHub upload/remediation is part of job completion.

## Snapshot acquisition and registration (Phase 2A)

1. Local operator authorizes a directory. CLI enumerates regular files using a trusted inclusion policy; never follows links, loads target configuration as policy or executes target tooling.
2. Copy independent bytes to a new platform staging directory. Enforce file/count/byte/path budgets and validate Windows/Linux path representations, links, reparse points, special files, alternate streams, case/name collisions and copy-time mutation. Fail closed when required protection is unavailable.
3. Build a canonical manifest with sorted relative paths, file lengths/hashes, manifest version, inclusion-policy digest and provenance. Provenance includes acquisition kind, safe operator-provided label and optional declared commit; a commit label is not proof of a clean checkout. Never send absolute local source paths in API metadata.
4. Publish atomically under an immutable spool key. Registration accepts `{project_id, snapshot_key, manifest_digest}`; the key is an opaque validated identifier, never a path. Server recomputes/verifies registered content under its configured spool root and binds project ownership.
5. Unpublished/invalid source cannot be scanned. Protect spool writes and mount snapshots read-only in consumers. Verify identity at use; cleanup cannot race active references. Define raw-source TTL/size limits and cleanup behavior before intake acceptance.

No arbitrary archive endpoint, server clone, symlink dereference or remote URL fetch. CI prepares its authorized checkout locally through the same contract; it does not upload an arbitrary archive to a central service.

## Scanner/launcher contract (Phase 2B)

Adapter input: `{scan_id, scanner_run_id, snapshot_id, manifest_digest, approved_profile_id, profile_digest, generation, budget}`. Only trusted code resolves executable paths, image/rule/DB inputs and fixed argv. Never interpret repository strings as flags or commands; always invoke fixed executables without a shell.

Result envelope: `{schema_version, scanner_id, adapter_version, engine_version, image_digest, policy_digest, database_digest_and_age, status, coverage, findings, warnings, duration}`. Each finding includes original/normalized severity, safe relative path/range or dependency location, rule/advisory identity, redacted description, occurrence/tracking keys and validated evidence refs. UNKNOWN is retained. Validate paths/ranges against the manifest, bound nesting/strings/arrays, and reject invalid output.

Internal launcher interface is capability-restricted: receive an already leased invocation, verify current ownership before launch, and return only a bounded typed result tagged with job/generation/token. It cannot claim arbitrary host operations. Launcher uses the shared pure adapter code to normalize/redact raw output before submitting a result; ordinary worker revalidates and publishes. A sanitized staged result, if persisted in `job_attempts`, is fenced and is not a completed finding set until worker publication. Raw stdout is transient, never a database/log payload. Internal handoff names are implementation details to finalize/test in 2B; the fixed-operation and ownership requirements are not optional.

Lease token, local API credential, launcher credential and DB/provider secrets never enter scanner environment/mounts. Unknown/expired invocation or stale result is rejected and obsolete work is cleaned up.

## Finding identity

Within-run occurrence identity is versioned and unique per scanner execution; include rule/advisory identity, path, relevant location/context anchor and dependency identity as applicable. Separate versioned tracking fingerprints match candidates across scans. Do not merge different scanners' evidence or distinct advisories solely because file/rule match. Hash input must not persist raw secrets; omit suspected secret bytes from identity material.

Location movement, changed rules and changed scan scope can break matching. Preserve immutable occurrences and explicit provenance. Never automatically copy a review disposition or declare remediation solely because an occurrence disappears.

## HTTP contracts and phase introduction

All data endpoints authenticate and restrict Host/Origin. Errors are sanitized `{code, message, request_id, retryable, details}`; details contain allowlisted field/code data, never submitted values or raw validation bodies. UUID/path/enum constraints are documented in OpenAPI.

| Endpoint | Contract | Phase |
|---|---|---|
| `GET /health` | 200 coarse process liveness, no dependency probe/secrets | 1 |
| `GET /ready` | 200 expected DB/schema available, else 503 safe category; no scanner/provider dependency | 1 |
| `POST /api/v1/projects` | Bounded `{name}`; 201 project metadata; create and audit commit together | 1 |
| `GET /api/v1/projects/{id}` | 200 metadata or 404 | 1 |
| `GET /api/v1/scan-runs/{id}` | 200 persisted metadata; add per-scanner outcomes/coverage in 2A/2B; 404 unknown | 1 read-only |
| `POST /api/v1/source-snapshots` | Verified local registration; 201; repeated same project/key/digest resolves same snapshot; mismatch 409 | 2A |
| `POST /api/v1/scan-runs` | `{project_id, snapshot_id, profile_id}` + required `Idempotency-Key`; 202 with `{id,status,status_url}` and Location; replay same ID; mismatch 409 | 2A |
| `GET /api/v1/scan-runs` | Project/status filters, bounded keyset cursor | 2A |
| `GET /api/v1/scan-runs/{id}/findings` | Severity/scanner/rule/review filters, bounded cursor | 2A fake; full 2B/3 |
| `GET /api/v1/findings/{id}` | Sanitized finding, coverage, evidence/triage/review summaries | 2B |
| `POST /api/v1/findings/{id}/triage` | Idempotent 202, separate triage ID/Location; hosted consent validated before transmission | 3 |
| `GET /api/v1/triage-runs/{id}` | Independent triage state, validated result/abstention or safe failure | 3 |
| `PUT /api/v1/findings/{id}/review` | `{expected_revision, disposition, note}`; first write expects 0, success increments; stale revision 409 | 3 |
| `GET /api/v1/scan-runs/{id}/export?format=json\|sarif` | Sanitized deterministic export; partial coverage represented; protected download | JSON 2B, SARIF 5 |

Unimplemented routes are absent/404, never fake success. Phase 1 exposes no scan POST or snapshot registration and no seed findings. Its metadata reads are exercised with test-only storage fixtures.

HTTP semantics: 400 malformed semantic/cursor request; 401 missing/invalid bearer; 403 denied origin/capability or hosted-consent policy; 404 unknown resource; 409 idempotency/revision/registration conflict; 413 intake/request limit; 422 typed body/parameter validation; 429 capacity exceeded; 503 temporary DB/schema/required capability unavailable. Safe 500 for unexpected errors. Bound request bodies/headers/notes and return retry guidance where meaningful. No stack traces, request echo or credential data.

Idempotency scope is local principal plus operation/resource scope. Keys are bounded opaque strings (maximum 128 safe ASCII characters), not credentials or log messages. Canonical payload includes IDs and explicit semantic options; equivalent JSON ordering does not cause mismatch. Do not expire keys independently while their resource persists; no key reuse during MVP history retention.

## Query/index contract

Default descending `(created_at, id)` keyset order; cursor carries version, last key, filter digest and initial upper watermark. Validate cursor and cap `limit` at 100 (default 50). Filters must match the cursor. Concurrent newer scans do not enter an existing traversal. Changes in mutable status/review filters may change membership: pagination is not a historical DB snapshot. Document that limitation; do not promise snapshot consistency.

Initial indexes: project scan history `(project_id, created_at DESC, id DESC)`, due runnable jobs and expired running leases (partial state indexes), findings `(scan_run_id, normalized_severity, id)` and scanner lookup, unique occurrence keys and review revision keys. Add rule/review/free-text indexes only after representative EXPLAIN results. Never interpolate filters/sort columns into raw SQL without an allowlist.

## Optional schema boundary

Phase 8 only: separate `soc` namespace for synthetic `security_events`, `investigations` and append-only `analyst_feedback`, with independent migrations/routes/fixtures and feature disablement. Do not add SOC columns or required imports to flagship finding tables. No Phase 1 SOC tables or modules.
