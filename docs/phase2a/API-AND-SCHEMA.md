# Implemented Phase 2A contracts

Existing Phase 1 access controls and sanitized error envelopes remain. Health/readiness
are public under Host/Origin checks; data routes require the local bearer.

| Operation | Behavior |
|---|---|
| POST /api/v1/source-snapshots | project_id, snapshot_key, manifest_digest; opaque lowercase 32-hex key and 64-hex SHA; verify local mounted bytes; 201 metadata; same registration returns original; conflict 409; unavailable mandatory capability 503 |
| POST /api/v1/scan-runs | project_id, snapshot_id, profile_id=fake-v1; one required safe Idempotency-Key, 1–128 chars; atomic 202 with id/status/status_url and Location; replay same ID; conflict 409; capacity 429 |
| GET /api/v1/scan-runs/{id} | Original fields plus per-scanner version/status/coverage/error/winning generation; unknown 404 |
| GET /api/v1/scan-runs | Required project UUID; optional status/cursor/limit |
| GET /api/v1/scan-runs/{id}/findings | Optional severity/scanner/rule_id/cursor/limit; immutable normalized synthetic findings, no source excerpts |

Default limit 50, maximum 100. Descending created_at/UUID keyset cursors are versioned,
HMAC authenticated, <=2,048 characters, and bind the last tuple, initial upper watermark
and filter digest. Filter mismatch/tampering returns 400. Newer records cannot enter
an existing traversal. Mutable status membership is not a historical DB snapshot.
Bearer rotation invalidates cursors. Queries use LIMIT+1 and no OFFSET.
Review filters wait for Phase 3. No detail/export/review/real-scanner endpoint exists.

Request/header/time limits, field-only 422 errors, correlation IDs, safe 500/503,
exact local hosts/origins and disabled proxy/access logs remain. Unregistered,
unverified, expired or mismatched source cannot become newly accepted work.
No archive/path-valued registration/remote URL/clone endpoint exists.

Revision `0002_orchestration` extends `0001_foundation` without resetting retained data:

| Table | Added fields/invariants |
|---|---|
| source_snapshots | acquired_at/expires_at/verified, default false for old metadata; existing uniqueness/FKs/digests retained |
| scanner_runs | Unique scan/scanner slot; bounded JSON coverage; status, adapter version, winning generation, timestamps/error |
| jobs | Unique scanner job; allowed states; attempts=generation<=max 1..5; complete running lease shape, absent otherwise |
| job_attempts | Unique job/generation; worker, timestamps/outcome; terminal outcome requires completion |
| findings | Unique scanner occurrence; compound scan/scanner, job/scanner and job/generation FKs; bounded versioned fingerprints, normalized fields and source ranges |
| idempotency_requests | Unique principal-operation scope/key; canonical payload SHA and accepted scan FK |
| audit_events | Restricted new event/object/actor combinations; safe request ID; empty metadata or positive integer generation only |

Partial due/expired job indexes support claims/recovery. Existing project history and
finding scan/history/severity indexes support bounded reads. Findings keep their scanner
identity; different scanners are never merged. Rich engine/image/rule/DB/CWE/dependency
provenance belongs to Phase 2B.

Constraints enforce shape, uniqueness and reference integrity. Trusted application
transactions enforce lease authority under the job lock; a DB administrator or writer
bypassing that interface can bypass fencing. Audit is application append-only, not
administrator tamper resistance.

All completion/recovery paths lock job -> scanner -> parent; attempt changes follow the
owning job. No DB connection remains checked out while source is read/scanned.
Publication validates ownership with fresh database time and atomically commits all
authoritative writes. Output/transaction failure publishes no partial finding set.
Other successful scanner slots remain available; mixed terminal outcomes yield partial.
