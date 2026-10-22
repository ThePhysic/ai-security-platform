# Separate Companion — Matroid Visual Inspection Platform Security Audit and Hardening

Status: **Separate approved planning scope; audit execution and changes in the Matroid repository require separate authorization.** Role order for the flagship is 1Password, Brain Co, Prophet Security; this companion does not introduce a second platform or SOC.

Target: user's **completed** Matroid SWE Visual Inspection Platform (Fastify/TypeScript API + React UI + MongoDB + Redis/BullMQ workers + Docker Compose/CI). Retain its existing design and reliability achievements; do not rewrite it in Python or import it into flagship.

The stack above is supplied project context, not a fresh code inspection. Confirm actual components and trust assumptions in SA-0. Existing Redis/BullMQ usage in Matroid does not add those dependencies to the flagship.

## SA-0 — Scope and threat model
Inspect actual code and README, identify deployed vs demo assumptions, public vs local endpoints, trusted users, authentication expectations, valuable assets (uploaded images, annotations, histories, job state, secrets), trust boundaries (browser/API/DB/worker/storage/containers), and intended production evolution. In a single-user local demo, absence of full auth is not automatically a bug; document what would be needed if users/tenants were introduced.

**Gate:** diagram, asset inventory, explicit authorization/tenant applicability table, reproducible environment and initial risk register.

## SA-1 — Automated + manual review
After flagship Phase 2B, scan an explicitly authorized immutable local snapshot only if the source/isolation gates permit it, plus manual checks below. Matroid source remains untrusted scanner input. If G4 is still restricted to approved controlled fixtures, do not silently classify the whole Matroid application as a fixture or bypass the isolation gate; proceed with authorized manual review and defer automated scanning until eligible.

Review areas:
- API authorization / IDOR exposure if applicable: GET asset content, inspection status/history, retry, review endpoints; input validation and rate/size limits.
- Secure image upload: MIME vs magic bytes, limits, filenames, canonicalized paths, race/cleanup and malicious/oversized input handling. Ensure safe filesystem/storage maintenance semantics.
- Worker / BullMQ: job payload trust, idempotency, retries, queue poisoning, resource exhaustion, Redis configuration and crash recovery.
- Data: MongoDB indexes/queries, revision concurrency, accidental cross-record access, secure logs, sensitive information in response and error messages.
- Docker/nginx/CI: least privileges, network bindings, allowed origins, secrets use, non-root images, GitHub workflow permissions, pinned base/actions as appropriate.
- Threat model: SSRF/remote inference risk **only if those capabilities exist**; do not invent endpoints/features.

**Gate:** evidence for every finding (path/line/test), severity rationale and false-positive disposition; no speculative CVEs claimed as real.

## SA-2 — Fixes and tests
Tackle confirmed high-value, non-disruptive fixes. Add focused regression tests that fail before the fix and pass after. If adopting authentication or tenant isolation, implement correct authorization boundaries deliberately, not superficial fake middleware. Preserve stable behavior and previously validated Matroid backend reliability.

Fixes require a separate Matroid implementation task; flagship phase authorization does not authorize changes there. Record patch ownership, existing test commands and rollback/backup requirements before modifying upload/storage/queue behavior. Run only its trusted regression harness; do not execute code from an arbitrary scan target. Roll back an incompatible patch without deleting uploaded data or resetting queues to hide failures.

**Gate:** each accepted finding has before/after evidence, test and change rationale; no regressions in existing Docker/integration reliability suites.

## SA-3 — Report and résumé evidence
Deliver threat model, severity-ranked findings with disposition, patches/PR notes, test results, residual risks and a short demonstration. Record number of verified findings, fixed issues, regression tests and selected prevention measures accurately. Do not equate scanner alerts with exploitable vulnerabilities.

**Gate:** audit report reproducible by reviewer; final app starts and old functionality works; results factual and bounded.

## Integration with flagship
Use the primary scanner only when an authorized immutable Matroid snapshot is eligible under the current source/isolation gates. Give discovered genuine edge cases back to flagship evaluation fixtures as synthetic equivalents without moving sensitive repo data or credentials. Matroid stays a separate project; **no SOC investigation pipeline here**.

Acquisition authorization does not imply safe contents; enforce the flagship's current G3/G4 input restrictions and report scan coverage/partial failures. Never infer an exploitable vulnerability solely from a scanner alert. Hosted triage requires separate explicit consent for the snapshot/data scope; do not move private source or real secrets into prompts, reports or public fixtures. Follow [03](03-DATA-API-AND-WORKFLOW.md) and [04](04-THREAT-MODEL.md).
