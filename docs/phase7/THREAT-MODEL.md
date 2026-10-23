# Final implementation threat model

Date: 2026-10-23 (America/Los_Angeles). This describes the finished local implementation
and supplements the historical [Phase 0 model](../phase0/04-THREAT-MODEL.md).
It does not authorize public hosting, enterprise tenancy, Phase 8 or Matroid work.

## Assets and actors

Protected assets include private source bytes, snapshot identities, scanner policy/DB
provenance, durable lease ownership, findings, triage evidence, explicit consent, human
revisions, audit history, local credentials and matched backups. Exports and metadata can
also be confidential even when redacted.

An attacker can supply adversarial repository files, names, ignore/config files, scanner
output, model proposals, malformed API inputs and hostile browser content. Acquisition
authorization does not make that data trusted. The local operator/account, administrator,
DB superuser, Docker Desktop, launcher, maintenance scripts and dependency toolchain remain
trusted. Project UUIDs are data scope in a single-operator application, not tenant isolation.
No assurance is claimed against a compromised administrator or browser extension.

## Boundary review

| Boundary / threat | Enforced control | Observed validation |
| --- | --- | --- |
| Browser/CLI to localhost API; token theft, CSRF, rebinding | Bearer, exact Origin/Host, no cookies, loopback publication, request/body deadlines, safe errors/logs | API regressions; actual Chromium auth/origin/host/storage tests |
| Browser rendering; hostile descriptions, Markdown, paths and advice | React text, no HTML interpretation/arbitrary links, restrictive CSP, bounded response parser, no token storage | Actual browser security contracts and explicitly scripted hostile-content cases |
| Local intake to published spool; links, streams, mutation and traversal | Fixed NTFS/local path rules, pinned reads, hardlink/reparse rejection, canonical manifest/digests, exclusive publication, immutable consumer mounts | Ten native NTFS checks; snapshot regression suite; actual read-only container mounts |
| Launcher to Docker; proxy escalation and escape | Separate capability absent from ordinary/triage workers, fixed profiles/images/argv/mounts, no generic command API, no socket in consumers, non-root/no caps/no egress/read-only/resource bounds | 31 actual containment checks plus real PostgreSQL handoff/fencing regressions |
| Target policy poisoning / incomplete detection | Platform rules/config, controlled discovery/suppression, pinned adapters and offline DB, per-scanner coverage and partial outcomes | 16 genuine scanner checks; frozen labelled/adversarial regression |
| Jobs to authoritative DB state; stale or duplicate publication | DB-time lease expiry, increasing generation, token, bounded retries; same-transaction fence for findings/status/audit | Real concurrent processes; 25 scan and five triage crash/retry experiments |
| Model to evidence/tools; injection and cross-snapshot access | Fixed read-only schemas, server-side finding/scan/snapshot scope, byte/call/time/cost limits, citation checks, abstention | Deterministic/mocked-provider adversarial cases and process regressions |
| Source to hosted provider; disclosure or consent replay | Hosted deny default, scoped consent checked per send, confidentiality minimization, synthetic-secret tests; no live hosted test | Existing consent/retry tests and browser absence of hosted execution |
| AI to human decision; false authority / lost update | Advisory labeling; explicit review confirmation; expected revision; atomic append-only revision/audit | Actual two-session browser 409 conflict, revision/history/feedback and DB atomicity tests |
| Maintenance to filesystem; unsafe cleanup | Dry-run default, registered references retained, seven-day orphan grace, whole-tree validation, pinned NTFS deletion / relative POSIX deletion | Native hardlink/junction/outside-file preservation tests; actual orphan reclamation on disposable NTFS spool |
| Backup/restore to DB and source; mismatched or malicious recovery | Private ACL, publisher + DB write exclusion, bounded custom dump, trusted manifest digest, complete inventory verification, exact disposable targets, atomic DB restore | 18 table fingerprints, matched snapshots, corruption/missing/mismatch rejection, real pg_restore interruption/rollback/retry |
| Dependency/build/CI boundary; substituted artifacts or secret exposure | Frozen runtime/npm locks, hashed isolated build constraints, pinned images/actions, manual trusted-branch workflows, minimal permissions, no target scripts | Uncached clean build, matching web assets, public advisory and local provenance audit; no remote Actions run |

The maintenance lock serializes platform writers; it is not an OS administrator boundary.
PostgreSQL SHARE locks prevent ordinary data writes during capture while allowing dump
reads. Lock acquisition can fail safely under contention. Application availability may
briefly degrade during maintenance; no zero-downtime or production SLO is claimed.
See [PostgreSQL lock semantics](https://www.postgresql.org/docs/17/explicit-locking.html).

## Confidential data lifecycle

| Data | Policy |
| --- | --- |
| Raw acquired source | Private spool, read-only consumers; default 128 MiB / 32 publications and per-snapshot budgets. Admission normally expires after 24 hours, maximum seven days. Every registered source remains retained while history exists. No hard deletion-deadline compliance claim. |
| Unregistered publications | Preserve through the seven-day maximum registration window; explicit reference-checked cleanup only after eligibility. |
| Unpublished staging | Existing one-hour cleanup contract with hardened bounded deletion. Unexpected links, ownership or substitution fail closed. |
| Scanner stdout/stderr and workspace | Bounded process buffers and disposable container storage; normalize/redact before persistence. Fixed-label orphan reconciliation and actual termination tests. No durable raw-output archive. |
| JSON/SARIF | Sanitized, source-verified, private local exports; 4 MiB each and aggregate 64 files / 64 MiB. Preserve existing exports; unknown or interrupted artifacts require inspection. |
| Triage prompts/trace | Bounded sanitized traces; no live hosted calls. Original source may contain unrecognized secrets, so heuristic redaction is not a universal guarantee. |
| DB audit/review/attempt history | Retained; no new DB row deletion. History is append-only through application contracts, not cryptographically tamper-proof against DB administrators. |
| Matched backups | Private `.local/backups/phase7/`, ignored and excluded from Docker/review artifacts. At most three bundles, 384 MiB payload each, 64 MiB dump, 100,000 rows/table. Partial bundles consume quota; never auto-pruned. |
| Credentials | Separate ignored local configuration, memory-only browser bearer, generated private sandbox secrets. No credential values in published reports or backup configuration. Embedded source secrets can still exist inside confidential backups. |

## Residual risks and interpretation

No known unaddressed high-severity defect was established within the intended trust model
after the reviewed fixes. This is a bounded local review, not certification.

- Static rules miss classes of weakness and produce false positives. Completed execution
  is distinct from complete vulnerability coverage. Stale/missing DB coverage is not clean.
- Containers share infrastructure; local Docker enforcement tests do not prove immunity
  to kernel exploits. Revalidate the host/boundary after relevant platform changes.
- A13 still permits semantically unsupported advisory remediation with valid citations.
  The agent cannot execute it or set a human disposition. Advice requires human judgment.
- Two frozen Kubernetes annotation bindings remain ungraded. The deterministic provider
  supports limited rule families; hosted quality and availability remain unverified.
- Backup digests require a trusted separately retained receipt. Backups are not signed or
  application-encrypted; filesystem encryption and secure off-host recovery are operator
  concerns, and external backup transmission was not performed.
- A partially copied restore spool is preserved and refused if not exactly matching. A
  fresh disposable instance is the safe next attempt. No automatic destructive repair.
- Extended Windows namespaces, network volumes and some long/ambiguous names are unsupported;
  operations reject them. Firefox/WebKit, comprehensive WCAG and public deployment are untested.
- Known-advisory checks do not exhaustively audit every transitive package inside scanner
  images. Hash pinning establishes identity, not publisher trust or absence of malicious code.

Details, severity and mitigations are in [FINDINGS.md](FINDINGS.md).
