# Phase 6 completion report

Date: **2026-10-22, America/Los_Angeles**. The security reporting dashboard implements
Phase 6 only. 1Password AppSec/investigation/review remains primary; Brain Co secure AI
workflows and Prophet reliable history/integration remain supporting overlap.

| Checkpoint/gate | Result | Scope |
| --- | --- | --- |
| 6A: foundation and scanner workflow | PASS | Local React/TypeScript/Vite, authenticated project/history/scan/finding views, coverage and synthetic distinctions |
| 6B: triage and human review | PASS | Actual deterministic worker investigation/abstention, scoped citations, advisory output, confirmed revision writes, conflict/history/feedback |
| 6C: reporting/usability | PASS | Explicit page-scoped persisted metrics, responsive/keyboard controls, loading/empty/error states and final visual review |
| G9 | PASS locally | Windows/Docker Desktop/Chromium and deterministic/offline scope; no required test silently skipped |

No Phase 7 implementation, staging, commits, pushes, workflow activation or deployment
occurred. No hosted model, paid call, provider key, source transmission, remediation,
additional scanner, SOC feature or Matroid change was introduced.

## Delivered workflow and architecture

The dashboard is available only at **http://127.0.0.1:18082** and directly calls the
existing loopback API at port 18081. Operator bearer credentials remain only in page
memory, are cleared from the input after connection, and are cleared on explicit
disconnect/reload. No credential is embedded in source/bundles, URLs, images or browser
storage. Exact Host/Origin, safe errors, bounded fetches, no-store, no-referrer, CSP and
inert JSX rendering protect the browser boundary.

For the retained controlled demonstration, enter project UUID
`b4ed7386-d321-4a11-b5d5-29f77f46db0c`. Navigate signed history/findings pages, inspect independent
scanner outcomes/provenance/coverage, filter severity/scanner/rule/review, and select a
finding's server-scoped snapshot reference. Real and synthetic results are conspicuously
separate. Succeeded, partial, failed and pending states retain their backend meaning;
missing coverage never becomes a clean result.

An operator explicitly requests deterministic offline triage. The UI shows provider,
status, explanation, uncalibrated confidence, abstention and validated citations, with
remediation marked advisory. It never starts hosted reasoning or automatically makes a
human decision. Notes/dispositions/feedback require explicit confirmation and expected
revision. Stale saves display the current server review, retain the draft and block
writes until explicit reconsideration. Immutable history uses bounded natural pagination.

Metrics are limited to the loaded history page (three scans), loaded filtered findings
page (ten findings), or selected finding's review/triage. Persisted timestamps are shown;
there are no global totals, composite risk score, invented trends or clean-as-secure claim.

See [architecture, exact versions and API mapping](ARCHITECTURE-AND-CONTRACTS.md),
[complete file inventory](FILES.md), [commands](COMMANDS.md), [validation matrix](VALIDATION.md)
and [start/restart/rollback](RUNBOOK.md).

## Dependencies and backend compatibility

React/React DOM **19.3.1**, TypeScript **7.0.2**, Vite **8.3.5**, Playwright **1.64.1**,
Chromium **156.0.8078.4** (revision 1248), Node **24.22.1**, npm **11.19.1**.
React type packages are 19.3.0; Node types are 26.6.5. The exact npm lock/integrities,
locked reinstall, build hashes and ten frontend checks are in
[frontend-evidence.json](frontend-evidence.json). The web audit reports zero advisories
at validation time; this is not a universal dependency-security guarantee.

No UI/component/chart/router/agent framework or infrastructure was added. Python/uv,
PostgreSQL 17.11, scanner images/policies/DB and runtime dependencies remain unchanged;
full installed versions are in [runtime evidence](runtime-evidence.json).

There are **no new HTTP endpoints, response changes, backend source changes or migrations**.
Only Compose adds the exact frontend origin; existing API behavior, Host rules and
single-user bearer authorization remain. Explicit UUID identification uses the existing
project API instead of introducing a listing/aggregation endpoint. Migration stays
**0004_triage_review**. No retained database downgrade/reset occurred.

## Validation outcomes

| Executed group | Pass | Fail | Skip/blocked |
| --- | --- | --- | --- |
| Full actual Chromium suite, live and scripted modes separated | 19 | 0 | 0 |
| Final affected layout/security browser checks | 5 | 0 | 0 |
| Compiled-preview actual API/browser integration | 1 | 0 | 0 |
| Full earlier-phase backend suite plus exact-origin test | 256 | 0 | 0 |
| Native Windows NTFS | 10 | 0 | 0 |
| Actual Docker scanner containment | 31 | 0 | 0 |
| Actual Semgrep/Trivy regression | 16 | 0 | 0 |
| Frontend source/build/auth/log checks | 10 | 0 | 0 |
| Runtime/data preservation | 32 | 0 | 0 |
| Frozen outcomes/Git/instruction boundaries | 6 | 0 | 0 |

Ruff, mypy, strict TypeScript, locked npm reinstall, production build and scoped audit pass.
Counts overlap: focused browser cases repeat full-suite scenarios, and the backend suite
contains the crash/recovery experiments. They are not independent security sample totals.

The full browser suite contains 11 genuine API/PostgreSQL/browser workflows, three
browser/security contract cases, and five explicitly scripted transport scenarios. It
proves valid/invalid authentication, empty/partial/complete data, actual signed pagination
and filters, record-derived metrics, explicit deterministic multi-step investigation,
supported reasoning and synthetic/unsupported-family abstention, no AI-to-human mutation,
confirmation before revision-0 creation, two-session stale conflict/explicit reconsideration,
scoped feedback and five-entry history pagination. Keyboard and 390x844/1440x1000 layouts
were exercised. Production preview uses actual records and no inline-script/eval/style
allowance, with zero observed console errors in its case.

Hostile descriptions/paths/Markdown/agent output remain inert; fabricated citations are
rejected for display as matching evidence. Synthetic secret metadata is redacted;
untrusted error bodies are not displayed. Known local credentials are absent from built
assets, changed files, container logs, console/URL/browser storage and published evidence.
No shell/Docker/write/hosted/consent method exists on the frontend client. Actual API
hosted requests are denied under disabled admission. No source excerpts are loaded.

Earlier-phase regressions reran **25 scan crash/retry experiments** (five each at claim,
output, findings, commit and DB disconnect) and **five triage recovery experiments**.
They preserve lease/fencing/idempotency, one winning result/event, provider-failure
independence, optimistic review/audit semantics, snapshots, auth, bounded exports,
disposable migrations and indexed-history/workload behavior. Scanner container tests
again verify actual resource/egress/privilege restrictions, termination/orphans, policy
poisoning and offline coverage. The administrator NTFS rerun supplied ten passes.

All original development rows are byte-equivalent by private row-hash comparison across
17 tables. There are still 13 source snapshots, 28 scans and 1,825 findings. Controlled
UI validation added one empty project, 18 succeeded triage runs and four newly created
review records with 28 immutable revisions; the original review and its two revisions
remain unchanged. New records intentionally remain retained. No source spool/policy/
scanner/evaluation data was reset.

Frozen quality/category and adversarial results match accepted earlier results; timing
can differ. Accepted evidence/labels/methods/rules are unchanged. G8 workload rerun output
is regression evidence under shared resources, not a new production-capacity claim.

## Limits, corrected failures and operations

Initial validation failures and fixes are recorded in [VALIDATION.md](VALIDATION.md),
including Vite cache-header override, stale page-control ownership, asynchronous test
assertion, correct abstention reason, timestamp label and native elevation. Final affected
checks passed; no security control or frozen label was weakened to improve results.

Known limits:

- Chromium/Windows is tested; Firefox/WebKit/Safari, full screen-reader studies and
  comprehensive WCAG compliance are unverified. Core keyboard/labels/focus and two
  responsive sizes passed; this is not accessibility certification.
- The local operator/browser/toolchain are trusted. Logical memory clearing, exact local
  origins and known-format redaction do not protect against compromised administrators,
  extensions or every possible secret/encoding. Metadata can still be confidential.
- Development CSP allows inline styles for Vite HMR; compiled preview does not. This
  remains local development/preview, without a production deployment claim.
- Project UUID entry, page-scoped metrics, metadata/citations and selected-finding triage
  are intentional limits. No raw-source browser, global aggregate, composite risk,
  project-directory UI, deep-link persistence or automatic scan/triage/remediation exists.
- Deterministic triage supports limited rule families. Two Kubernetes annotation bindings
  remain ungraded, unsupported/incomplete cases remain visible, and A13 unsupported
  advisory remediation remains unfixed. Valid citations do not prove semantic advice.
- Hosted provider quality/billing/retention and remote Actions were not tested or enabled.
  The full frozen scanner corpus acquisition was not repeated; accepted genuine
  observations were replayed for quality tests alongside separate actual scanner checks.

No architectural/scope deviation was needed. Using the explicitly permitted project-UUID
lookup avoids API expansion; adding one exact development origin is the only backend
configuration adjustment. Source, job fencing, scanner authority and human-history
boundaries are preserved. Prior reports, local instructions and staging remain untouched.

Development services and the loopback UI remain available with real and hosted admission
disabled; no host launcher/scanner orphan remains. The disposable test database is stopped
with its volume retained. The [runbook](RUNBOOK.md) explains safe restart and application-
only rollback: stop UI, keep CLI/API/data, and optionally remove its exact Origin through
a reviewed configuration change. No schema downgrade or data deletion is required.

Recommended Phase 7 handoff, **not authorized or implemented**: review G9 evidence and
the complete threat model, then perform only separately approved final hardening,
retention, matching DB/spool backup/restore and release/rebuild validation. Carry forward
the browser/local-host limits, G7 annotation/advice limits and bounded G8 measurements.
Do not introduce public hosting, live paid models, new scanners, automatic remediation,
SOC or Matroid work without their own authorization.
