# Phase 6 G9 evidence

All required local checks executed. Checkpoints 6A/6B/6C and G9 pass for the declared
Windows/Docker Desktop/Chromium, deterministic-provider scope. No remote workflow,
live hosted model, public deployment or Phase 7 release exercise ran.

| Check | Result | Evidence |
| --- | --- | --- |
| Full browser suite | 19 passed, 0 failed/skipped | `browser-evidence.json`: 11 genuine API/PostgreSQL/browser workflows, three browser/security contracts, five explicitly scripted transport scenarios |
| Final presentation regressions | 5 passed, 0 failed/skipped | `layout-evidence.json`; overlaps full-suite scenarios, not five new independent samples |
| Compiled production preview | 1 passed, 0 failed/skipped | `preview-evidence.json`; actual records, authentication, coverage details, correct Created timestamp label, strict CSP and no console errors |
| Frontend type/build/install | PASS | Strict TypeScript, locked npm ci with install hooks disabled, Vite production build; exact versions/hashes in `frontend-evidence.json` |
| Frontend source/assets/auth/log checks | 10 passed, 0 failed/skipped | `frontend-evidence.json`; known real credentials absent from public changes/bundles/container logs; no storage/dangerous HTML APIs in maintained client source |
| Dependency audit | 0 reported advisories, exit 0 | `dependency-audit.json`, scoped only to web/package.json; not a universal dependency-safety guarantee |
| Full backend regression | 256 passed, 0 failed/skipped | `test-evidence.json`; previous 255 plus exact dashboard-origin API test; Ruff and mypy also pass |
| Scan crash/retry | 25 passed | Five each after claim, output, findings, commit and database disconnect; expected findings/events, stale publication rejection |
| Triage recovery | 5 passed | Claim/output/outcome/commit/database-disconnect experiments; successful scanner state remains independent |
| Actual scanner containment | 31 passed, 0 failed/skipped | `isolation-regression.json` on Windows/Docker Desktop, maintained controlled probes only |
| Actual real scanner checks | 16 passed, 0 failed/skipped | `scanner-regression.json`; positive/clean, malformed output, suppressed config, stale/missing database and unsupported coverage |
| Native NTFS | 10 passed, 0 blocked/skipped | `windows-filesystem-evidence.json`, user administrator rerun |
| Runtime/retention | 32 passed, 0 failed/skipped | `runtime-evidence.json`; every pre-existing row unchanged across 17 tables, local auth, restricted containers and disabled real/hosted admission |
| Frozen quality/policy and Git boundaries | 6 passed | `regression-comparison.json`; unchanged quality/attack outcomes, earlier evidence, scanner/agent/backend code and local instructions; nothing staged |

These counts overlap: the backend suite contains process experiments, and focused browser
checks repeat some full-suite cases. They must not be added into an inflated number of
independent security samples. Scripted UI tests are not presented as genuine provider
failures; existing real PostgreSQL/provider/process regression tests establish the
underlying failure semantics, within their accepted deterministic/mocked-provider scope.

## Genuine browser behavior

Actual local API/PostgreSQL and independent deterministic triage workers supplied:

- Memory-only authentication; valid/invalid token behavior; disconnect/reload clearing;
  browser storage/URL/console checks and no implicit writes on navigation.
- Existing project lookup, two history pages, signed finding pages, exact
  severity/scanner/rule/review filters and counts checked against API-returned records.
- Real succeeded and partial scanner records, explicit incomplete coverage, and
  synthetic diagnostics kept separate from genuine findings.
- Explicit offline investigation with finding/source citations, confidence/advisory
  labeling, insufficient-evidence synthetic abstention and unsupported real vulnerability
  rule-family abstention. No human disposition changes merely because triage succeeds.
- Two browser sessions: initial review revision 0, confirmation required before creation,
  first writer revision 1 plus scoped AI feedback, stale writer 409, displayed current
  server decision, preserved draft and blocked save, explicit reconsideration and revision 2.
  Additional controlled API writes populate a five-entry history page and a second page;
  these test writes affect only the new Phase 6 review record.
- Keyboard navigation/focus and labeled controls at 390x844, desktop layout at 1440x1000,
  no document-level horizontal overflow, empty project and invalid identifier states.
- Default hosted execution denied by the actual API, with no new model key/call/consent.

The accepted Phase 5 controlled real scan has 85 findings; loaded finding metrics show
up to ten, not 85 as a global total. Source snapshots, scanner results and all pre-existing
human reviews remain unchanged. Browser tests intentionally retain new triage/review rows;
they never delete records to make reruns pass.

## Hostile and failure scenarios

Five explicitly scripted browser scenarios test hostile finding descriptions/paths,
Markdown and model output, fabricated/mismatched citations, synthetic secret redaction,
pending/running/failed/unavailable triage, failed scanner states, slow/loading/API retry
and empty filtered pages. Enforcement is inert text rendering, no arbitrary links/images,
fixed authority methods, identity checks, safe errors and bounded fetches, rather than
an LLM refusing an instruction. The fifth case proves background pending-scan refresh
preserves unsaved human notes and keyboard focus without issuing any review write.

Browser/security contract cases additionally exercise actual disallowed/null Origin and
Host responses, a null-origin browser fetch, missing auth, strict CSP/no-store, denial of
private configuration/test-source serving, closed-client rejection, absence of Docker/
shell/hosted/remediation methods, and malformed/oversized response rejection.

Neither arbitrary secret detection nor universal XSS prevention is claimed from a finite
corpus. The code never interprets returned Markdown/HTML, but confidentiality still depends
on upstream minimization and a trusted local browser/host. Private manual visual inspection
captures used controlled records after the credential field was absent; no screenshots
are published or enabled by the test runner.

## Corrected observations

| Initial observation | Final correction/evidence |
| --- | --- |
| Vite replaced Cache-Control with no-cache | Local middleware preserves no-store; dev and preview header tests pass |
| History/filter navigation timeout | Old data and pagination controls could appear briefly under a new request identity; synchronous identity guard plus current-page assertions, followed by passing full/focused tests |
| Synthetic fake rule expected unsupported_rule | Real provider reports insufficient_evidence; test now preserves that result. A separate genuine unsupported family demonstrates abstention without changing agent logic |
| Partial-result assertion counted before load completed | Await visible finding row; required partial state and returned findings both verified |
| Background active-scan reload could remount a review draft | Keep the same finding/review mounted, preserve focus and label stale metadata; new browser regression passes |
| Scan history date column said Started | Displayed persisted creation time relabelled Created; preview checks it explicitly |
| Native symlink creation denied | Administrator rerun provided ten passes; no weakening or skip |
| Probe fixture had Windows CRLF rather than LF | Accept only the two exact known marker encodings, preserve bytes, and stop the guarded validation chain on failed preparation |
| Windows asset verifier used default text encoding/missing HTTP method | Explicit UTF-8 and existing helper's GET contract; final ten asset checks pass |
| Audit invoked from repository root resolved an ancestor manifest | Unrelated read-only result discarded; scoped web audit rerun/saved, no ancestor package/file changed |

Earlier failed reports were superseded by final passing evidence; no prior accepted phase
report or frozen label was rewritten. An existing Starlette/httpx TestClient deprecation
warning remains in backend logs, with no skipped tests or unrelated dependency upgrade.

## Explicit validation limits

Chromium on Windows is the tested browser; Firefox/WebKit/Safari and assistive-technology
studies were not executed. The focused keyboard/responsive checks are not a comprehensive
WCAG certification. Development CSP permits inline styles for HMR; preview does not.
The local Vite toolchain/operator/browser are trusted, not sandboxed against administrators.
No raw source view, project directory picker, global metric aggregation, full text search,
browser deep-link routing or public production hosting is included.

The full frozen scanner corpus was not reacquired; accepted genuine observations were
replayed for agent/quality regressions, with separate actual scanner-container checks.
Two ungraded Kubernetes bindings, unsupported/incomplete categories, deterministic
reasoning limitations and A13 unsupported advisory remediation remain unchanged.
Citations establish identity/location, not semantic support for every recommendation.
Hosted provider quality, billing, availability and retention remain unverified and unauthorized.

The G8 workload rerun is regression output under shared local resources, not a new
capacity/SLO claim. Phase 7 backup/restore, final retention/hardening, complete release
rebuild and any remote deployment remain unimplemented and separately authorized.
