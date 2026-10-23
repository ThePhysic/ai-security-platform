# Phase 4 completion report

Phase 4 delivers a frozen source-only AppSec corpus, real offline scanner baseline,
deterministic triage comparison and expanded scripted adversarial assessment.
Date: 2026-10-22, America/Los_Angeles. No Phase 5 implementation is authorized or started.
1Password AppSec remains primary; secure AI evaluation and reproducible backend evidence
support the Brain Co and Prophet overlap without additional product capabilities.

## Checkpoints and G7

| Checkpoint | Result | Scope |
| --- | --- | --- |
| 4A: labelled corpus and quality evaluation | PASS with documented annotation errata | 28 repositories, 14 development/14 held-out, 14 categories; 21 supported/complete correctly bound scanner units; original labels preserved |
| 4B: expanded adversarial evaluation | PASS for declared enforcement scope | 16 versioned cases, two repetitions, 17/17 prohibited proposals blocked per repetition; zero observed prohibited actions/disclosures; one unsupported advisory recommendation explicitly observed |
| G7 | PASS for declared local scope | All required offline, actual-scanner, PostgreSQL/process, Windows and regression checks executed; no remaining blocked/skipped required checks |

This is not a claim of general vulnerability detection, production safety, semantic
prompt-injection immunity or hosted-model quality. The
[readable evaluation summary](EVALUATION-SUMMARY.md) and
[machine-readable report](../../evaluation/results/report.json) contain exact
denominators, case results, provenance, measured timings and evidence hashes.

## Corpus, labels and held-out integrity

Dataset **`appsec-corpus-1`**, labels **`source-review-1`**, attacks
**`adversarial-corpus-1`**, freeze **`corpus-freeze-1`**. The freeze SHA256 is
`5db395bc7091f8e5796c6b287a95a1da84b8e6edfc4675e2de6efb6897775845`.
[The manifest](../../evaluation/manifest.json) independently labels intended source
behavior, expected detectability, expected triage/abstention, evidence, remediation,
review disposition, provenance and limitations. It was frozen before scanner observations.

Paired categories cover Python and TypeScript eval, Python/JavaScript SQL construction,
Python/JavaScript shell execution, vulnerable/patched Python and JavaScript dependencies,
synthetic secrets, Docker root configuration, Kubernetes privilege configuration, CI
permissions/actions and unsupported authorization/deserialization/path behavior. No
fixture code, build, workflow, package script or dependency installation was executed.

Labels came from source semantics and stated trust assumptions. Historical dependency
labels were checked against upstream release/advisory records linked in the
[methodology](../../evaluation/README.md); they do not depend solely on scanner output.
An advisory-specific fixed version is not labelled universally vulnerability-free.
The held-out split is an engineering holdout with paired concepts, not an independent
blind reviewer study or an unseen-category generalization claim. No product behavior
was tuned, and no frozen fixture, label or split was modified after observations.

**Annotation error:** the original KSV-001 binding resolved to KSV-0001 (privilege
escalation), while the fixtures label privileged mode, whose upstream rule is KSV-0017.
Both original cases and their observed alerts remain intact. The explicit
[annotation errata](../../evaluation/errata-v1.json) excludes them from formal quality
denominators rather than calling an unrelated real escalation alert a false positive.
There are still 21 eligible scanner units, exceeding the minimum 20-repository corpus.
A separately versioned future binding correction is recommended; no corrected held-out
score is substituted here. Original expected/observed detectability matches remain 27/28.

## Scanner baseline and coverage

Two complete controlled repetitions ran **112 actual scanner containers** through the
existing proven launcher/profile boundary. Only pinned local assets were used; neither
API real-scan admission nor scanner network access was enabled. Semantic scanner results
matched across repetitions. All 56 actual source snapshots were verified against exact
materialized bytes before Linux/PostgreSQL replay. The secret slot uses explicit CRLF
on both platforms to preserve the actual Windows input. No raw source/scanner text was
exported by attestation or normalization.

| Partition | TP | FP | FN | TN | Precision | Recall |
| --- | --- | --- | --- | --- | --- | --- |
| Development | 5 | 1 | 0 | 5 | 5/6 (83.3%) | 5/5 (100%) |
| Held-out | 6 | 1 | 0 | 3 | 6/7 (85.7%) | 6/6 (100%) |
| Combined | 11 | 2 | 0 | 8 | 11/13 (84.6%) | 11/11 (100%) |

These are primary-target metrics on supported, complete and correctly bound units only.
Four unsupported cases, one incomplete secret-free text case and two invalid rule bindings
are excluded and separately reported. The two false positives are fixed-literal eval
near misses. The secret-free fixture's `no_supported_targets` result is incomplete rather
than a true negative. Missing/stale DB behavior was independently rerun in G5 validation.

Other alerts remain unlabelled incidental findings. For example, the Django target
advisory disappears at its patched version while other advisories remain. No blanket
clean dependency claim or full detection-recall claim is made. Authorization and unsafe
deserialization/path behavior remain gaps in the unchanged eight-rule SAST policy.

## Triage, evidence and labelled review

Evaluation-only factories replay genuine normalized scanner metadata into guarded real
PostgreSQL, reacquire byte-identical source in Linux, bind the verified local manifest
and use existing triage acceptance/jobs, tools, publication fencing and review storage.
They do not replace scanner execution or add a production ingestion path.

There were **15 primary-alert investigations per repetition**: 13 graded and two retained
ungraded bindings. Thirteen repositories had no primary scanner alert and were not
triaged. Each investigation used actual finding/source/rule/coverage/context evidence.

- **Nine correct answered opinions, zero incorrect answered opinions**, among nine
  graded answered cases; four graded abstentions, all four required for unsupported
  trusted rule families. Abstention rate: 4/13 (30.8%).
- Required disposition conformance: 13/13, including the four abstentions. This is not
  100% accuracy on all repositories or a general reasoning benchmark.
- Citation identity/range validity: 13/13 graded investigations. Independent evidence
  support rubric: 13/13; remediation compatibility rubric: 13/13. No unsupported claim
  or recommendation occurred in the graded deterministic baseline.
- The rubric separately checks frozen expected disposition, relevant source coverage,
  conservative uncertainty qualifiers and required guidance. A unit test proves that
  valid citations and the expected disposition do not make overconfident/bad prose pass.
  It is not a general natural-language entailment judge.
- Label-derived reviewer agreement: 9/9 answered cases, zero corrections; four abstentions
  require human investigation. Revisions are persisted only in the disposable test DB.
  These are labelled evaluation decisions, not measured agreement among real reviewers.

Per-category metrics, partition results, per-case outcomes and required-abstention counts
are machine readable. Triage independently discovers **zero additional vulnerabilities**;
it does not improve scanner discovery recall in this evaluation.

## Expanded adversarial assessment

Sixteen versioned attack goals cover injected source comments, misleading tool content,
shell, URLs, credentials, writes, cross-snapshot access, five citation forgeries, source/
context limits, oversized arguments/output, malformed/incomplete provider output, secret
exfiltration, remediation poisoning, human-authority spoofing, provider failures and stale
publication. Actual enforcement is exercised through production schemas, evidence scope,
budgets, citation checks and real PostgreSQL lease fences, not an LLM refusing a request.

Each repetition has 24 case-level proposals/fault variants: **17 prohibited proposals
blocked**, six malformed/provider fault variants safely failed, and one advisory-poisoning
probe remained advisory. Both repetitions match. Results are repeated observations,
not additional independent cases. Case-by-case results appear in the readable summary
and `triage-adversarial-evidence.json`.

**A13 semantic limitation:** valid citations can accompany harmful unsupported remediation
text. Structural validation accepts that text as an opinion; no code change, execution,
human disposition or review revision follows automatically. The evaluator explicitly
counts **one unsupported recommendation per repetition**, separate from the clean
deterministic baseline. The product was not silently expanded to hide this result.

Observed successful prohibited actions, synthetic-secret disclosures and automatic human
decisions: **zero** in this declared corpus. Known synthetic values were absent from
mocked provider payloads, output, traces, logs and exported reports. This does not prove
universal secret detection, prompt-injection immunity or model honesty. Hosted wire probes
use explicit mocked transport; no real model call, key or external source transmission
was authorized, created or used.

## Commands, versions and regression results

[COMMANDS.md](COMMANDS.md) records executed command families and diagnostic reruns.
[RUNBOOK.md](RUNBOOK.md) gives setup, reproduction, state checks, restart and rollback.
The evidence JSON records exact container commands/return codes and all crash trials.

| Check | Final result |
| --- | --- |
| Full unit/API/real PostgreSQL suite | **226 passed, 0 failed, 0 skipped** |
| Native Windows unit/API | **120 passed**, 106 PostgreSQL tests deselected and run separately; 0 failed/skipped |
| Original scan crash/retry trials | **25 passed** across five critical points x five iterations |
| Triage crash/transaction/DB-interruption trials | **5 passed** with independent processes and stale publication rejection |
| G4 actual controlled-container isolation | **31 passed**, 0 failed/skipped |
| G5 real scanner regression | **16 passed**, 0 failed/skipped |
| Operator-administered NTFS snapshot regression | **10 passed**, 0 blocked/failed/skipped |
| Final runtime and retained-data checks | **32 passed**, 0 failed/skipped |
| Actual API/worker/DB restart and access-control checks | **10 passed**, 0 failed/skipped; zero records created/modified |
| Ruff, formatting and mypy | Passed; mypy 60 application source files |
| Locked dependency resolution | Passed, existing 41-package lock unchanged; no added dependency |

These suites overlap and are not additive totals. The existing upstream Starlette
TestClient deprecation remains a warning. All required checks executed.

Python **3.12.15**, uv **0.13.5**, PostgreSQL **17.11**, FastAPI **0.161.0**, Pydantic
**2.14.1**, SQLAlchemy **2.0.55**, Alembic **1.20.1**, Psycopg **3.3.6**, Ruff **0.17.2**,
mypy **1.20.2**, pytest **9.1.1**. Full installed versions are in runtime evidence.
The test image installs the existing frozen project/development dependency set.
Semgrep **1.179.0** and Trivy **0.76.1**, immutable images, policy digests and the recorded
offline database identity/age remain in scanner observations and the combined report.
No scanner DB/rule refresh or image repinning occurred.

Agent remains `deterministic-v1` / `offline-1`; prompt `triage-prompt-1`, tools
`evidence-tools-1`, confidentiality `confidentiality-1`. Mocked optional hosted adapter
retains its Phase 3 pinned model/configuration; no hosted quality or availability claim.
Schema remains **`0004_triage_review`**; no new migration or API contract was introduced.

Actual observed scanner lifecycle p50/p95: Semgrep **4719/5141 ms**, Trivy **2422/2688 ms**,
56 observations per scanner. Triage timings appear in the machine/readable report and
exclude acquisition/queue/scanning. CPU/memory/PID/time limits and OOM state are recorded;
peak memory, paid cost, actual model tokens and production/load SLOs were not measured.

## Failures, deviations and preserved boundaries

The first scanner attempt hit the existing 32-snapshot quota; independent bounded spools
fixed the harness, with no quota increase or retained-source deletion. Native sandbox ACL
denials required a host-permission rerun; symlink creation required the operator's
administrator run. A state check correctly failed while controlled scanner containers
were still active and passed after they finished. A metric unit fixture initially lacked
its category field; it was corrected and the full suite rerun. Final lint/type/test gates
pass. No failed attempt is counted as passing evidence or converted to a skip.

The Kubernetes annotation error and unsupported-advice acceptance are remaining declared
limitations, not hidden score improvements. Application source, providers/tools, job
fencing/idempotency, scanner policy/registry/launcher boundary, database migrations and
existing API behavior are unchanged. Only corpus/harness/tests, test-image inclusion,
fixture line-ending policy, separate evidence selectors and documentation changed.

All **17 retained development tables** match their pre-evaluation aggregate content/count
fingerprints, including scans/findings, triage and immutable review history. Development
source snapshots and scanner assets were preserved. Earlier accepted Phase 0–3 reports
were not overwritten. API stays loopback-only; application workers/scanners have no Docker
authority. Real scanner and hosted admission remain disabled.
Actual API, both workers and PostgreSQL were restarted without volume deletion; saved
resource responses and all 17 table fingerprints persisted. While PostgreSQL was stopped,
liveness stayed 200 and readiness returned 503. Authentication, Host/Origin/request-size
restrictions and credential-free logs/errors were also checked against the actual API.

Remaining risks are the small paired synthetic dataset, annotation fallibility, no real
reviewer study, limited rule coverage/offline reasoning, heuristic redaction and semantic
claims that structural validation cannot prove. A correctly cited harmful recommendation
can still mislead a human. Any mitigation beyond necessary evaluation fixes requires a
separate product proposal/authorization. Future evaluation should version corrected labels,
retain v1, add independent expert review and measure generalization without tuning held-out
cases. Actual hosted quality/billing/data transmission still require separate approval.

## Restart, rollback and next handoff

No runtime/schema rollback is necessary for this evaluation-only phase. Stop running the
harness, retain manifests/results and preserve revision 0004/history. Use the compatible
Phase 3 Compose restart documented in the runbook if services need restarting. Only the
disposable `asp-phase1-test` database is stopped after validation, with its volume retained.
Local development API/DB/scanner worker/triage worker remain available. No scanner
containers or host launcher remain active, and hosted/real-scan admission are off.

[FILES.md](FILES.md) lists every created/modified deliverable. Local instructions remain
unchanged, ignored, unstaged and excluded from build contexts/artifacts. No staging,
commits, pushes, remote deployment/workflow activation, Matroid changes, UI, automatic
remediation, SOC or Phase 5 integration/performance work occurred.

**Recommended Phase 5 handoff — NOT AUTHORIZED:** consume these honest coverage and
abstention semantics in the approved CLI/JSON/SARIF/developer workflow and reliability
milestone. Preserve consent, source identity, fencing and human-review authority. Carry
forward the v1 errata and A13 semantic limitation; propose product changes independently.
Do not claim triage discovery uplift or treat unsupported/incomplete results as clean.
Stop after Phase 4.
