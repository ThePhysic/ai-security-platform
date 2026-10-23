# Phase 3 completion report

Phase 3 implements bounded read-only security investigation and revision-checked human
review for the local AppSec platform. 1Password remains the primary role focus; secure
AI boundaries and durable integration/recovery provide the Brain Co/Prophet overlap.
Date: 2026-10-22, America/Los_Angeles.

## Checkpoints and G6

| Checkpoint/gate | Status | Evidence |
| --- | --- | --- |
| 3A: scoped evidence, deterministic triage and human review | PASS | Genuine finding/source/rule/coverage/context workflow, source-sensitive decisions, abstention, citations, atomic immutable history and process review races |
| 3B: optional hosted adapter and agent security | PASS within authorized mocked-transport scope | Complete structured tool loop through hosted wire format, default denial, scoped consent/revocation, retry budgets, injection/tool/citation/disclosure checks; zero live hosted calls |
| G6 | PASS for declared local scope | [Complete PostgreSQL regression evidence](test-evidence.json), [live local pipeline](live-evidence.json), [runtime restrictions](runtime-evidence.json) |

Live hosted access, account eligibility, service availability, provider retention and
model quality were not tested: actual external calls were explicitly unauthorized.
That is a disclosed capability limit, not a mock substitution for the required real
PostgreSQL/process gates. All required offline/mocked-provider and local integration
checks executed. No required check is silently skipped.

## Delivered implementation

The [architecture and API/schema contract](ARCHITECTURE-AND-CONTRACTS.md) describes
all modules, budgets, routes, consent and lock order. Five strict read-only tools derive
their authority from the triage's exact finding/scan/snapshot. Source retrieval verifies
the immutable manifest and line ranges; models cannot choose roots/paths, credentials,
commands, URLs, scanners or plugins. A frozen catalog exposes actual first-party rule
definitions and provenance from the unchanged trusted scanner policy. Rule mismatches
are explicit rather than silently using new policy to explain old findings.

The explicit loop supports structured `needs_review`, `likely_false_positive` or
`abstain` opinions with confidence, remediation guidance and validated citations.
An acceptance scenario needs both finding and source inspection: variable eval, fixed
literal eval and unrelated source yield different outcomes. Each non-abstaining result
requires both evidence kinds. Deterministic output is repeatable; its heuristic confidence
is not a calibrated exploit probability. Source-unavailable cases abstain without
substituting another snapshot. AI opinions never become human decisions automatically.

The optional OpenAI Responses adapter has a fixed endpoint, pinned model, strict fixed
functions, structured final JSON, bounded response size/time and explicit error classes.
It exposes no built-in shell/network/search/plugin tools. Consent binds operation,
finding/scan/snapshot/manifest, provider/prompt/tool/catalog/confidentiality/budget
configuration and data categories; every send/retry rechecks and reserves under current
ownership. Revocation prevents later reservations. The default Compose environment
contains no hosted key. Provider credentials would belong only to the trusted triage
provider process after separate approval; no credential was created or transmitted.

Source/secret confidentiality is enforced before model input. Secret locations return
redacted markers; other excerpts receive bounded heuristic redaction. Known synthetic
secrets were absent from provider payloads, output, traces, notes, errors, logs and
generated evidence. Only safe tool names/counts/hashes persist in traces. Notes/output
are bounded plain text with HTML/Markdown/control handling. This is not complete DLP.

Human dispositions preserve Phase 0 vocabulary. First writes require expected revision
0; concurrent/stale changes receive 409. Current review, immutable revision and audit
commit atomically. PostgreSQL rejects UPDATE/DELETE of revision history. Feedback is
separate from model output and must identify the same finding's completed assessment.
No React interface, automatic patch or pull-request capability was added.

## Durable execution, schema and retained data

Forward revision **`0004_triage_review`** extends revision 0003. Six new tables store
triage requests, consent, validated outcomes, send reservations and current/immutable
review history. Existing job attempts serve triage attempts; job/idempotency targets
are exclusive scan-or-triage. Composite FKs enforce finding/scan/snapshot/manifest scope.
Database uniqueness enforces idempotency and review revision identity. JSON and text
bounds supplement application validation. Migration DDL is frozen independently of
future application metadata; destructive reversal is guarded to the disposable DB only.

Triage workers use the existing SKIP LOCKED/generation/token/DB-time machinery and
independent bounded heartbeats. Claim, completion, failure, recovery and send reservations
have current-ownership fences. Outcomes/status/attempt/completion audit publish atomically;
stale/expired attempts publish nothing. Scanner workers do not claim triage jobs.
Provider interruption, rate limiting, invalid output or retry exhaustion cannot rewrite
a completed scan. A blocked provider watchdog exits the worker before another job is
accepted; operator restart enables recovery without accumulating hung calls.

[Migration evidence](migration-evidence.json) records a **437,643-byte private backup**.
Before/after counts remained: projects 10, snapshots 10, scans 23, audit 153, scanner
runs 46, jobs 46, attempts 55, findings 1566, idempotency records 23, scanner invocations
47, launcher capabilities 9. Row-content comparison digests for scans, findings,
snapshots, scanner runs and audit events also matched. Existing spool, images/assets,
scanner policy and prior accepted evidence were preserved. No development reset,
destructive downgrade or full source snapshot export occurred.

## Executed validation

| Suite | Result |
| --- | --- |
| Full unit/API/real PostgreSQL suite | **222 passed, 0 failed, 0 skipped** |
| Native Windows unit/API | **117 passed**, 105 PostgreSQL cases deliberately deselected and run separately; 0 failed/skipped |
| Original scanner crash/retry trials | **25 passed**, all five critical points x five iterations |
| New triage crash/transaction trials | **5 passed**: after claim, after output, during outcome transaction, after commit, DB connection interruption |
| G4 actual controlled-container rerun | **31 passed**, 0 failed/skipped; [separate Phase 3 artifact](isolation-regression.json) |
| G5 real scanner rerun | **16 passed**, 0 failed/skipped; [separate Phase 3 artifact](scanner-regression.json) |
| Native NTFS safety rerun | **10 passed**, zero blocked/skipped after operator administrator run |
| Actual API/DB/worker restart pipeline | **10 passed**, 0 failed/skipped; zero hosted calls |
| Final runtime/security state | **31 passed**, 0 failed/skipped |
| Reproducibility, lint and types | Locked install/resolution, Ruff/format clean, mypy **60 source files** |

Suites overlap and are not additive totals. [Commands](COMMANDS.md) and harnesses make
them reproducible. The only remaining warning is the existing upstream Starlette
TestClient deprecation. A native test case initially exceeded Windows fixture-name
limits; compact IDs corrected the harness while retaining the same oversized input.
Initial symlink privilege blockage was resolved by the operator's administrator run.
No safeguard was weakened and no required case was converted to a skip.

Actual PostgreSQL tests cover competing triage workers, identical/conflicting/lost-
response acceptance, stale heartbeat/result/audit rejection, atomic review rollback,
two-process review conflicts, retry exhaustion and stalled-provider process recovery.
Each of the five crash trials ended with one outcome and one completion event,
rejected stale publication and an unchanged successful scan. The full 25 prior scan
experiments also reran. Hosted reservations retain their allowance across retry;
revoked/replayed/changed-operation consent grants no new send permission.

Security cases include source-comment/tool-output injection, unrecognized commands/
URL/credential tools, cross-project finding access, unsafe ranges, malformed/oversized
arguments/output, fabricated or modified snapshot/path/line citations, tool/context/
token/time/cost limits and incomplete/refused provider output. No authorized escape or
known synthetic disclosure was observed in these initial tests; this is not Phase 4's
expanded quality/adversarial benchmark.

The live pipeline used retained genuine controlled Semgrep/Trivy findings. It persisted
an evidence-backed `needs_review` opinion, a secret-finding abstention, explicit human
feedback and a 200/409 concurrent review result; actual API/worker/triage-worker/DB
restarts preserved them. Exact scan/scanner/finding content digests remained unchanged.
Validation review notes are clearly labelled controlled validation, not a human verdict.

G4/G5 retained the same image/engine/rule/DB identities: Semgrep positive 8, Trivy
positive 78; both clean fixture results zero within declared coverage. Network/root/source
write denial, no daemon/credentials, limits, termination/orphan cleanup, poisoning,
malformed output and missing/stale DB behavior passed again. The host launcher was not
enabled for public scanning, and accepted Phase 2B evidence was not overwritten.

## Versions and operational boundaries

Python **3.12.15**, uv **0.13.5**, FastAPI **0.161.0**, Pydantic **2.14.1**,
SQLAlchemy **2.0.55**, Alembic **1.20.1**, Psycopg **3.3.6**, PostgreSQL **17.11**;
Ruff **0.17.2**, mypy **1.20.2**, pytest **9.1.1**. Existing `uv.lock` is unchanged;
no runtime library, agent framework, vector DB or new infrastructure product was added.
[Runtime evidence](runtime-evidence.json) lists every installed distribution/version.
Semgrep **1.179.0** and Trivy **0.76.1** retain their original pinned scanner registry.

Optional hosted configuration pins **gpt-5.4-mini-2026-03-17** and version-1 prompt,
tool and confidentiality policy. Official references used:
[Responses migration](https://developers.openai.com/api/docs/guides/migrate-to-responses),
[Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs),
[model snapshot/pricing](https://developers.openai.com/api/docs/models/gpt-5.4-mini).
They support adapter shape/model selection, not a claim of executed hosted behavior.

## Limitations, rollback and handoff

- This is local single-operator scope, not enterprise tenancy or production certification.
  Trusted host/DB administrators and supply-chain inputs remain outside the threat claim.
- Offline assessment supports a narrow trusted rule set, not arbitrary vulnerability
  reasoning. Other findings abstain. Citation identity does not prove semantic truth;
  human review and later quality measurement remain essential.
- Redaction cannot guarantee that all secrets/private data are recognized. Source text
  is not persisted in traces, but a consented excerpt can still be confidential.
- Hosted validation is mocked only; availability, billing and provider retention need
  separately authorized live validation. Reserved cost/token values are conservative,
  not measured usage. Revocation cannot retract prior/in-flight sends.
- A stalled provider causes worker exit and needs restart. Old queued configuration
  is never silently repinned; changed catalogs/configuration fail closed. Existing source
  retention/quotas and no published-snapshot GC remain unchanged. Full restore/retention
  hardening belongs to Phase 7.
- DB trigger history is not tamper-proof against administrators. Failed runs retain
  safe attempt/failure metadata rather than raw conversations. Validation creates
  retained labelled records; it does not delete accepted history.

No unresolved required Phase 3 gate blocker remains in the declared scope. The human
vocabulary follows the approved Phase 0 contract, and the hosted adapter uses no new
SDK/framework. No scope/stack substitution, expanded benchmark, UI, remediation, external
GitHub integration, SOC, Matroid change or later-phase implementation occurred.

[RUNBOOK.md](RUNBOOK.md) provides safe restart/rollback: disable triage acceptance,
stop only the triage worker, preserve revision 0004 and history, keep hosted/scanner
admission disabled, and prefer compatible forward fixes. Never downgrade retained data
or run old queue consumers against triage jobs. Final local API/DB/scan/triage workers
remain available; the disposable test DB is stopped with volume retained, no scanner
containers/host launcher remain, and both hosted and real scanner admission are off.

[FILES.md](FILES.md) lists all created/modified deliverables. Local instructions remain
unchanged/ignored and unstaged; no credentials or full snapshots are included. No staging,
commits, pushes, remote deployments or remote workflow activation occurred.

**Recommended Phase 4 handoff — NOT AUTHORIZED:** extend the existing initial cases into
the approved separately labelled/held-out quality and adversarial evaluation, with
explicit denominators, abstentions, evidence support and human correction metrics.
Preserve these tool/consent/fencing contracts. Any real hosted experiment still needs
separate authorization and approved synthetic inputs. Stop after Phase 3.
