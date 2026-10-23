# Phase 5 validation and acceptance

G8 is evaluated for local Windows/Docker Desktop execution, deterministic offline triage
and mocked hosted transport. It makes no claim of remote GitHub execution, hosted model
quality, production capacity or complete vulnerability detection. See the completion
report for the final gate decision and exact final suite count.

| Requirement | Evidence |
| --- | --- |
| Locked dependencies, typing and lint | `uv lock --check`, locked/offline sync, frozen image installs; Ruff and mypy in `test-evidence.json` |
| Complete CLI workflow and codes | Eight live validation groups, 27 actual CLI invocations; default real policy, explicit fake diagnostics, idempotent replay/conflict, status/history/finding pages and safe exports in `live-evidence.json` |
| Wait timeout/cancellation | Actual subprocesses against a controlled loopback status server; exit 2 and no server mutation request in `cli-interruption-evidence.json`; also included in the final complete suite |
| JSON/SARIF | Pydantic/generated JSON Schema and official pinned OASIS Draft 04 SARIF validation; stable ordering, source paths/lines/hashes, per-scanner partial outcomes, synthetic markers, absent raw source/advice/links |
| Confidentiality and output paths | Synthetic credentials absent from normalized reports/logs; traversal, bad source identities, invalid lines, URL-shaped rules, output basename and interrupted/existing file checks |
| CI and fallback | Seven local checks, 145 unit/API tests, three offline artifacts in `ci-evidence.json`; trusted default branch/manual actions, read-only token, pinned actions; no remote run/upload |
| Independent workers | Actual PostgreSQL with 1/2/4 spawned worker processes; 72 scans, 144 jobs, 15,120 synthetic findings; each job completed once with generation 1 in the measured normal workload |
| Performance and query plans | `performance-evidence.json`, `hardware.json`, `workload-provenance.json`, `PERFORMANCE.md`; actual indexed/diagnostic sequential plans, no speculative new index |
| Scan crash/retry | 25 process experiments: five each after claim, output, findings, commit and database disconnection; stale writes/heartbeats rejected, correct terminal findings/events |
| Triage recovery | Five process experiments after claim, output, outcome, commit and database disconnection; one outcome/completion event, independent successful scan preserved |
| Provider failure and malformed output | Existing real PostgreSQL triage tests: bounded timeout/rate-limit/unavailable retries, terminal invalid output, consent revocation/replay, durable provider budgets, stalled process recovery; zero live hosted calls |
| Scanner limits, failures and partial outcomes | 31 real container isolation controls plus 16 real scanner checks; PG launcher handoff/retry/stale publication tests; incomplete parser/unsupported/missing DB semantics remain explicit |
| Snapshot boundary | Administrator native NTFS ten passes; prior portable path/link/mutation/quota/intake tests and actual native spool-to-container transport through CLI registration |
| HTTP/security/migrations | All existing G1 API/auth/Host/Origin/body/error/log/session/transaction/constraint tests; disposable migration reset/downgrade/re-upgrade only; development revision unchanged |
| Persistence and data preservation | Actual API/database/worker restarts, database unavailable health/readiness/error and recovery; 32 final runtime checks; every pre-existing row hash preserved across 17 tables |
| Frozen evaluation | Two offline triage/adversarial repetitions over retained genuine scanner observations, same quality/category and attack outcomes; frozen fixtures/labels/rules/results byte-equivalent to accepted baseline |

## Frozen evaluation limitations remain

No evaluation corpus, labels, rules, scanner adapter or agent reasoning behavior changed.
All 28 fixtures and their 14/14 development/held-out split remain frozen. The existing
scanner baseline retains two ungraded Kubernetes bindings, four unsupported cases and
one incomplete case. The deterministic triage baseline retains four required abstentions
among 13 graded invocations. Valid citations are not a proof that advice is supported.

Adversarial A13 still accepts an unsupported remediation recommendation **as an advisory
opinion**. The case has no execution/write tool and cannot change human review. It is
not relabelled as good advice. The 16 cases retain zero observed prohibited-action
successes and synthetic-secret disclosures; those bounded observations do not establish
universal security. AI advice is absent from automatic CI pass/fail decisions.

The Phase 5 evaluation test replays the immutable genuine scanner observations and
reruns actual agent/tools/DB/review/attack logic twice. Separate Phase 5 positive/clean,
failure and isolation regressions execute actual scanner containers. The entire 112-run
Phase 4 scanner corpus acquisition was not repeated or overwritten; its accepted
provenance remains explicit. Measured triage timings can differ; quality labels and
semantic outcomes must match. No new model quality claim is made.

## What has not been validated

Live hosted API billing, availability, model reasoning and provider retention remain
unverified and unauthorized. GitHub runner/action/artifact-service behavior and security
entitlements were not tested remotely; local checks cannot substitute for a remote run.
The clean candidate build includes authorized unstaged changes because creating a Git
commit is forbidden. No public deployment, enterprise connector, frontend, backup/restore
release exercise or broad load test was performed.

Local performance is a bounded microbenchmark with small source-only fixtures, cached
assets, limited samples and shared host resources. It is not a throughput promise or
SLO. Known-format redaction does not guarantee complete private-data removal. CI artifacts
are a controlled replay example, not scanning of an arbitrary GitHub checkout. These
declared limits are separate from required local checks; a required execution failure
would be marked blocked or failed instead of silently skipped.
