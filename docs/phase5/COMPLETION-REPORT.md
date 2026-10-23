# Phase 5 completion report

Phase 5 delivers local developer workflows, sanitized JSON/SARIF and deterministic
scanner policy, with reproducible reliability/performance evidence. The primary focus
remains 1Password AppSec/developer guardrails; Brain Co secure AI/CI and Prophet durable
backend relevance remain supporting overlap. No Phase 6 or later work was performed.

| Checkpoint/gate | Result | Declared scope |
| --- | --- | --- |
| 5A: developer integration | PASS locally | CLI, exports, policy codes and artifact-only workflow definition/clean candidate validation |
| 5B: reliability/performance | PASS locally | Actual PostgreSQL and independent workers, real isolated scanners, restarts/failure injection and bounded measurements |
| G8 | PASS for declared local scope | Required local checks executed; no silent skips; remote Actions and live hosted calls unexecuted and unauthorized |

The user must review this gate before authorizing Phase 6. No workflow was activated,
code-scanning artifact uploaded, credential provisioned, Git file staged/committed/pushed
or remote deployment performed. The separate Matroid application was untouched.

## Delivered behavior

The existing CLI now submits and waits, queries coverage and per-scanner outcomes,
traverses bounded signed finding pages, exports source-verified JSON/SARIF and evaluates
an explicit deterministic policy. Default security policy requires complete Semgrep
and Trivy execution and fails HIGH/CRITICAL findings. Exit 0 means completed/pass,
1 completed/threshold failure, 2 invalid/operational/incomplete; incomplete required
checks win. Fake diagnostic results need explicit opt-in and remain synthetic. AI
triage, human review and remediation opinions never influence these scanner policy codes.
Cancellation and timeout leave durable server jobs running.

The existing export API adds SARIF format and a versioned source/provenance envelope.
It verifies immutable source identity, relative paths and valid lines, orders output
deterministically and preserves partial scanner outcomes. Arbitrary scanner messages,
raw source, unsafe links, secret values and model advice are excluded or rejected.
CLI artifacts are private, bounded, exclusive, atomic and confined to `.local/reports/`.
JSON additions retain schema_version 1 plus scan/findings; strict consumers need the
documented new reporting fields.

The new manual/default-branch CI demonstration generates three artifacts with read-only
permissions, pinned actions, no target-script/dependency execution, network-disabled
non-root processing and no code-scanning upload dependency. It explicitly replays
retained genuine controlled observations; it is not scanning arbitrary PRs or claiming
that Windows scanner isolation transfers to hosted runners. The foundation workflow
also becomes manual/default-branch to prevent automatic untrusted PR toolchain execution.

See [implemented contracts](ARCHITECTURE-AND-CONTRACTS.md), [file inventory](FILES.md),
[commands](COMMANDS.md), [validation matrix](VALIDATION.md), [measurements](PERFORMANCE.md)
and [runbook/rollback](RUNBOOK.md).

## Versions and database compatibility

| Component | Exact version |
| --- | --- |
| Python / uv | 3.12.15 / 0.13.5 |
| PostgreSQL | 17.11, Debian 17.11-1.pgdg12+2 |
| FastAPI / Pydantic / pydantic-settings | 0.161.0 / 2.14.1 / 2.16.1 |
| SQLAlchemy / Alembic / Psycopg | 2.0.55 / 1.20.1 / 3.3.6 |
| Ruff / mypy / pytest | 0.17.2 / 1.20.2 / 9.1.1 |
| Added development JSON Schema validator | jsonschema 4.26.0 |
| Added transitive development dependencies | attrs 26.1.0, jsonschema-specifications 2025.9.1, referencing 0.37.0, rpds-py 2026.9.1 |
| Docker Desktop Linux engine / Compose | 29.9.1 / 5.6.0 |
| Semgrep / Trivy | 1.179.0 / 0.76.1, unchanged accepted assets |
| Migration | **0004_triage_review**, unchanged; no Phase 5 revision/index |

`uv lock --check` and `uv sync --locked --offline` succeeded; lock contains 46 packages.
Runtime dependencies and architecture are unchanged. Full installed versions and
container restrictions are in [runtime evidence](runtime-evidence.json). Images remain
digest-pinned. Exact scanner/rule/database digests and age appear in
[scanner evidence](scanner-regression.json) and the real workload samples in
[live evidence](live-evidence.json); database SHA-256 is
`4566427d61ff4e2c565b331376b07e58afc5166efd4a78cdc8fd10ca657d2898`,
updated 2026-10-22T19:14:47.059491Z. No scanner asset refresh was needed.

The official [OASIS SARIF schema source](https://github.com/oasis-tcs/sarif-spec/blob/a560296ca8c921f3bdb8d4a8db57ab83dae968a7/sarif-2.1/schema/sarif-schema-2.1.0.json)
is vendored with digest/license and validated as Draft 04, offline. Checkout v4.2.2 and
[upload-artifact v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2)
are pinned by immutable action commits in the workflow definitions.

## Test and failure evidence

The final complete suite passed **255 tests, 0 failed, 0 skipped**, recorded in
`test-evidence.json`. It includes all
existing G1–G7 tests and new reporting, policy, workflow, real PG export, workload and
actual CLI interruption checks. Ruff and strict mypy pass. The clean candidate CI run
independently passes **145 unit/API tests**, seven artifact/build/schema checks, and
produces three schema-valid example artifacts with a deliberate policy failure code 1.

Native NTFS: **10 passed**, zero blocked/skipped after the administrator command.
Container isolation: **31 passed**, including egress/DNS, filesystem/credential/daemon
denial, non-root/capability policy, CPU/memory/PID/tmp/output/deadline bounds,
ownership-loss termination, actual launcher kill and orphan cleanup. Real scanner:
**16 passed**, including positive/clean detections, poisoned ignore/suppression handling,
genuine malformed output, unsupported coverage and missing/stale database failure.

Live CLI: **eight groups passed, 27 actual subprocess invocations**, with creation,
Windows spool registration, idempotent replay/conflict, pagination, pass/fail/incomplete
policy and operational errors, safe JSON/SARIF, three actual 200-file scans, real
API/worker/triage/database restarts, unavailable-DB health/readiness and reconnect.
Those scans succeeded with **85 non-synthetic findings each**; threshold policy
correctly returned 1. Known synthetic and local credentials were absent from logs
and exports. Final rebuilt-runtime retained-scan export was also verified.

**25 scan crash/retry experiments** passed: five each after claim, output, findings,
commit and database disconnection. Winning generation/event/finding counts were correct;
stale heartbeat, findings, status and audit publication were rejected. **Five triage
recovery experiments** passed after claim/output/outcome/commit/database disconnect,
with one outcome/event and successful scan status preserved. Provider timeout/rate-limit/
unavailable/malformed output, revocation and durable budgets reran through the existing
real PostgreSQL tests with deterministic/mocked transport, without hosted calls.

The separate process interruption test proves wait timeout and SIGINT return 2 and issue
only read requests. Atomic artifact tests cover interrupted publication and overwrite
rejection. The full suite also reruns disposable migration upgrade/repeat/downgrade/
upgrade and database constraints/transaction/HTTP/auth/logging tests. Required PG and
process checks use actual PostgreSQL/processes, not mock substitutes.

Corrected early harness failures and reruns are listed in [commands](COMMANDS.md).
An existing TestClient deprecation warning remains; it is not a skipped check.

## Performance and indexed queries

Two workloads are deliberately distinguished:

- Backend diagnostic: fixed 200 files/6,030 bytes, 72 scans, 144 jobs and 15,120 synthetic
  findings across 1/2/4 independent workers and two ordered repetitions each. It measures
  leases, fenced persistence and queries, not real vulnerability detection throughput.
- Genuine security-v1: fixed 200 files/4,068 bytes, three sequential scan observations,
  six isolated scanner jobs with one ordinary worker and serial trusted launcher. Exact
  queue/execution/lifecycle timings and provenance are retained. No real-scanner scaling
  claim is made for 2/4 workers.

Nearest-rank p50/p95, sample counts, worker RSS/CPU, hardware and cache limitations are
in [PERFORMANCE.md](PERFORMANCE.md). Query evidence compares the existing finding index
with a forced sequential diagnostic and records the history planner choice. No new
index was justified. One measured worker kill/retry recovered with generation 2 and
stale publication rejected; the observation includes lease expiry, backoff and rerun,
not an SLO or a separately isolated provider/network latency estimate.

## Preservation, risks and limits

All pre-existing development records are byte-equivalent by private per-row hash
comparison across **17 tables**, including consent/triage and immutable human-review
history. Controlled Phase 5 validation rows/snapshots remain retained. Counts increased
from 23 to 28 scans and 1,566 to 1,825 findings; the original history was not reset.
Schema revision remains 0004, and rollback needs no data downgrade.

Frozen evaluation fixtures, manifest, labels, prior reports, rules and accepted policy
assets are unchanged. Quality/category metrics and adversarial outcomes match the
accepted Phase 4 results; timing differs normally. Two Kubernetes bindings remain
ungraded; unsupported/incomplete cases, deterministic-provider abstentions and A13's
unsupported advisory recommendation remain visible. Valid citations do not establish
semantic remediation support. Model advice is excluded from automated policy decisions.

Remaining limits:

- Known-format redaction is not comprehensive secret detection. Paths/dependency/rule
  metadata can themselves be confidential; inspect artifacts before any authorized sharing.
- Real admission and hosted execution are disabled after validation. Scanner assets,
  database freshness, launcher health and original G4 boundary still gate real execution.
- Benchmarks are small local observations with shared resources and unflushed caches;
  they do not establish production capacity, tail guarantees or operational readiness.
- Clean candidate validation is not a committed-checkout or remote GitHub run. The
  workflow artifact example replays controlled observations; private/fork repository
  scanning and external upload would need separate design/approval. Remote service
  availability and entitlements remain unverified.
- Live hosted quality/cost/provider retention remain unverified and unauthorized.
  No AI/scanner behavior or frozen label was expanded to improve evaluation scores.
- Local artifacts are retained privately without an automatic retention service;
  per-artifact bounds and exclusive publication do not make the local host an
  administrator-resistant sandbox.

No stack/scope deviation occurred. Additive export fields, diagnostic-versus-real
measurement scope and manual trusted-branch workflow behavior are explicit implementation
choices. Required local gates are not replaced by remote or hosted claims.

## Safe operations and next handoff

The [runbook](RUNBOOK.md) provides exact project-only restart and application rollback
commands. Development services remain available, loopback-only and restricted; real
and hosted admission are false, no scanner containers/host launcher remain, and the
disposable test database is stopped with its volume preserved. No unrelated resources
were stopped or changed. Local instructions are unchanged, ignored and excluded from
builds and generated artifacts.

Recommended Phase 6 handoff, **not authorized or implemented**: build only the approved
minimal React/TypeScript/Vite dashboard over existing authenticated contracts. Preserve
coverage/incomplete distinctions, scanner policy versus advisory AI/human assessments,
optimistic review revisions, private evidence boundaries and local browser restrictions.
Carry forward the exact G7 limitations and G8 performance scope. Read this report and
the earlier architecture/runbooks before proposing UI behavior; do not add remediation,
new scanning engines, enterprise integration, SOC or Phase 7 release work.
