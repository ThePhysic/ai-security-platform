# Phase 5 measured local workloads

These are local observations, not production capacity, SLOs or vulnerability-detection
quality estimates. Raw measurements and plans are in [performance-evidence.json](performance-evidence.json),
[live-evidence.json](live-evidence.json) and [recovery-evidence.json](recovery-evidence.json).
Run `python scripts/validate_phase5.py` and the controlled live validation described in
the runbook to reproduce; new timing samples will differ.

## Environment and method

Windows 11 build 26200, AMD Ryzen 9 7940HS, 16 logical processors, 33,515,835,392 bytes
physical RAM. Docker Desktop Linux engine 29.9.1, WSL2 kernel 6.18.54.1, 16 CPUs and
16,353,488,896 bytes available to Docker. Python 3.12.15, PostgreSQL 17.11 and locked
runtime/scanner assets are recorded in the runtime/scanner evidence. PostgreSQL and the
retained development application share this host; unrelated applications were not stopped.
See [hardware.json](hardware.json) for exact facts.

Percentiles use nearest rank. No OS, database or Docker caches were flushed. The
`first_publication_execution` and `repeated_warm` labels identify execution order,
not true cold/warm cache isolation. The disposable tables grow between repetitions;
this is an explicit confounder. There is no independently repeated production-scale
sample, capacity guarantee or extrapolation to other hosts/repositories. Provider/model
cost is unmeasured; no hosted model ran.

## Durable backend diagnostic

Fixed 200 marker files, 6,030 bytes, fake-v1. Each scan produces 210 **synthetic** findings
across two fake scanner jobs. Each row below uses 12 accepted scans/24 jobs and real
PostgreSQL, with synchronized independent spawned worker processes. Total: 72 scans,
144 jobs, 15,120 findings. Each job has one completion event and generation 1; normal
workload retry/error counts are zero. No target scripts or dependencies execute.

| Workers | Order | Jobs/s | Queue p50/p95 ms | Job execution p50/p95 ms | Scan lifecycle p50/p95 ms |
| --- | --- | --- | --- | --- | --- |
| 1 | first_publication_execution | 8.94 | 5637.70 / 6491.97 | 31.92 / 74.38 | 5666.95 / 6627.61 |
| 1 | repeated_warm | 8.89 | 5677.16 / 6620.00 | 32.48 / 58.03 | 5716.77 / 6699.41 |
| 2 | first_publication_execution | 12.40 | 5358.09 / 5868.66 | 34.04 / 89.11 | 5390.21 / 6024.21 |
| 2 | repeated_warm | 13.66 | 5266.38 / 5701.67 | 31.38 / 92.26 | 5311.71 / 5766.23 |
| 4 | first_publication_execution | 18.40 | 5351.90 / 5522.59 | 35.29 / 127.02 | 5390.14 / 5597.98 |
| 4 | repeated_warm | 18.38 | 5102.32 / 5314.48 | 38.05 / 102.48 | 5158.51 / 5411.05 |

Throughput excludes process startup and pre-enqueue time: 24 completed jobs divided by
barrier-release-to-all-workers-exited wall time. It includes worker completion/exit
collection overhead. Queue wait and scan lifecycle use database timestamps and include
sequential acceptance of the batch and process initialization; these different intervals
explain why queue/lifecycle numbers exceed the measured drain window. Startup and each
worker's lifetime CPU seconds/max RSS are retained in JSON. RSS is Linux KiB and process
lifetime peak, not per-job allocation or total host usage. These marker adapters exercise
source verification, leases and fenced writes, not real scanner engine throughput.

Observed worker lifetime peak RSS ranged from 125.30 to 125.30 MiB; per-process CPU time ranged from 4.907 to 6.089 seconds. These are diagnostic child processes in the test container, not individually production-cgroup-limited worker containers.

## Genuine security-v1 observations

Exactly 200 acquired source/config files, 4,068 bytes, content/manifest digests in
[workload-provenance.json](workload-provenance.json). Maintained inert positive fixtures
plus numbered benign Python/JavaScript files; 85 normalized non-synthetic findings per
scan. Three sequential scans, six actual Semgrep/Trivy container jobs, one ordinary
worker and the existing serial host launcher. Scanner policies/images/offline database
remain unchanged. All succeeded; default HIGH policy correctly returned 1. This is a
small repeated fixture measurement, not a realistic large-repository capacity test.

| Observation | CLI wall ms | DB scan lifecycle ms | Findings |
| --- | --- | --- | --- |
| 1 | 27641.00 | 22970.61 | 85 |
| 2 | 27234.00 | 22737.57 | 85 |
| 3 | 25547.00 | 21428.05 | 85 |

CLI wall: n=3, p50=27234.00 ms, p95=27641.00 ms.

DB scan lifecycle: n=3, p50=22737.57 ms, p95=22970.61 ms.

Job queue wait: n=6, p50=439.24 ms, p95=11109.02 ms.

Job execution: n=6, p50=10847.15 ms, p95=11870.81 ms.

With n=3 the scan p95 is simply the maximum sample. CLI wall includes process startup,
polling, export verification and policy. Job duration includes launcher handoff/container
lifecycle and publication, not only engine CPU. The second scanner waits for the first
under the single-worker/serial launcher configuration. All six jobs have generation 1.
No real-scanner 2/4-worker capacity claim is made. The separate backend diagnostic
supplies the 1/2/4-process correctness and throughput comparison.

## Queries and index evidence

Thirty sequential observations each, same measured connection/ORM boundary, 15,120
finding rows and 72 history rows:

| Query | n | p50 ms | p95 ms |
| --- | --- | --- | --- |
| Finding page | 30 | 3.355 | 5.491 |
| History page | 30 | 1.927 | 3.583 |

`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` on controlled disposable tables after ANALYZE
records the actual first-page predicate/order/limit. It is a narrower projection than
the ORM latency observations above; do not equate server execution and full API latency.
The forced sequential comparison changes session-local planner settings only, never
removes or creates an index.

| Plan | Execution ms | Top shared-hit blocks | Interpretation |
| --- | --- | --- | --- |
| planner_default | 0.060 | 50 | Existing ix_findings_scan_history index scan |
| forced_sequential_diagnostic | 1.912 | 694 | Diagnostic sequential scan plus bounded sort |
| history | 0.060 | 2 | Planner chose sequential scan plus sort over only 72 rows |

The existing finding history index is appropriate for this measured predicate; the
small history scan is inexpensive. No additional index or migration is justified by
these samples. Buffer hits reflect cached observations, not disk-I/O capacity. Larger
or differently filtered workloads require new evidence before any index decision.

## Failure recovery

One explicitly timed worker kill after output recovered in **571.50 ms** (n=1), including termination, lease expiry, bounded backoff and re-execution to terminal
success. The winning generation is 2, and stale publication/heartbeat fail. This is a
combined retry-to-recovery observation, not an isolated retry-delay or tail guarantee.
The 25 scan and five triage process experiments separately validate all documented
crash points, commit outcomes, database interruption and fenced authoritative writes.
No p95 recovery claim is derived from one sample.
