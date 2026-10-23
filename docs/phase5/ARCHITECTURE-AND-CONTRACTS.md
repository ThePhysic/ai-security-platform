# Phase 5 developer contracts

Phase 5 extends the local AppSec CLI and reporting layer. The scanner launcher,
policies, providers, agent, human decisions and PostgreSQL publication fences retain
their accepted behavior. There is no new service, database migration or runtime dependency.

## Workflow and exit codes

`asp` is the existing installed Python entry point; `python -m ai_security_platform.cli`
is equivalent. Commands read the bearer token from the environment or ignored local
configuration. The API URL must be HTTP on localhost/127.0.0.1 with an explicit port,
without user information, paths, query or fragment. Proxies and redirects are disabled.
Responses are bounded to 4 MiB, and resource identifiers are parsed as UUIDs.

| Command | Contract |
| --- | --- |
| `project-create NAME` | Create an authenticated local project |
| `snapshot-create SOURCE --label LABEL` | Acquire independent validated bytes into the existing private spool |
| `snapshot-register --project UUID --key KEY --digest SHA256` | Server-side identity verification through the read-only container mount |
| `scan-submit --project UUID --snapshot UUID --idempotency-key KEY --profile PROFILE` | Durable acceptance only; historical default remains `fake-v1` |
| `scan --project UUID --snapshot UUID --idempotency-key KEY [--profile PROFILE]` | Submit, bounded wait, export verified facts, evaluate policy; default `security-v1` |
| `scan-wait UUID` | Wait for an existing scan and evaluate policy |
| `scan-status UUID` | Status, coverage and independent scanner outcomes |
| `scan-history --project UUID [--cursor CURSOR --limit N]` | Existing signed keyset history page |
| `findings UUID [--cursor CURSOR --limit N]` | Existing signed keyset finding page |
| `findings UUID --all [--limit N --max-pages N]` | At most 20 pages, 100 records/page, 1,000 records; reject duplicate records/repeated cursors/exhausted budget |
| `policy UUID [--policy FILE]` | Evaluate scanner facts without changing persisted state |
| `export UUID --name BASENAME --format json\|sarif [--policy FILE]` | Publish a sanitized artifact and return its policy outcome |

Scan, scan-wait, policy and export return **0** when required scanning completes and
policy passes, **1** when completed scanning fails the threshold, **2** for invalid
requests, operational errors or incomplete required checks. Incomplete takes precedence
over finding severity. Intake/query commands return 0 for successful operations, 2 for
errors; acceptance is not a successful security-policy decision.

Wait defaults to 120 seconds, configurable 0.1–900; polling defaults to 0.5 seconds,
configurable 0.1–5. Individual calls use at most ten seconds or remaining wait time.
429/502/503/504 and transport timeouts may be polled again within that deadline.
Ctrl+C returns 2 with `scan_continues:true`; cancellation or timeout stops the client
wait, without cancelling a durable server job. Preserve the idempotency key and query
or replay after a lost response. Submission and acquisition remain separate operations:
replaying a key must reference the same registered immutable snapshot.

An optional explicitly named JSON policy file is limited to 4 KiB, with strict types
and unknown fields rejected. There is no repository-controlled policy discovery.
Defaults:

```json
{"version":1,"required_scanners":["semgrep","trivy"],"fail_at":"HIGH","allow_synthetic":false}
```

Thresholds are INFO/LOW/MEDIUM/HIGH/CRITICAL. Required stages must succeed with explicit
complete execution, no coverage warnings/unavailability, and acceptable synthetic status.
UNKNOWN severity returns 2. An explicitly optional failed scanner remains visible;
required completeness and all returned finding severities still govern policy. Diagnostic
fake findings require explicit `allow_synthetic:true` and fake scanner names; they never
become real detections. No human rejection, model confidence, remediation recommendation,
triage availability or evaluation annotation suppresses a scanner policy finding.

## HTTP export and schema compatibility

The existing authenticated `GET /api/v1/scan-runs/{id}/export` accepts `format=json`
(default) or `format=sarif`. Unsupported formats receive the established sanitized 422.
JSON preserves top-level `schema_version:1`, `scan` and `findings`; adds
`reporting_version:scanner-report-1`, source references and explicit limitations.
Consumers with their own closed schemas must adopt the new documented fields. This
is additive HTTP data, not a claim of byte compatibility with older exports.

`reporting/contracts.py` defines the Pydantic report contract, with the generated JSON
Schema in `tests/schemas/report-v1.json`. Official SARIF 2.1.0 uses the vendored OASIS
Draft 04 schema, pinned commit and SHA-256 in `tests/schemas/provenance.json`, with
upstream license retained. Validation resolves only internal references, offline.

Export requires a published, verified snapshot and re-verifies the spool manifest and
source bytes. It closes its read transaction before filesystem I/O. More than 1,000
findings returns 409 `export_limit`; missing/invalid source returns safe 409
`export_evidence_unavailable`/`export_evidence_invalid`. No plausible clean report is
substituted. Query pages remain available independently of artifact export.

Reports are bounded to 4 MiB and use stable ordering: scanners by identity; findings by
scanner/path/line/rule/occurrence; rules and source artifacts sorted. CLI output uses
canonical JSON with a trailing newline. Determinism applies to the same persisted facts,
not independently created scans with different UUIDs/timestamps. SARIF includes separate
runs per scanner, original/normalized severity, rule index, relative verified path/line,
source file hash, tracking/occurrence fingerprints, provenance, execution success,
coverage and explicit synthetic markers. Partial findings survive failed scanner runs.

Source excerpts, arbitrary scanner messages/links and AI advice are omitted. Messages
come from trusted platform category text. Strings/provenance/evidence are allowlisted
and bounded; known synthetic/credential formats are redacted or rejected. Only files
referenced by findings enter the source map. Absolute source paths and raw secret
values are excluded. This does not guarantee removal of every possible confidential
identifier or unknown secret format; paths and dependency/rule metadata can be sensitive.

Artifact output is limited to `.local/reports/<basename>.json|sarif` under the current
workspace. Basenames allow lowercase ASCII letters/digits/underscore/hyphen, 1–48
characters. No absolute output paths or overwrites. Ancestor link/reparse checks,
private directory permissions, exclusive temporary files, fsync and atomic exclusive
hard-link publication prevent partial/clobbered artifacts. This trusts the local operator
and filesystem; it is not an administrator-resistant filesystem sandbox.

## CI and authority

Both workflow definitions are manual dispatch on the trusted default branch only,
with contents:read, immutable action SHAs, checkout credential persistence disabled
and no code-scanning permission/upload step. This closes the earlier automatic
untrusted-PR toolchain execution path. The foundation workflow retains database,
queue and agent checks. The developer artifact workflow uses an isolated non-root,
read-only, network-disabled container with fixed limits, without local credentials,
source mounts or Docker authority inside that container.

The artifact example deliberately replays frozen genuine controlled scanner observations
against verified fixture bytes; it is labelled `offline-fixture-replay`, **not a new
scan of a GitHub checkout**. It demonstrates artifact/policy plumbing and schema validation
without assuming Windows scanner isolation is portable to a hosted Linux runner.
The selected Semgrep-required example fails policy with code 1; Trivy's unsupported
coverage remains visible. Generation failures/missing policy artifacts produce operational
failure 2. GitHub represents either nonzero code as a failed step; the policy artifact
and named step distinguish the reason.

Upload-artifact is pinned to v7.0.2's immutable commit, restricted to three named files,
with seven-day retention and hidden files excluded. Running that workflow would transmit
these controlled artifacts to GitHub; **no workflow was activated here**. Code-scanning
upload is absent and would require separate authorization/entitlement checks. No private
repository scanning, fork-secret exposure, pull_request_target or target dependency/script
execution is introduced.

Local clean-tree validation copies tracked and authorized untracked candidate files,
excluding private configuration, caches, instruction files and links. It builds the
pinned image, validates three artifacts offline and runs unit/API tests. Because no
commit is authorized, this is a **clean candidate tree**, not a committed-checkout or
remote Actions success claim. Fixed filenames are extracted using bounded stdout;
Docker archive copy did not expose the tmpfs files on this host.

## Reliability ownership

`jobs/`, scanner adapters, launcher boundary, agent and review writes are unchanged.
The workload harness uses the guarded disposable PostgreSQL database and independent
spawned worker processes. All scan/triage fencing, at-least-once execution, recovery
and immutable review guarantees remain in their original owners. There is no schema
revision beyond `0004_triage_review`, new index, infrastructure service or provider call.
