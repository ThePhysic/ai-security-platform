# GitHub Actions CI compatibility repair

Scope: local CI compatibility/correctness only, based on committed HEAD
`806835f13ee57ff3f734efc534f886933a2a367f`. No production application, schema, dependency,
scanner policy, benchmark label or accepted result was changed. No database service was
started and no retained source, credentials, backup or database record was modified.

## Root causes

1. **Foundation corpus failure:** `evaluation/** text eol=lf` materializes the committed
   normalized blobs with LF. The original manifest/adversarial hashes describe CRLF
   bytes. A clean checkout therefore fails `evaluation.corpus.load()` even though JSON
   content is semantically identical.
2. **Additional foundation integrity failure:** recorded scanner provenance also hashes
   `frozen-v1.json` itself. That file's original bytes are CRLF too. Fixing only the two
   manifest members leaves the later provenance assertion failing. A third exact-path
   CRLF override is necessary; the freeze file and recorded hash remain untouched.
3. **Developer artifact generation:** the generator invokes that same corpus loader,
   so its broad exception handler hides the assertion as
   `offline_artifact_generation_failed`, exit 2. With correct checkout bytes the original
   offline generation path succeeds under its existing restrictions. Diagnostics now
   include only an allowlisted exception class, never exception text, inputs or traces.
4. **Developer demonstration policy handling:** the old final command called
   `SystemExit(policy.exit_code)`. Its intentionally failing fixture has code 1, so a
   correct demonstration still failed Actions. A separate CI verifier now expects 1,
   validates the complete artifact set and exits 0 only for that consistent result.

The pre-repair Git materialization reproduced both mismatched frozen members and the
separate freeze-identity mismatch. The old policy check was executed against the genuine
generated `policy.json` and returned 1; the new verifier returned 0 against the same bytes.

## Preserved byte identities

| File | Original SHA-256 retained |
| --- | --- |
| evaluation/manifest.json | 6de9a96f60b28f56536b8c47931e2d86305e5754702affaa2cd2f446d3417f10 |
| evaluation/adversarial.json | e6b981153b23e2d04a6bcb6d9ec433d5d1aabc91d43cd86989b2ca4d61914df2 |
| evaluation/frozen-v1.json | 5db395bc7091f8e5796c6b287a95a1da84b8e6edfc4675e2de6efb6897775845 |

These three overrides follow the existing general LF rule. All other evaluation paths
retain their existing LF attributes and committed checkout bytes. Existing local result
files were not normalized, regenerated or rewritten. All frozen members, labels,
fixture bytes, scanner observations, metrics and accepted phase evidence remain
byte-identical to the pre-repair working-tree baseline.

## Changed files

| File | Purpose |
| --- | --- |
| [.gitattributes](../../.gitattributes) | Three exact-path CRLF overrides, preserving the original frozen hashes |
| [developer-guardrails.yml](../../.github/workflows/developer-guardrails.yml) | Generation/verification/upload dependencies, expected-policy verification and unconditional guarded cleanup |
| [generate_ci_artifacts.py](../../scripts/generate_ci_artifacts.py) | Allowlisted exception-type diagnostics; unchanged execution-mode text shared with the verifier |
| [verify_ci_artifacts.py](../../scripts/verify_ci_artifacts.py) | CI-only strict artifact/schema/consistency/policy checks; bounded stdin transfer |
| [test_evaluation_corpus.py](../../tests/unit/test_evaluation_corpus.py) | Verify original freeze/manifest identities against recorded scanner provenance before PostgreSQL tests |
| [test_guardrails_workflow.py](../../tests/unit/test_guardrails_workflow.py) | Verify success gating, isolated execution, permissions/manual triggers and unconditional cleanup |
| [test_reporting_cli.py](../../tests/unit/test_reporting_cli.py) | Expected code 1, invalid codes/types, missing/malformed/oversized/incomplete artifacts, stream limits and safe diagnostics |
| [validate_ci_repair.py](../../scripts/validate_ci_repair.py) | Reproducible clean materialization and restricted Linux validation without staging or commits |
| [validation.json](validation.json) | Executed commands, checkout facts, resource controls and positive/negative outcomes |
| This report | Root causes, evidence, changes and limitations |

The foundation workflow itself needs no change: corrected checkout attributes repair its
input bytes. The production CLI still returns 0/pass, 1/finding-policy failure and
2/operational-or-incomplete outcomes.

## Artifact and workflow correctness

The generator still executes with network none, read-only root filesystem, UID/GID
10001, ALL capabilities dropped, no-new-privileges, PID limit 64, 512 MiB memory,
one CPU and a 128 MiB temporary filesystem. No Docker socket, credentials, hosted models,
live scanners or external transmission are supplied.

The verifier checks exactly three bounded regular artifact files, strict JSON parsing
(including duplicate-key/non-finite rejection), the existing JSON and SARIF schemas,
scoped source references, deterministic JSON-to-SARIF consistency and a recomputed policy
requiring Semgrep. It accepts only integer code 1 and the exact corresponding policy;
passing code 0, operational code 2, booleans, missing fields or incomplete required
coverage fail verification. Optional incomplete scanner coverage remains honestly visible
in the report; it is not relabelled clean.

Host artifact bytes are sent through bounded base64 JSON on stdin to the existing
restricted container, with no extraction or filesystem writes. The host sender uses
only the standard library (verified with Python `-I -S`). The received envelope is capped
at 16 MiB + 1 KiB and each decoded artifact at 4 MiB. This verifies the actual files
selected for upload without relaxing the read-only container requirement. A preliminary
local design using `docker cp` was rejected by Docker's read-only-rootfs check and was
replaced; that was a validation-design issue, not an additional original workflow cause.

Verification runs only after generation succeeds; upload runs only after verification
succeeds. A generator failure no longer creates upload/missing-policy cascades. Cleanup
remains `if: always()` and removes only the named disposable workflow container when it
exists. No push/PR triggers, permission grants or code-scanning upload were added.

## Executed validation

| Check | Result |
| --- | --- |
| Full relevant unit/API suite in restricted Linux container | 219 passed, 0 failed, 0 skipped; 124 PostgreSQL tests deselected |
| Frozen corpus/provenance subset | 4 passed, 0 failed, 0 skipped; overlaps the full suite |
| Restricted offline generator | Passed; 3 artifacts, policy code 1, zero live scans/hosted calls |
| Actual stdin verifier | Passed; exits 0 while policy.json remains 1 |
| Negative verifier CLI cases | 6 expected rejections with exit 2: unexpected pass, operational failure, boolean code, missing policy, malformed SARIF, incomplete required scanner |
| JSON/SARIF schemas and report/policy consistency | Passed in generation, verification and unit tests |
| Workflow static security checks | Passed within unit suite |
| Ruff, relevant Ruff formatting, mypy | Passed in clean Linux container and host checks |
| Clean Git materialization under Linux and Windows settings | All frozen member hashes and recorded freeze identity pass; remaining evaluation checkout bytes unchanged |
| Original index / private instructions / production source / retained evidence | Unchanged |

The one existing Starlette/httpx deprecation warning remains. Deselected PostgreSQL tests
are not claimed as executed: this repair changes no application/database behavior, and
the authorized checks require no database records or service changes. No mandatory
repair check is blocked.

The reproducible entry point is:

```powershell
.\.venv\Scripts\python.exe scripts/validate_ci_repair.py
```

It uses Git `checkout-index --all` with explicit `core.autocrlf=false, core.eol=lf` and
`core.autocrlf=true, core.eol=crlf`, overlays only the authorized repair, verifies all
frozen hashes, builds the test target from the clean Linux-configured tree and runs
actual Linux containers. It verifies that the original Git index is unchanged. This is
a clean Git materialization plus Linux runtime proof, not an uncommitted remote run or a
claim that native Linux Git was invoked on this Windows host.

Exact Docker/unit/lint/type commands and their image identity are in
[validation.json](validation.json). Container checks retain every resource/security flag;
the unit/lint containers use a separate 256 MiB tmpfs, while artifact generation and
verification retain the workflow's 128 MiB limit. All disposable validation containers
are removed with label-checked cleanup; build images and ignored logs remain local.

Initial validation also caught a late-bound closure lint warning in the new validation
helper; it was corrected and the final clean checks rerun. No security requirement was
relaxed to resolve either local validation issue.

## Limits and stopping point

Remote GitHub Actions were not triggered, and these changes are uncommitted/unpushed.
The repaired remote outcome remains unobserved until the user publishes and manually
runs the change. Local validation does not verify artifact-upload service availability
or GitHub runner infrastructure. Existing finite-corpus, unsupported coverage, two
ungraded Kubernetes bindings and A13 advisory-remediation limitations remain unchanged.

No project feature, accepted architecture, visibility, workflow trigger, deployment or
Matroid change occurred. Stop after this CI repair.
