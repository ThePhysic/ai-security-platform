# Final review findings and disposition

Severity reflects the declared local single-operator trust model. Findings are bounded
by reproducible observations, not assumptions about production or hostile administrators.

| ID | Severity | Boundary / impact | Reproduction and disposition |
| --- | --- | --- | --- |
| F01 | Medium defense-in-depth | Staging cleanup used path-based traversal and changed permissions before unlinking; an injected hardlink/substitution could affect an outside file if the private staging boundary were violated | **Fixed.** Whole-tree no-follow validation, hardlink/reparse rejection and pinned handle/descriptor deletion. Native tests preserve the outside file and reject junction substitution. `tests/unit/test_lifecycle.py` |
| F02 | Medium supply chain | Runtime uv.lock did not constrain isolated hatchling build resolution; fresh builds could select different backend/transitive build code | **Fixed.** Hatchling 1.32.4 plus five exact transitive build constraints with official wheel SHA-256 hashes, recorded in uv.lock. Runtime versions unchanged. Fresh uncached application build and frozen installation pass. `build-toolchain.json` |
| F03 | Low local availability | Individually bounded exported reports had no aggregate storage quota | **Fixed.** Serialized exclusive publication; 64 files / 64 MiB aggregate, 4 MiB each. Existing exports are preserved on quota failure; no-overwrite and interrupted-write contracts retained. Native and container tests cover the bound. |
| F04 | Critical upstream advisory candidate | OSV's open-ended Go range matches Trivy 0.76.1 for GO-2026-4919 / CVE-2026-33634 | **Reviewed; affected artifact not established here.** Retain the raw match. Upstream identifies compromised 0.69.4 release and 0.69.5/0.69.6 Docker images; the project uses pinned 0.76.1, no Trivy setup/action, and verified local image/executable/DB provenance. This is an applicability inference, not proof of publisher integrity. Sources below. |
| F05 | Low advisory quality | A13 can return unsupported remediation alongside structurally valid citations | **Accepted documented limitation.** Existing frozen result unchanged. No action/write tool or automatic human decision exists; dashboard/reporting label advice advisory and exclude it from policy decisions. Semantic-remediation validation remains future work. |
| F06 | Low operational confidentiality residual | Private backups contain source and DB history; checksum receipts are not signatures or encryption | **Mitigated within local scope.** Private ACLs, ignored/build-excluded directories, fixed targets, out-of-band trusted manifest digest and bounded quotas. No credential configuration is included. Host administrators and DB source are trusted. No external transmission. |

F04 primary sources: the [upstream Trivy advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
enumerates the affected release/image versions, while the [0.76.1 release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1)
identifies the later release. The [Go record](https://vuln.go.dev/ID/GO-2026-4919.json)
uses a broader range. [Raw OSV record](trivy-advisory.json) and
[version-query results](dependency-advisories.json) preserve the discrepancy.

No scanner policy, image, benchmark label or agent behavior was changed to remove the
match or improve evaluation scores. No known high-severity defect in the supported
application boundary remains unaddressed; the upstream advisory is not reported as a
clean audit result or silently excluded.

F07 (Low reproducibility limitation): the archived first review observed one `python-dependency-positive` repetition changed
context bytes from 3,524 to 3,523 and token bound from 50,057 to 50,056 compared with Phase 6.
The frozen methodology already excludes these resource observations; all dispositions,
citations/support and attack outcomes match. The context tool orders freshly generated
finding UUIDs, which can change selected peer-rule lengths after reacquisition. That
specific payload explanation is an inference; raw context is deliberately not exported.
The final rerun has three one-byte resource differences (two dependency repetitions and
one ungraded Kubernetes case); semantic/support outcomes still match. No labels, methodology
or agent behavior were changed. See [comparison](regression-comparison.json).

F08 (Low least-privilege gap, fixed before final signoff): the new disposable Compose
anchor inherited the API launcher credential into ordinary and triage workers. The
established development configuration was unaffected, and real admission remained disabled.
Both disposable consumer environments now explicitly clear that capability. A new static
contract and actual container checks verify absence, while the API retains its separate
verification credential. The test Docker context includes only the nonsecret Compose
contract so this test runs in clean CI as well. No credential value was exported.
[Before finding](review-1/sandbox-capability-finding.json),
[actual corrected boundary](sandbox-capability-evidence.json),
[final environment checks](environment-evidence.json).
Earlier Phase 7 review results are preserved under `review-1/`; final root reports are
new validation after this fix. All accepted Phase 0?6 evidence remains unchanged.

## Additional reviewed areas

Authentication, Host/Origin, request limits, secret-safe errors/logs, snapshot identity,
launcher capability separation, fixed scanner policy, job/triage fencing, scoped evidence,
consent replay, human revision atomicity and UI hostile-content rendering passed their
applicable regressions. They remain limited by the [final threat model](THREAT-MODEL.md).

The six isolated build packages are hatchling 1.32.4, packaging 26.3, pathspec 1.1.1,
pluggy 1.7.0, tomlkit 0.15.2 and trove-classifiers 2026.9.21.13. Official archive hashes
were obtained over HTTPS from PyPI metadata; this is a trust source, not independent
signature verification. uv supports recording build constraint hashes in its lock:
[official settings](https://docs.astral.sh/uv/reference/settings/#build-constraint-dependencies).

The final advisory query covers public package names/versions only. CI actions resolve
to their official pinned commits with contents:read, workflow_dispatch and trusted default
branch guards. No remote workflow was activated. Scanner images/policies and the 1,627,238,400-byte
offline vulnerability DB match retained provenance. An exhaustive transitive scanner-image
SBOM/CVE assessment and third-party certification were not performed.
