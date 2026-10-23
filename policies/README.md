# Trusted scanner policy

`scanners.lock.json` is public provenance, not a credential file. It pins official
upstream manifests, prepared local image IDs, tool/executable/core hashes, first-party
policy hashes and the offline Trivy database bundle/files/metadata. Actual execution
uses immutable IDs with no pulls. Image tags are preparation conveniences only.

Source for trusted policy is `runner/images/`: the eight Semgrep rules and narrow
Trivy secret rule are platform-authored. No third-party commercial Semgrep rules are
downloaded. Trivy Dockerfile/Kubernetes checks are embedded in the pinned executable;
runtime check updates, dependency resolution, DB updates and network are disabled.
The DB bundle digest is a platform SHA256 of recorded file hashes, not a claim to be
the upstream OCI manifest digest. Prepared assets stay under ignored private `.local/`.

Preparation is an explicit network-enabled operation without target source or application
credentials. `python -m runner.prepare --reuse-database` rebuilds trusted images and
verifies/reuses the existing offline DB. Omitting that flag explicitly downloads a new
official DB asset, records new hashes and changes the registry. Coordinate API/worker
image rebuilds and repeat G5 before reopening admission. Existing accepted work remains
bound to its original registry; never silently retarget queued work to new policy.
DB age is checked from UpdatedAt and capped at 48 hours; missing/tampered/stale assets
fail closed. Do not edit hashes to accept changed bytes.

Primary references consulted for scanner-specific behavior:

- [Semgrep CLI](https://docs.semgrep.dev/cli-reference): fixed config, inline suppression,
  version-check and metrics flags. `--no-git-ignore` alone is insufficient to remove
  repository policy authority; the platform also constructs its controlled audit view.
- [Semgrep releases](https://github.com/semgrep/semgrep/releases): pinned version source.
- [Trivy filesystem CLI](https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/)
  and [filtering](https://trivy.dev/docs/latest/configuration/filtering/): offline and
  scanner selection flags, ignores and suppression behavior.
- [Trivy releases](https://github.com/aquasecurity/trivy/releases): executable version.

These references explain choices; the local JSON evidence records observed behavior.
Prepared local image IDs may differ on a clean rebuild. Verify and record a new
registry and rerun gates rather than assuming a tag reproduces the previous image ID.
