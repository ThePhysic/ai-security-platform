# Frozen local security evaluation, version 1

This corpus measures the existing AppSec scanner and bounded triage baseline. It is
not a general vulnerability benchmark or a hosted-model quality claim. Phase 4 adds
evaluation code only; product rules, providers, tools, schema and job semantics remain
unchanged. The primary portfolio focus is 1Password AppSec; agent evaluation and durable
reproducibility preserve the Brain Co and Prophet overlap.

## Labels, provenance and split

[manifest.json](manifest.json) contains **28 first-party synthetic source-only repository
fixtures** across 14 categories. Each category has one target weakness and one clean or
contextually benign counterpart. Independent fields describe source semantics, scanner
detectability, expected triage/abstention, evidence requirements, reviewer disposition,
remediation and limitations. These labels were authored from code semantics and explicit
trust assumptions before observations, not copied from scanner or agent outputs.

The SQL examples distinguish statement interpolation/concatenation from driver binding.
Execution examples distinguish caller-controlled evaluation/shell interpretation from
fixed literals or fixed executable argument lists. Configuration labels concern a
specific permission, not a demonstrated exploit. Authorization and deserialization/path
cases expose gaps in the current eight-rule SAST policy; a lack of alerts on these is
**unsupported coverage**, not evidence of safety.

Dependency labels target named historical advisories rather than every possible issue.
Django's [upstream security release](https://www.djangoproject.com/weblog/2023/jul/03/security-releases/)
documents the CVE-2023-36053 fix in 4.2.3. Minimist's
[upstream changelog](https://github.com/minimistjs/minimist/blob/main/CHANGELOG.md) and
[advisory](https://github.com/advisories/GHSA-xvch-5gv4-984h) establish the historical
prototype-pollution fix. No dependency is downloaded or installed by evaluation.
A version fixed for the target advisory can still have other vulnerabilities.

There are **14 development and 14 held-out repositories**, with a fixed alternating
category/polarity assignment. [frozen-v1.json](frozen-v1.json) pins every label, split,
attack expectation and source file before the first scanner run. Its SHA256 is
`5db395bc7091f8e5796c6b287a95a1da84b8e6edfc4675e2de6efb6897775845`.
Neither labels nor product behavior are tuned after held-out observations. Paired
fixtures share concepts; this is an engineering holdout, not a blind independent
reviewer study, an unseen-category split or proof against training contamination.
Do not relabel v1 to improve scores. A justified correction requires a separately
versioned corpus and an explicit comparison retaining prior results.

The original frozen KSV-001 label was resolved to KSV-0001. Investigation of the unexpected
negative-fixture alert established that this is the wrong semantic rule binding:
[KSV-0017](https://avd.aquasec.com/misconfig/kubernetes/general/avd-ksv-0017/) checks privileged
containers, while KSV-0001 checks privilege escalation. [errata-v1.json](errata-v1.json)
preserves the original labels and observations and excludes both affected fixtures from
formal quality metrics. It does not turn a real escalation alert into a false positive
for another property. A separately versioned future correction is recommended. All other
target identities match exactly. The remaining supported/complete formal units exceed 20.

## Units and denominators

Scanner precision/recall use **one named target per repository**, restricted to declared
supported and complete executions. True/false positive labels refer to that target's
security behavior. Broad eval rules intentionally alert on two fixed-literal near misses.
Incomplete and unsupported cases are separate counters, never true negatives. Other
alerts are unlabelled incidental findings, not automatically false positives. Each
partition has its own counts and explicit numerator/denominator, including null ratios
when a denominator is zero.

Triage investigates one primary matched alert per repository, selected by stable path,
line and occurrence ordering. No alert means `not_invoked`, not a correct answer or
an agent abstention. Unsupported Trivy rules should abstain. Report correct/incorrect
answered opinions separately from abstentions and from conformance to required abstention.
The agent discovers no new findings here; it cannot improve scanner discovery recall.

Evidence grading has two layers: production citation identity/snapshot/range validation,
and a case-specific conclusion/remediation check against frozen semantic labels,
relevant source ranges, conservative uncertainty qualifiers and required guidance terms.
An expected disposition with valid citations but overconfident/unsupported prose fails
this independent grading check. Report the layers separately. The latter is a small rubric,
not a general natural-language entailment judge or proof of exploitability. Reviewer
agreement/correction is a **label-derived proxy**, persisted only in disposable test
history, not measured agreement among real security reviewers.

## Execution and confidentiality

Run from the workspace root with the accepted Windows/Docker Desktop boundary:

```powershell
uv run python -m runner.validate_isolation --phase4
uv run python -m runner.validate_scanners --phase4
uv run python -m evaluation.scan
uv run python scripts/validate_phase4.py
```

Scanner preparation/assets and immutable profiles remain unchanged. The host-only
harness holds the existing exclusive launcher lock and uses the same approved fixed
profiles, offline databases, no-network containers and output normalization. It never
enables public real-scan admission or runs a fixture script/build/package hook. Two
repetitions use independent 28-snapshot private spools within the existing 32-snapshot
quota. No production quota is raised and no old spool is deleted.

Only the secret-positive private fixture copy receives an unusable synthetic key-shaped
value. The checked-in fixture contains a slot. Raw scanner output stays transient;
only bounded normalized metadata, counts, hashes, versions and timings reach reports.
No source excerpts, secrets, model prompts or provider traces are exported.

PostgreSQL evaluation replays genuine normalized scanner outputs through evaluation-only
metadata factories, re-acquiring the same source bytes in Linux and rebinding evidence
to the locally verified manifest. It uses real `EvidenceTools`, `investigate`, durable
triage claim/reservation/publication and review storage. It is not a production scan
acceptance bypass or a claim that fixture factories ran scanners. Actual scanners run
in the preceding host step. Missing scanner observations fail rather than skip the test.

Sixteen [adversarial cases](adversarial.json) make explicit scripted malicious proposals
through production schema/tool/citation/lease checks. The deterministic baseline also
retrieves injected comments as untrusted evidence. Mocked hosted wire tests measure
enforcement, not model susceptibility or hosted reasoning. No live hosted request,
paid use, API credential or external source transmission is permitted.

The remediation-poisoning case deliberately measures whether valid citations can carry
bad advice. Advice that passes structural validation is reported as unsupported; the
test checks that it gains no execution or human-review authority. Zero observed prohibited
actions/disclosures is limited to these cases, not a universal guarantee.

Two scanner and triage/attack repetitions establish semantic reproducibility. Random
snapshot/DB identities, evidence hashes tied to them, DB age and observed timings are
not expected to match byte-for-byte. Report timing only where measured; resource limits
and OOM state are observed configuration/state, not peak-memory measurements. Offline
token reservations are bounds, not actual model usage or bills.
