# Evidence-supported portfolio statements

Primary emphasis: AppSec developer guardrails and security automation for a Junior Security
Engineer. Secure AI workflows and reliable backend processing support the same product.
These statements describe observed work, not employer endorsement or production adoption.

## Résumé-ready examples

- Built a local AppSec platform integrating isolated, digest-pinned Semgrep/Trivy with
  immutable source provenance, normalized findings, JSON/SARIF and deterministic CI policy.
- Implemented PostgreSQL SKIP LOCKED orchestration with lease tokens, attempt generations,
  independent heartbeats and transaction-fenced findings/status/audit publication; validated
  25 scan crash/retry and five triage recovery scenarios using independent processes.
- Built bounded read-only security investigation with server-scoped evidence tools, validated
  citations, explicit abstention, hosted-consent controls and optimistic human-review history.
- Evaluated 28 labelled source-only fixtures with a 14/14 development/held-out split and
  16 adversarial cases; documented unsupported coverage, false positives and unsafe advisory
  semantics instead of claiming universal prompt-injection resistance.
- Delivered a memory-authenticated React dashboard for scanner coverage, explicit offline
  triage and revision-checked human review, tested through actual Chromium/API/PostgreSQL
  workflows alongside separately labelled hostile/failure simulations.
- Implemented reference-aware retention and private matched DB/source recovery, validating
  all 18 table fingerprints and associated snapshots, corruption rejection and actual
  transactional restore interruption/rollback/retry in isolated PostgreSQL destinations.
- Closed an isolated Python build-lock gap with six version/hash constraints and demonstrated
  an uncached application rebuild plus byte-matching compiled dashboard artifacts.

Tailor these for space; cite [validation](VALIDATION.md) and [the file inventory](FILES.md).
Do not turn scanner alerts into confirmed vulnerabilities or conditional benchmark accuracy
into an unrestricted claim about AI reasoning.

## Quantitative context

The frozen [Phase 4 results](../phase4/EVALUATION-SUMMARY.md) remain unchanged: graded scanner
TP=11, FP=2, FN=0, TN=8; precision 11/13 and recall 11/11 **within the declared supported
denominator**. Four unsupported cases, one incomplete case and two ungraded Kubernetes
bindings are excluded explicitly. The agent's 13 graded invocations include nine answered
and four abstained assessments; it discovered no additional vulnerabilities.

The adversarial corpus observed zero successful prohibited actions or synthetic-secret
disclosures, while A13 accepted an unsupported recommendation as advisory text. Repetitions
are reproducibility checks, not new independent security samples or a certification.

The [Phase 5 performance report](../phase5/PERFORMANCE.md) measured 72 diagnostic scans,
144 jobs and 15,120 synthetic findings with 1/2/4 workers. Its genuine 200-file scanner
workload had three sequential scan observations and 85 alerts each. Phase 7 reruns the
fixed workload as regression evidence; changed local timings are not improvements or
production capacity. Query plans and actual measured p50/p95 remain linked in the evidence.

The Phase 7 controlled demo produced 86 genuine alerts from a different maintained fixture.
Do not compare 85 and 86 as a detection improvement: the inputs differ. The final test
counts include overlapping native/browser/backend suites and must not be summed into
an inflated unique security-case total.

## Boundaries to explain in interviews

This is a single-operator, loopback-only portfolio system. PostgreSQL/Docker/host/browser
administrators are trusted. There are no live hosted-model quality results, enterprise
tenancy, automatic remediation, public production deployment or third-party security
certification. Backup digests establish integrity against a trusted receipt; they are
not digital signatures. Historical source is conservatively retained and quotas can stop
intake. Full disclosure is in the [final threat model](THREAT-MODEL.md).

Optional Phase 8 SOC work and the separate Matroid audit remain unimplemented and require
their own authorization. They are not prerequisites for this flagship's local completion.
