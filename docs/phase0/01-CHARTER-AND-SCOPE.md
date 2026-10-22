# Product Charter and Scope

Status: **APPROVED planning baseline; implementation NOT YET AUTHORIZED.**

## Product

A local-first AppSec platform that acquires authorized local source as immutable, validated snapshots, treats their contents as untrusted, runs bounded scanners and supports normalized findings, evidence-grounded read-only AI investigation and human review. It demonstrates secure developer workflows and reliable Python backend engineering without becoming a SOC product.

Authorization to acquire a repository does not make files, configuration, filenames or scanner output safe. The default model provider is deterministic and offline; hosted transmission is separately opt-in.

## Role alignment

| Priority | Role | Portfolio evidence |
|---|---|---|
| 1 | 1Password Junior Security Engineer | Secure SDLC, developer remediation guidance, secrets/privacy controls, risk metrics, agent safety and CI guardrails |
| 2 | Brain Co AI Security Engineer | Bounded AI workflows, evidence retrieval, structured outputs, adversarial/quality evaluations and developer/CI guardrails |
| 3 | Prophet Security Backend New Graduate | Durable PostgreSQL jobs, integrations, indexed history, provenance, observability, recovery and human feedback |

Backend and AI depth belong in the AppSec flagship. They do not require a second product or additional infrastructure.

## Mandatory requirements

| ID | Requirement | First complete gate |
|---|---|---|
| R01 | Local authentication, restricted origins/hosts, sanitized logs and DB lifecycle | Phase 1 |
| R02 | Immutable snapshot intake with provenance; no API host paths, remote clone or arbitrary archives | Phase 2A |
| R03 | Durable acceptance, idempotency, fenced job ownership, bounded retries and recovery | Phase 2A |
| R04 | Versioned Semgrep/Trivy adapters, trusted policies, per-scanner outcomes and coverage | Phase 2B |
| R05 | Normalized findings, occurrence identity, evidence, provenance, filters and JSON export | Phase 2B |
| R06 | Bounded agentic retrieval, structured results, validated citations, abstention and initial safety tests | Phase 3 |
| R07 | Human dispositions, notes, optimistic concurrency and immutable revisions | Phase 3 |
| R08 | At least 20 labelled fixtures and 10 adversarial cases with repeatable evaluation | Phase 4 |
| R09 | Complete CLI, least-privilege CI, JSON/SARIF, policy exit codes and reliability/load evidence | Phase 5 |
| R10 | Minimal accessible dashboard using persisted data and honest metrics | Phase 6 |
| R11 | Clean rebuild, retention/cleanup, recovery/restore, final threat review and factual demo | Phase 7 |

Safety tests begin with the capability they protect. Minimal snapshot/submit/query CLI and cursor pagination begin in Phase 2A; Phase 5 completes the workflow. Human dispositions are `confirmed`, `false_positive`, `investigate`, `accepted_risk`, `remediation_planned`. AI classifications never automatically become human dispositions or change code.

## Demonstration and milestones

1. Operator publishes an authorized local snapshot; provenance and scope exclusions are visible.
2. API returns 202 only after scan, scanner work and jobs commit durably together.
3. Workers recover after interruption; restricted scanner execution produces independent outcomes.
4. Reviewer inspects findings, coverage, source evidence and tool/rule/database versions.
5. Agent retrieves finding and source/context evidence, recommends a reviewable response or abstains.
6. Human records a revision-checked disposition; reporting preserves scanner evidence.
7. Show benchmark limitations, adversarial tests and measured recovery.

| Milestone | Gate |
|---|---|
| M0 | Approved Phase 0 documented; implementation separately authorized |
| M1 | Phase 2B: scanner MVP without LLM; restricted fixture mode disclosed if isolation gate remains open |
| M2 | Phase 3: working bounded agent and human review |
| M3 | Phase 5: evaluated developer integration and reliability |
| M4 | Phase 7: complete flagship within declared trust mode |
| M5 (optional) | Separately authorized Phase 8 synthetic SOC simulation after M4 |

## Scope limits

- No execution, building, installation, package-manager hooks or plugins from target repositories.
- No unsandboxed scanning of untrusted repositories and no bypass when isolation is unavailable.
- No server-side remote cloning, arbitrary archive upload or remote acquisition service in the MVP. CI scans an explicitly authorized local checkout in its own isolated run.
- No unrestricted model shell/network/write tools, automatic patches, autonomous pull requests or remediation deployment.
- No default Redis, Celery, Kubernetes, vector database, DAG engine, SIEM, enterprise integrations or live cloud scanning.
- No public hosting, enterprise RBAC or multi-tenant claim. Project IDs are not tenant isolation.
- DAST is outside the flagship and is not a hidden completion requirement.
- Queue/concurrency tests require real PostgreSQL; SQLite cannot substitute for its locking semantics.
- JSON/SARIF export is mandatory. GitHub upload depends on eligibility, configuration and explicit approval; artifacts are the fallback.

## Independent work

Phase 8 is optional after Phase 7 signoff and separate authorization: synthetic events, distinct event/investigation schema, a few fixed correlations, evidence timelines and feedback. It must be independently removable. No live SIEM or enterprise connectors.

The completed Matroid Visual Inspection Platform remains a separate AppSec audit/hardening case study. Follow [08](08-MATROID-SECURITY-AUDIT.md); do not rewrite it, import its application code or add a SOC pipeline.
