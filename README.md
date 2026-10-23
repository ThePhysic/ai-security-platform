# AI Security Platform

Local security engineering and developer guardrails platform, prioritizing
1Password AppSec work, then Brain Co secure AI workflows and Prophet backend reliability.

**Status: Phase 3 implemented; see its completion report for G6 evidence.
Phase 4 requires separate authorization.**

Local immutable snapshot intake and durable PostgreSQL workers drive pinned Semgrep
and Trivy through a separate trusted Windows launcher and isolated scanner containers.
Real scan admission defaults to disabled and requires verified local isolation plus
a live launcher. Deterministic fake adapters remain available for diagnostics.
Bounded offline triage and revision-checked human review use independent durable jobs.
Hosted triage is disabled; only mocked provider transport has been validated.

- [Current triage/review setup and safe rollback](docs/phase3/RUNBOOK.md)
- [Phase 3 completion and G6 limitations](docs/phase3/COMPLETION-REPORT.md)
- [Agent boundaries, consent and API/schema contracts](docs/phase3/ARCHITECTURE-AND-CONTRACTS.md)
- [Real scanner workflow](docs/phase2b/RUNBOOK.md)
- [Phase 2B completion, gates and limitations](docs/phase2b/COMPLETION-REPORT.md)
- [Launcher and scanner security boundary](docs/phase2b/ARCHITECTURE.md)
- [API/schema changes](docs/phase2b/API-AND-SCHEMA.md)
- [Phase 2A historical snapshot workflow](docs/phase2a/RUNBOOK.md)
- [Phase 2A completion, gates and file inventory](docs/phase2a/COMPLETION-REPORT.md)
- [Phase 1 historical setup](docs/phase1/RUNBOOK.md)
- [Phase 1 completion report and file inventory](docs/phase1/COMPLETION-REPORT.md)
- [Sanitized live restart/container evidence](docs/phase1/validation-evidence.json)
- [Approved architecture](docs/phase0/02-ARCHITECTURE-AND-DECISIONS.md)
- [Phase 1 contract](docs/phase0/09-PHASE1-SPECIFICATION.md)
- [Project brief](docs/PROJECT_BRIEF.md)

Development API: loopback only at http://127.0.0.1:18081.
Credentials are generated into ignored local configuration;
never publish credentials or resolved Compose configuration.
