# AI Security Platform

Local security engineering and developer guardrails platform, prioritizing
1Password AppSec work, then Brain Co secure AI workflows and Prophet backend reliability.

**Status: Phase 2A complete; G2/G3 passed local validation. Phase 2B is not authorized.**

Local snapshot intake and durable PostgreSQL workers extend the authenticated foundation.
Only deterministic synthetic marker adapters are available. Real scanners, scanner
launchers, AI, review and a UI require later authorization.

- [Current setup, snapshot workflow and safe rollback](docs/phase2a/RUNBOOK.md)
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
