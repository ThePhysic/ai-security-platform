# AI Security Platform

Local security engineering and developer guardrails platform, prioritizing
1Password AppSec work, then Brain Co secure AI workflows and Prophet backend reliability.

**Status: Phase 1 foundation implemented and locally validated. Phase 2A is not authorized.**

The foundation provides five local HTTP contracts with authenticated data access,
explicit PostgreSQL migrations, safe request/logging boundaries and isolated tests.
It does not yet acquire source, submit scans, run workers/scanners, use AI or provide a UI.

- [Local setup, migrations, validation and safe rollback](docs/phase1/RUNBOOK.md)
- [Phase 1 completion report and file inventory](docs/phase1/COMPLETION-REPORT.md)
- [Sanitized live restart/container evidence](docs/phase1/validation-evidence.json)
- [Approved architecture](docs/phase0/02-ARCHITECTURE-AND-DECISIONS.md)
- [Phase 1 contract](docs/phase0/09-PHASE1-SPECIFICATION.md)
- [Project brief](docs/PROJECT_BRIEF.md)

Development API: loopback only at http://127.0.0.1:18081.
Credentials are generated into ignored local configuration;
never publish credentials or resolved Compose configuration.
