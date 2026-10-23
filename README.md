# AI Security Platform

Local security engineering and developer guardrails platform, prioritizing
1Password AppSec work, then Brain Co secure AI workflows and Prophet backend reliability.

**Status: Phase 7 implemented; G10/M4 pass for the documented local scope.
Optional Phase 8 and the separate Matroid audit require their own authorization.**

Local immutable snapshot intake and durable PostgreSQL workers drive pinned Semgrep
and Trivy through a separate trusted Windows launcher and isolated scanner containers.
Real scan admission defaults to disabled and requires verified local isolation plus
a live launcher. Deterministic fake adapters remain available for diagnostics.
Bounded offline triage and revision-checked human review use independent durable jobs.
Hosted triage is disabled; only mocked provider transport has been validated.
The frozen offline benchmark preserves annotation errata, unsupported coverage and
advisory-quality limitations alongside measured results.

- [Final local quick start, maintenance and rollback](docs/phase7/RUNBOOK.md)
- [Phase 7 completion and G10/M4 evidence](docs/phase7/COMPLETION-REPORT.md)
- [Final architecture and trust boundaries](docs/phase7/ARCHITECTURE.md)
- [Final threat review and findings](docs/phase7/THREAT-MODEL.md)
- [Private matched backup/restore and retention](docs/phase7/RETENTION-AND-RECOVERY.md)
- [Controlled demonstration](docs/phase7/DEMONSTRATION.md)
- [Factual portfolio statements and limitations](docs/phase7/PORTFOLIO.md)
- [Phase 6 dashboard start, authentication and rollback](docs/phase6/RUNBOOK.md)
- [Phase 6 completion and G9 evidence](docs/phase6/COMPLETION-REPORT.md)
- [Phase 6 browser architecture and contracts](docs/phase6/ARCHITECTURE-AND-CONTRACTS.md)
- [Phase 5 developer workflow and rollback](docs/phase5/RUNBOOK.md)
- [Phase 5 completion, G8 and file inventory](docs/phase5/COMPLETION-REPORT.md)
- [Phase 5 measured reliability and performance](docs/phase5/PERFORMANCE.md)
- [Current triage/review setup and safe rollback](docs/phase3/RUNBOOK.md)
- [Phase 4 evaluation results and limitations](docs/phase4/EVALUATION-SUMMARY.md)
- [Phase 4 completion and G7 evidence](docs/phase4/COMPLETION-REPORT.md)
- [Versioned corpus and evaluation methodology](evaluation/README.md)
- [Evaluation reproduction and rollback](docs/phase4/RUNBOOK.md)
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

Dashboard: http://127.0.0.1:18082 (local operator token, memory only).

## Local quick start

Use Docker Desktop Linux containers and the existing private operator configuration.
The runbook covers first-time credential generation, explicit migrations and recovery.
Existing users can verify frozen dependencies and start only this project:

```powershell
uv sync --frozen
docker compose -p asp-phase1-dev --profile workers --profile triage up -d --wait --no-build api worker triage-worker
Push-Location web
npm.cmd ci --ignore-scripts --no-audit
npm.cmd run dev
Pop-Location
```

Use the exact loopback addresses above. Real scanning and hosted AI remain disabled by
default. For the dashboard, enter the operator token privately; it is held only in memory.
The controlled demo and detailed setup commands are in the Phase 7 runbook. Backups and
snapshots stay private; never include local state in a review package.

Static scanners have false positives and coverage gaps. Deterministic offline triage
supports limited rule families and makes no independent vulnerability-discovery claim.
A13 unsupported advisory remediation and two ungraded Kubernetes bindings remain visible.
Human verification is required. This local project is not a production deployment or
third-party security certification.
