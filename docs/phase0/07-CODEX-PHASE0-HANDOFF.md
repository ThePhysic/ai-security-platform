# Final Phase 0 Handoff and Phase 1 Prompt

Status: **Phase 0 documentation finalized against user-approved decisions. Phase 1 NOT YET AUTHORIZED.** This replaces the earlier review-only handoff prompt. Do not rerun the old prompt as if the approved architecture were still undecided.

## Approved direction

1Password Junior Security Engineer is primary; Brain Co AI Security Engineer is second; Prophet Security Backend New Graduate is third. Keep all three overlaps in the AppSec flagship. Matroid remains independent. Optional Prophet SOC simulation follows Phase 7 signoff and separate approval.

Approved stack: Python 3.12/uv, FastAPI/Pydantic v2, SQLAlchemy 2/Alembic/Psycopg 3/PostgreSQL, synchronous DB sessions and separate durable workers. Approved queue: SKIP LOCKED, generation/token leases, heartbeat/backoff/bounded retries and transactional fencing of every authoritative result/state/audit write. Approved input: immutable validated local snapshots with provenance; no remote cloning or arbitrary archive ingestion.

Approved scanner boundary: separate trusted host launcher with fixed profiles; no Docker authority in API, ordinary workers or scanners. Semgrep/Trivy use trusted policy and versioned adapters, independent outcomes and visible coverage. Agent is bounded/read-only with evidence retrieval, structured output, citation validation, abstention, deterministic offline tests and separately opt-in hosted provider. Local auth, Origin/Host restrictions, sanitized logs, scoped hosted consent and optimistic human review are mandatory.

No default Redis/Celery/Kubernetes/vector DB/SIEM/automatic remediation. Minimal React/TypeScript/Vite UI follows backend/evaluation gates.

## Evidence and blocking disposition

| Gate | Due | Current status |
|---|---|---|
| G1 foundation/runtime/auth/migrations | Phase 1 | OPEN — VALIDATION REQUIRED |
| G2 queue/fencing/recovery | Phase 2A | OPEN — VALIDATION REQUIRED |
| G3 immutable snapshot intake | Phase 2A | OPEN — VALIDATION REQUIRED |
| G4 host launcher/isolation | Phase 2B before untrusted scanning | OPEN — VALIDATION REQUIRED; controlled-fixture fallback only |
| G5 real scanners/policy/coverage | Phase 2B | OPEN — VALIDATION REQUIRED |
| G6 agent/consent/review/initial safety | Phase 3 | OPEN — VALIDATION REQUIRED |
| G7 expanded adversarial/quality evaluation | Phase 4 | OPEN — VALIDATION REQUIRED |
| G8 CI/reporting/load/recovery | Phase 5 | OPEN — VALIDATION REQUIRED |
| G9 dashboard/browser safety | Phase 6 | OPEN — VALIDATION REQUIRED |
| G10 hardening/rebuild/restore | Phase 7 | OPEN — VALIDATION REQUIRED |

No unresolved architecture decision genuinely blocks scoped Phase 1. Explicit implementation authorization is still absent. Actual dependency resolution and local PostgreSQL/Compose execution are untested prerequisites to completing G1. Prior WSL status was access denied; CLI presence does not prove daemon readiness. G2/G3/G4 are later blocking gates for their capabilities, not prerequisites to creating the foundation.

Top residual risks: scanner/launcher containment, stale publication, snapshot mutation/escape, repository-controlled suppression, confidential-data transmission, incomplete coverage, dependency compatibility and scope. Owners/mitigations are in [02](02-ARCHITECTURE-AND-DECISIONS.md); tests are in [06](06-EVALUATION-AND-RELIABILITY.md).

## Phase 0 go/no-go checklist

- [x] User-approved decisions recorded separately from open validation evidence.
- [x] Role order, mandatory flagship scope, optional SOC and separate Matroid boundaries reconciled.
- [x] Schema/API/security contracts, dependencies, acceptance tests and rollback plans documented.
- [x] Phase 1 files, explicit exclusions, tests and completion criteria specified in [09](09-PHASE1-SPECIFICATION.md).
- [ ] Explicitly authorize Phase 1 implementation and the required local dependency/service validation scope.
- [ ] Execute G1 checks during that separately authorized phase; no implementation gate passed during Phase 0.

Recommendation: ready for a separate Phase 1 authorization. Do not implement merely because the planning documents are finalized. Current finalization permits edits only to `docs/phase0/` and no install/service/Git/remote operations.

## Ready-to-paste Phase 1 Codex prompt — NOT YET AUTHORIZED

The draft below is inert planning text. Only a later explicit user instruction authorizing Phase 1 activates the implementation scope; it cannot override sandbox/approval requirements or authorize remote writes.

```text
Implement Phase 1 ONLY for C:\Users\ridle\ai-security-platform.

Authorization boundary: this is a draft until I explicitly authorize Phase 1.
Once authorized, perform the project-local dependency resolution/installation
and project-scoped API/PostgreSQL/test service execution needed for Phase 1,
subject to the execution environment's approval requirements. Do not provision
cloud resources, publish, commit, push, deploy, activate remote workflows, or
change any other project's services/data.

Read local AGENTS.md, docs/PROJECT_BRIEF.md, all docs/phase0/ documents, and
README.md. Use docs/phase0/09-PHASE1-SPECIFICATION.md as the exact Phase 1
contract, docs/phase0/03-DATA-API-AND-WORKFLOW.md for shared contracts, and
docs/phase0/02-ARCHITECTURE-AND-DECISIONS.md for approved ADRs. Preserve the
role order: 1Password, Brain Co, Prophet Security.

Use Python 3.12, uv, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, Psycopg 3
and PostgreSQL. Start with synchronous sessions/DB handlers; asynchronous
jobs belong to separate durable workers in Phase 2A.

Deliver only the Phase 1 files/modules and endpoints in specification 09:
- Locked runtime/dev dependencies, app factory and typed settings.
- Local bearer auth, exact Origin/Host controls and loopback host publication.
- Safe structured logs, bounded request IDs and sanitized error envelopes.
- Explicit Alembic migration for projects, snapshot metadata, scan metadata
  and audit events; synchronous request/session lifecycle.
- Coarse /health and DB/schema /ready, project create/get, read-only scan get.
- Non-root API image, local DB and separate disposable PostgreSQL test profile.
- Unit/API/real-PostgreSQL tests, lint/type checks, local CI definition and runbook.

Do not expose scan POST or snapshot registration before durable acceptance
exists in Phase 2A. Do not seed fake production scans/findings. Use test-only
metadata factories to verify scan persistence/read contracts.

Do not implement workers, queues, snapshot acquisition, Docker launcher,
Semgrep/Trivy, agent/provider tools, reviews, remediation, SARIF/upload,
React/Node UI, SOC extension or Matroid changes. Do not add Redis, Celery,
Kubernetes, a vector DB or new infrastructure. Never execute target-repository
code or expose Docker authority to the API/test application.

Never modify, stage, print the contents of, or commit local AGENTS.md.
Preserve existing unrelated changes; never git add all. Keep all remote writes,
commits/pushes/deployments outside this task. Use only explicitly disposable
test resources for downgrade/cleanup; preserve ordinary developer data.

Run and report G1 checks from specification 09: locked install, Ruff/mypy,
unit/API/PostgreSQL checks, migration fresh/head/disposable reversal,
DB/schema unavailable readiness, transactional project/audit writes,
actual API/DB restart persistence without deleting volumes, local network
restrictions and synthetic-secret non-disclosure across errors/logs.

Do not silently skip required infrastructure checks or claim passed checks
that were blocked. Report exact files, versions, commands, pass/fail/skip
counts, design deviations, security limitations, rollback evidence and the
Phase 2A handoff. Stop after Phase 1; do not continue without new authorization.
```
