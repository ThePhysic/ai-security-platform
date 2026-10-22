# Phase 0 — Approved Planning Baseline

Status: **Phase 0 documentation finalized. Architecture approved by the user; Phase 1 implementation NOT YET AUTHORIZED.**
Date: 2026-10-22 (America/Los_Angeles).
Repository: `ThePhysic/ai-security-platform`; workspace: `C:\Users\ridle\ai-security-platform`.

## Authority and priorities

The user's approved architecture and scope supersede the earlier draft and review recommendations. Local `AGENTS.md` and `docs/PROJECT_BRIEF.md` remain governing instructions. Design approval does not establish implementation feasibility or authorize implementation, installations, services, commits, remote writes or deployment.

1. **1Password Junior Security Engineer:** primary AppSec product; secure SDLC, developer tooling, secrets handling, risk metrics and agent safety.
2. **Brain Co AI Security Engineer:** secure AI workflows, evaluations, developer and CI/CD guardrails.
3. **Prophet Security Backend New Graduate:** durable jobs, integrations, indexed history, observability and failure recovery.
4. Other security-engineering relevance is secondary. The completed Matroid Visual Inspection Platform remains a separate audit companion.

These priorities describe intended portfolio evidence, not verification of current employer job postings.

## Document map and ownership

| Document | Owns |
|---|---|
| [01 — Charter](01-CHARTER-AND-SCOPE.md) | Requirements, exclusions, role alignment and milestones |
| [02 — Architecture and ADRs](02-ARCHITECTURE-AND-DECISIONS.md) | Approved choices, modules, feasibility gates and architectural risks |
| [03 — Data/API/workflow](03-DATA-API-AND-WORKFLOW.md) | Schema, transactions, source protocol, adapters and HTTP contracts |
| [04 — Threat model](04-THREAT-MODEL.md) | Trust boundaries, credential/data flow and security proof obligations |
| [05 — Phases](05-PHASES-AND-ACCEPTANCE.md) | Dependencies, ownership, acceptance and rollback; optional Phase 8 |
| [06 — Evaluation/reliability](06-EVALUATION-AND-RELIABILITY.md) | Test IDs, failure matrix, measurements and proposed commands |
| [07 — Handoff](07-CODEX-PHASE0-HANDOFF.md) | Finalization status and ready-to-paste Phase 1 prompt, NOT YET AUTHORIZED |
| [08 — Matroid](08-MATROID-SECURITY-AUDIT.md) | Independent audit plan, without authorization to edit that repository |
| [09 — Phase 1 specification](09-PHASE1-SPECIFICATION.md) | Exact Phase 1 files, contracts, exclusions, tests and completion criteria |

Read 01–06, then 09 and 07 before implementation. Read 08 for companion scope only. Resolve contract changes in their owning document and propagate references; avoid competing specifications.

## Status vocabulary

- **APPROVED:** user-approved architecture/scope; no implication of executed validation.
- **OPEN — VALIDATION REQUIRED:** evidence remains due at the named implementation gate.
- **DEFERRED:** outside the mandatory flagship or excluded from the MVP.
- **NOT YET AUTHORIZED:** implementation needs explicit user authorization for the assigned phase.

No implementation gate is passed in this baseline. PostgreSQL orchestration is approved but untested (Phase 2A). Windows/Docker Desktop scanner isolation is approved but unvalidated (Phase 2B).

## Phase 0 disposition

No unresolved architecture choice blocks scoped Phase 1. Explicit Phase 1 authorization is still required. Dependency resolution, PostgreSQL image selection and runtime checks are Phase 1 tasks; inability to validate them prevents declaring that phase complete.

Snapshot safety and job fencing must pass Phase 2A before real scanner integration. Isolation must pass Phase 2B before untrusted scanning. If it cannot be validated, permit only approved controlled fixtures and fail closed for other inputs; disclose restricted mode in reports and demonstrations.

Local single-user portfolio scope: no comprehensive detection, production security certification, enterprise tenancy, arbitrary code execution, autonomous remediation or production SOC claims. Phase 8 requires Phase 7 signoff and separate authorization, and is independently removable.

All finalization edits are planning Markdown under `docs/phase0/`. Root README status is known to be stale but remains untouched under this edit restriction. Keep local `AGENTS.md` unchanged, ignored, unstaged and untracked.
