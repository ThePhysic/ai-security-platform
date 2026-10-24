# AI Security Engineering Platform

**An application security and developer guardrails platform combining automated vulnerability scanning, isolated execution, evidence-grounded AI triage, and human security review.**

Built with **Python, FastAPI, PostgreSQL, React, TypeScript, Docker, Semgrep, and Trivy**, the platform provides a local, end-to-end security workflow—from analyzing source repositories and investigating findings to reviewing remediation guidance and generating developer-facing reports.

It emphasizes secure software development, fault-tolerant backend orchestration, least-privilege execution, and measurable security evaluation.

**Status:** Core platform complete (Phases 0–7, G10/M4 accepted within documented local scope). An optional synthetic SOC investigation extension (Phase 8) is also complete and disabled by default.

## Key Features

### Application Security Scanning
- Integrates **Semgrep and Trivy** for static code analysis, vulnerable dependencies, secrets, and selected infrastructure/CI configuration checks.
- Executes scanners in restricted, disposable Docker containers through a separate trusted launcher.
- Enforces trusted scanner policies, non-root execution, network isolation, resource limits, and bounded output.
- Normalizes findings with severity, source references, scanner provenance, and explicit coverage limitations.

### Agentic AI Security Triage
- Implements a bounded, read-only investigation agent with structured tool calls and scoped evidence retrieval.
- Validates source citations against retrieved evidence and supports explicit abstention when evidence is insufficient.
- Enforces tool authorization, execution budgets, and confidentiality controls outside the language model.
- Supports deterministic offline investigations and a separately gated hosted-provider adapter.
- Keeps AI remediation guidance advisory and subject to human verification.

### Durable Backend & Developer Workflows
- Uses **FastAPI and PostgreSQL** for authenticated APIs, persisted security findings, and searchable scan history.
- Supports durable asynchronous jobs, idempotent submission, lease fencing, retries, and crash recovery.
- Provides a developer CLI, sanitized JSON/SARIF exports, deterministic security-policy exit codes, and GitHub Actions integration.
- Preserves successful scanner results independently of AI-provider failures.

### Security Dashboard & Human Review
- React/TypeScript interface for scan history, finding filters, scanner coverage, and evidence inspection.
- Explicitly initiated AI investigations with visible uncertainty and advisory remediation guidance.
- Human review dispositions, immutable revision history, and optimistic concurrency conflict handling.
- Memory-only operator authentication and safe rendering of untrusted repository content.

## Architecture

The platform separates its API, durable execution, privileged scanner launching, AI investigation, and human-review responsibilities.

| Component | Technologies | Responsibility |
|---|---|---|
| Developer interface | React, TypeScript, Python CLI | Scan workflows, results, review, reporting |
| Backend API | FastAPI, Pydantic | Authentication, validation, scan and review contracts |
| Persistence | PostgreSQL, SQLAlchemy, Alembic | Durable jobs, findings, history, audit records |
| Job execution | PostgreSQL-backed workers | Leases, retries, idempotency, crash recovery |
| Scanner execution | Docker, Semgrep, Trivy | Restricted analysis using trusted policies |
| AI investigation | Python tool-calling agent | Scoped evidence retrieval and bounded triage |
| Developer integration | GitHub Actions, SARIF | Offline CI artifacts and policy feedback |

The trusted Windows launcher controls disposable scanner containers. The API, application workers, and scanner containers do not receive Docker daemon authority.

**Architecture details:** [System Architecture & Trust Boundaries](docs/phase7/ARCHITECTURE.md) | [Threat Model](docs/phase7/THREAT-MODEL.md)

## Security Evaluation

The platform includes a versioned, reproducible evaluation framework measuring scanner detection, AI triage quality, evidence support, and resistance to adversarial inputs.

| Evaluation | Recorded result |
|---|---|
| Labelled security fixtures | 28, divided into 14 development and 14 held-out cases |
| Adversarial scenarios | 16 distinct cases |
| Scanner precision | 11/13 (84.6%) on the eligible primary-target subset |
| Scanner recall | 11/11 (100%) on the same eligible subset |
| Agent safety | Zero observed unauthorized actions or synthetic-secret disclosures in the tested corpus |
| Crash/recovery experiments | 25 scan and 5 triage experiments passed |

**Evaluation limitations:** Scanner metrics apply only to the declared eligible fixture subset, not arbitrary repositories. Unsupported cases, incomplete coverage, two Kubernetes annotation-binding errors, and an unsupported remediation recommendation remain documented. Valid citations do not guarantee that remediation advice is semantically correct.

The deterministic offline agent is a limited evaluation baseline, not a general-purpose vulnerability reasoning model. No independent vulnerability-discovery improvement or live hosted-model quality is claimed.

[Full Evaluation Results](docs/phase4/EVALUATION-SUMMARY.md) | [Dataset & Reproduction](evaluation/README.md)

## Reliability & Recovery

The backend uses PostgreSQL-backed orchestration to maintain authoritative job state across interruptions.

Implemented controls include:

- Atomic job acceptance and idempotent request handling.
- Transaction-fenced publication of findings and audit events.
- Lease ownership, attempt generations, controlled retries, and stale-worker rejection.
- Independent scanner and triage lifecycles with explicit partial/incomplete outcomes.
- Matched PostgreSQL and source-snapshot backup/restore, reference-aware retention, and controlled cleanup.

Local validation includes worker interruption, database restart, scanner failure, and triage-provider failure experiments.

Performance testing measured synthetic workloads with 1, 2, and 4 workers, alongside separate genuine scanner runs. These measurements describe controlled local conditions rather than production capacity.

[Performance Measurements](docs/phase5/PERFORMANCE.md) | [Recovery & Retention](docs/phase7/RETENTION-AND-RECOVERY.md)

## Optional SOC Investigation Extension

A separately scoped extension demonstrates backend security-event investigation workflows relevant to security operations engineering.

It supports:

- Two synthetic event-source formats covering identity authentication and cloud IAM activity.
- Validated ingestion, canonical normalization, database-enforced idempotency, and historical queries.
- Two deterministic event-correlation rules.
- Evidence-linked investigation timelines, analyst dispositions, and revision-controlled feedback.
- Duplicate replay, out-of-order processing, and recovery testing.

The SOC module uses a separate database schema and remains **disabled by default**. The original application-security platform operates independently.

The extension uses controlled synthetic events, not live enterprise telemetry, and is not intended to function as a general-purpose SIEM.

[Phase 8 Completion & Limitations](docs/phase8/COMPLETION-REPORT.md) | [SOC Operation & Recovery](docs/phase8/RUNBOOK.md)

## Getting Started

### Prerequisites

- Windows with Docker Desktop configured for Linux containers
- Python 3.12 and uv
- Node.js and npm for local dashboard development
- Locally generated operator configuration and credentials

The platform runs locally. PostgreSQL and internal services are not intended for public network exposure.

**New installations:** Follow the [Final Setup & Operations Runbook](docs/phase7/RUNBOOK.md) for credential generation, dependency installation, image preparation, database migrations, and service startup.

### Existing Configured Environments

For an environment with initialized credentials, prepared images, and existing project configuration:

```powershell
uv sync --frozen

docker compose -p asp-phase1-dev --profile workers --profile triage up -d --wait --no-build api worker triage-worker

Push-Location web
npm.cmd ci --ignore-scripts --no-audit
npm.cmd run dev
Pop-Location
```

**Local endpoints:**

- API: `http://127.0.0.1:18081`
- Dashboard: `http://127.0.0.1:18082`

The dashboard requires an operator token, supplied privately and retained only in browser application memory.

Real scanner admission and hosted AI execution remain disabled by default. Follow the approved runbooks for controlled scanning and isolation checks. Do not enable hosted transmission without understanding the confidentiality and consent requirements.

[Controlled Demonstration](docs/phase7/DEMONSTRATION.md) | [Complete Operations Runbook](docs/phase7/RUNBOOK.md)

## Documentation

| Area | Documentation |
|---|---|
| Architecture | [System Design](docs/phase7/ARCHITECTURE.md) |
| Security boundaries | [Threat Model & Findings](docs/phase7/THREAT-MODEL.md) |
| Scanner isolation | [Launcher & Scanner Architecture](docs/phase2b/ARCHITECTURE.md) |
| Agent security | [Triage, Consent & Review Contracts](docs/phase3/ARCHITECTURE-AND-CONTRACTS.md) |
| Evaluation | [Security Evaluation Summary](docs/phase4/EVALUATION-SUMMARY.md) |
| Reliability | [Performance & Recovery](docs/phase5/PERFORMANCE.md) |
| Developer operations | [Quick Start, Backup & Rollback](docs/phase7/RUNBOOK.md) |
| Final implementation | [Phase 7 Completion Report](docs/phase7/COMPLETION-REPORT.md) |
| SOC extension | [Phase 8 Completion Report](docs/phase8/COMPLETION-REPORT.md) |
| Portfolio evidence | [Engineering Accomplishments & Limitations](docs/phase7/PORTFOLIO.md) |

Detailed implementation decisions and milestone-specific validation reports are retained in `docs/phase0/` through `docs/phase8/`.

## Related Project

**[Visual Inspection Platform — Application Security Audit & Hardening](https://github.com/ThePhysic/visual-inspection-platform/blob/main/docs/security/README.md)**

A complementary security assessment of a full-stack image inspection system, covering API and browser-origin boundaries, secure uploads, worker reliability, dependency analysis, Docker/CI hardening, and verified before-and-after security controls.

This separate project demonstrates practical application-security assessment and remediation, complementing the security tooling developed here.

## Scope & Limitations

This is a **locally validated security engineering portfolio project**, not a publicly deployed production security service.

Its guarantees are restricted to the documented trust model, selected scanner configurations, controlled datasets, and tested environments.

Important limitations include:

- Static scanners have false positives, unsupported vulnerability categories, and coverage gaps.
- Hosted model transport was validated through mocks; live hosted calls and external-source transmission were not tested.
- AI-generated remediation advice requires independent human verification.
- Security evaluations use finite synthetic datasets and do not establish universal resistance to adversarial inputs.
- Browser validation is primarily Chromium-based.
- The SOC extension processes synthetic security events only.
- CI includes controlled offline artifact workflows, not a claim of deployed automated scanning on arbitrary pull requests.

Local snapshots, private backups, generated credentials, and operator-specific configuration must never be committed or published.

See the [Final Threat Model](docs/phase7/THREAT-MODEL.md), [Evaluation Summary](docs/phase4/EVALUATION-SUMMARY.md), and [Final Completion Report](docs/phase7/COMPLETION-REPORT.md) for detailed evidence and outstanding limitations.
