# Project Brief

## Purpose
Build a portfolio-quality AI-powered security engineering
platform, prioritizing 1Password Junior Security Engineer
while supporting other AppSec, AI security and DevSecOps roles.

## Planned capabilities
- Static application security analysis
- Dependency, secrets and selected IaC/CI security checks
- Common finding model across scanner adapters
- Read-only agentic investigation and triage
- Evidence-backed remediation recommendations
- Agent safety and adversarial evaluations
- CLI, GitHub Actions, SARIF and developer reporting
- Lightweight security dashboard

## Security requirements
Treat analyzed repositories and scanner outputs as untrusted.
Do not execute arbitrary scanned repository code.
Do not expose credentials to AI models or reports.
Keep automated modifications behind human approval.

## Deferred
Autonomous patch deployment, full SOC/SIEM,
live cloud scanning and large-scale infrastructure.

## Companion project
A separate AppSec Audit and Hardening case study will
use the completed Matroid Visual Inspection Platform.

## Current state
Phase 7 completes the local flagship within the documented G10/M4 trust and validation
scope. See [the final completion report](phase7/COMPLETION-REPORT.md),
[operations runbook](phase7/RUNBOOK.md) and [threat model](phase7/THREAT-MODEL.md).
Real scanning and hosted AI remain disabled by default. The separately authorized
[optional Phase 8](phase8/COMPLETION-REPORT.md) adds bounded synthetic identity/IAM
ingestion and deterministic investigation; it is disabled by default and independently
removable. AppSec remains the primary product. The separate Matroid audit still requires
authorization; no public deployment or live SOC integration is implied.
