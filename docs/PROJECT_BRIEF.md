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

## Next step
Phase 0: architecture, threat modeling, technical choices,
interfaces, scope boundaries and implementation plans.
