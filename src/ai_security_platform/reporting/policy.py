"""Only scanner facts affect deterministic policy. Incomplete required checks win."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ai_security_platform.snapshots.policy import canonical, digest

SEVERITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: Literal[1] = 1
    required_scanners: list[Literal["semgrep", "trivy", "fake-patterns", "fake-config"]] = Field(
        default=["semgrep", "trivy"], min_length=1, max_length=4
    )
    fail_at: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    allow_synthetic: bool = False


def evaluate(report: dict[str, Any], policy: Policy) -> dict[str, Any]:
    stages = {row["scanner_id"]: row for row in report["scan"]["scanner_runs"]}
    incomplete = []
    for name in sorted(set(policy.required_scanners)):
        row = stages.get(name)
        if (
            row is None
            or row["status"] != "succeeded"
            or row["coverage"].get("complete_execution") is not True
            or row["coverage"].get("warnings")
            or row["coverage"].get("unavailable")
            or row["coverage"].get("warning_count", 0)
            or (row["synthetic"] and not policy.allow_synthetic)
        ):
            incomplete.append(name)
    unknown = any(r["severity"] not in SEVERITY for r in report["findings"])
    failures = sum(
        SEVERITY.get(r["severity"], -1) >= SEVERITY[policy.fail_at] for r in report["findings"]
    )
    diagnostic_rejected = (
        any(r["synthetic"] for r in report["findings"]) and not policy.allow_synthetic
    )
    code = (
        2
        if incomplete
        or diagnostic_rejected
        or unknown
        or report["scan"]["status"] not in {"succeeded", "partial"}
        else 1
        if failures
        else 0
    )
    return {
        "policy_version": 1,
        "policy_digest": digest(canonical(policy.model_dump())),
        "exit_code": code,
        "incomplete_required_scanners": incomplete,
        "unknown_severity": unknown,
        "threshold_findings": failures,
        "synthetic_diagnostic": policy.allow_synthetic,
        "ai_opinions_applied": False,
        "security_guarantee": False,
    }
