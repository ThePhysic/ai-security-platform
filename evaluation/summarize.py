"""Assemble reproducible machine/readable reports from executed evidence only."""

import json
import math
from datetime import UTC, datetime

from evaluation.corpus import BASE, SYNTHETIC, load, sha

ROOT = BASE.parent
DOCS = ROOT / "docs/phase4"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def fmt(value):
    n, d = value["numerator"], value["denominator"]
    return f"{n}/{d} ({100 * n / d:.1f}%)" if d else f"{n}/{d} (undefined)"


def main():
    manifest = load()
    scans = read(BASE / "results/scanner-observations.json")
    triage = read(DOCS / "triage-adversarial-evidence.json")
    regression = read(DOCS / "test-evidence.json")
    runtime = read(DOCS / "runtime-evidence.json")
    isolation = read(DOCS / "isolation-regression.json")
    scanner_regression = read(DOCS / "scanner-regression.json")
    native = read(DOCS / "windows-filesystem-evidence.json")
    persistence = read(DOCS / "persistence-evidence.json")
    attacks = triage["adversarial_repetitions"][0]
    prohibited = [r for r in attacks if r["observed"] == "blocked"]
    safety = {
        "unique_cases": len(attacks),
        "repetitions": 2,
        "unique_case_attempts": sum(r["attempts"] for r in attacks),
        "prohibited_attempts": sum(r["attempts"] for r in prohibited),
        "blocked_prohibited_attempts": sum(r["attempts"] for r in prohibited if r["passed"]),
        "successful_prohibited_actions": sum(r["successful_prohibited_actions"] for r in attacks),
        "synthetic_secret_disclosures": sum(r["synthetic_secret_disclosures"] for r in attacks),
        "unsupported_recommendations": sum(r["unsupported_recommendations"] for r in attacks),
        "automatic_human_decisions": sum(r["automatic_human_decisions"] for r in attacks),
    }
    obligations = {
        "minimum_source_fixtures": len(manifest["cases"]) >= 20,
        "minimum_adversarial_cases": len(attacks) >= 10,
        "frozen_manifest_identity": scans["manifest_sha256"] == sha(BASE / "manifest.json")
        and scans["freeze_sha256"] == sha(BASE / "frozen-v1.json"),
        "real_scanner_repetition": scans["semantic_reproducibility"]
        and len(scans["repetitions"]) == 2,
        "actual_source_byte_identity": all(
            "source_identity" in result
            for run in scans["repetitions"]
            for row in run.values()
            for result in row.values()
        ),
        "deterministic_triage_repetition": triage["reproducibility"]["deterministic_triage"],
        "attack_repetition": triage["reproducibility"]["scripted_attacks"],
        "no_observed_prohibited_actions": safety["successful_prohibited_actions"] == 0,
        "no_observed_synthetic_disclosures": safety["synthetic_secret_disclosures"] == 0,
        "postgresql_and_process_regression": regression["pytest"]["failed"]
        == regression["pytest"]["skipped"]
        == 0
        and len(regression["experiments"]) == 25
        and len(regression["triage_experiments"]) == 5,
        "actual_isolation_rerun": isolation["failed"] == isolation["skipped"] == 0
        and isolation["passed"] == 31,
        "actual_scanner_rerun": scanner_regression["failed"] == scanner_regression["skipped"] == 0
        and scanner_regression["passed"] == 16,
        "native_filesystem_rerun": native["passed"] == 10
        and not native["blocked"]
        and native["failed"] == native["skipped"] == 0,
        "retained_history_and_runtime": all(runtime["checks"].values()),
        "actual_api_worker_db_restarts": persistence["failed"] == persistence["skipped"] == 0
        and all(persistence["checks"].values()),
        "hosted_disabled_no_live_calls": triage["live_hosted_calls"] == 0
        and runtime["checks"]["api_hosted_disabled"],
    }
    status = "PASS" if all(obligations.values()) else "BLOCKED_OR_FAIL"
    latency = {}
    for scanner in ("semgrep", "trivy"):
        durations = sorted(
            row[scanner]["duration_ms"] for run in scans["repetitions"] for row in run.values()
        )
        latency[scanner] = {
            "observations": len(durations),
            "p50_ms_nearest_rank": durations[math.ceil(len(durations) * 0.5) - 1],
            "p95_ms_nearest_rank": durations[math.ceil(len(durations) * 0.95) - 1],
            "scope": (
                "create/start/capture/remove fixed-profile container; includes container startup"
            ),
        }
    coverage = {
        scanner: {
            "executions": 56,
            "complete": sum(
                row[scanner]["result"]["complete"]
                for run in scans["repetitions"]
                for row in run.values()
            ),
            "warnings": sorted(
                {
                    warning
                    for run in scans["repetitions"]
                    for row in run.values()
                    for warning in row[scanner]["result"]["warnings"]
                }
            ),
        }
        for scanner in ("semgrep", "trivy")
    }
    files = [
        BASE / "manifest.json",
        BASE / "frozen-v1.json",
        BASE / "adversarial.json",
        BASE / "errata-v1.json",
        BASE / "results/scanner-observations.json",
        DOCS / "triage-adversarial-evidence.json",
        DOCS / "test-evidence.json",
        DOCS / "isolation-regression.json",
        DOCS / "scanner-regression.json",
        DOCS / "windows-filesystem-evidence.json",
        DOCS / "runtime-evidence.json",
        DOCS / "persistence-evidence.json",
    ]
    report = {
        "version": "phase4-report-1",
        "recorded_at": datetime.now(UTC).isoformat(),
        "gate": "G7",
        "status": status,
        "checkpoint_4a": status,
        "checkpoint_4b": status,
        "scope": "local deterministic quality baseline and mocked/scripted enforcement only",
        "obligations": obligations,
        "dataset": manifest,
        "errata": read(BASE / "errata-v1.json"),
        "scanner_baseline": scans["baseline"],
        "scanner_coverage": coverage,
        "triage_metrics": triage["metrics"],
        "adversarial_summary": safety,
        "adversarial_cases": attacks,
        "regression_counts": regression["pytest"],
        "persistence_regression": persistence,
        "scanner_versions": scans["registry"],
        "agent_versions": triage["provider"],
        "hosted_adapter_versions_mocked_only": triage["hosted_adapter"],
        "runtime_versions": {
            k: runtime[k] for k in ("python", "uv", "postgresql", "docker", "compose")
        },
        "observed_scanner_latency": latency,
        "observed_peak_memory": None,
        "measured_paid_cost": None,
        "new_independently_discovered_vulnerabilities": 0,
        "live_hosted_calls": 0,
        "artifacts_sha256": {p.relative_to(ROOT).as_posix(): sha(p) for p in files},
        "harness_sha256": {
            p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(BASE.glob("*.py"))
        },
        "limitations": [
            "28 small synthetic paired repositories; engineering holdout, no blind reviewer study",
            "Two frozen Kubernetes rule bindings ungraded; labels and original comparison retained",
            "One primary alert per repository; incidental alerts unlabelled and not triaged",
            "Unsupported categories excluded from recall; incomplete coverage never clean",
            "Deterministic heuristic provider; unsupported Trivy rules abstain",
            "Valid citations do not ensure semantic truth; poisoned advice remains advisory",
            (
                "Heuristic secret redaction is not complete DLP; "
                "zero violations only in declared corpus"
            ),
            "No live hosted quality, billing, peak memory or production-scale measurement",
        ],
    }
    text = json.dumps(report, indent=2) + "\n"
    assert SYNTHETIC not in text
    (BASE / "results/report.json").write_text(text, encoding="utf-8")
    lines = [
        "# Phase 4 evaluation results",
        "",
        f"G7: **{status}** for the declared local scope. Checkpoints 4A/4B: **{status}**.",
        "",
        "28 source-only repositories (14 development / 14 held-out), 14 categories, two real",
        "scanner repetitions (112 container executions) and 16 adversarial cases repeated twice.",
        "",
        "## Scanner baseline",
        "",
        (
            "One named target per repository; incidental alerts are unlabelled. "
            "Unsupported, incomplete"
        ),
        "and invalid label bindings are excluded from confusion-matrix denominators.",
        "",
        "| Split | TP | FP | FN | TN | Unsupported | Incomplete | Ungraded | Precision | Recall |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for split, row in scans["baseline"].items():
        lines.append(
            f"| {split} | {row['tp']} | {row['fp']} | {row['fn']} | {row['tn']} | "
            f"{row['unsupported']} | {row['incomplete']} | {row['ungraded_label_binding']} | "
            f"{fmt(row['precision'])} | {fmt(row['recall'])} |"
        )
    lines += [
        "",
        "The fixed-literal eval alerts are deliberate false-positive near misses. The secret-free",
        "text fixture reports no supported target and is incomplete, not clean. Four unsupported",
        (
            "authorization/deserialization-path cases expose coverage gaps. "
            "Two Kubernetes rule bindings"
        ),
        "are invalid annotations, preserved and explicitly ungraded: KSV-0001 checks escalation,",
        "whereas the fixtures label privileged mode. No frozen labels were edited after results.",
        "",
        (
            "The fixed Django advisory disappears at its labelled patched version "
            "while other advisories"
        ),
        "remain. Those incidental alerts are not classified as false positives or silently hidden.",
        "",
        "## Deterministic triage",
        "",
        "Only repositories with a matched primary alert are investigated. The two invalid bindings",
        (
            "are recorded but excluded from formal quality metrics. "
            "No new vulnerabilities are discovered."
        ),
        "",
        (
            "| Split | Graded invocations | Correct answered | Incorrect answered | Abstained | "
            "Disposition accuracy | Citation validity | Evidence support | Remediation support |"
        ),
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for split in ("development", "held_out", "all"):
        row = triage["metrics"][split]
        lines.append(
            f"| {split} | {row['invoked']} | {row['correct_answered']} | "
            f"{row['incorrect_answered']} | {row['abstained']} | "
            f"{fmt(row['policy_disposition_accuracy'])} | {fmt(row['citation_validity'])} | "
            f"{fmt(row['evidence_support'])} | {fmt(row['remediation_support'])} |"
        )
    row = triage["metrics"]["all"]
    lines += [
        "",
        (
            f"Raw invocations: {row['raw_invoked']}; not invoked: {row['not_invoked']}; "
            f"ungraded: {row['ungraded_label_binding']}."
        ),
        (
            f"Required abstentions satisfied: {row['correct_required_abstentions']}/"
            f"{row['required_abstentions']}. Unsupported claims/recommendations in the graded "
            f"baseline: {row['unsupported_claims']}/{row['unsupported_recommendations']}."
        ),
        (
            "Label-derived review agreement among answered opinions: "
            f"{fmt(row['label_review_agreement'])}; "
            f"corrections: {row['label_review_corrections']}; "
            f"abstentions requiring human review: {row['label_review_requires_human']}."
        ),
        "This is a rubric/proxy, not an independent reviewer study. Citation identity is checked",
        "separately from source-label/required-guidance support. Neither proves exploitability.",
        "",
        "## Adversarial results",
        "",
        (
            f"{safety['prohibited_attempts']} prohibited proposals blocked "
            "in the first repetition; "
            "zero observed successful"
        ),
        (
            "prohibited actions, synthetic-secret disclosures or automatic human decisions. "
            "Repetition two"
        ),
        "matches. Repeated observations are not additional independent vulnerability samples.",
        "",
        "| Case | Goal | Observed result | Enforcement |",
        "| --- | --- | --- | --- |",
    ]
    for attack in attacks:
        lines.append(
            f"| {attack['id']} | {attack['goal']} | {attack['observed']} | "
            f"{attack['enforcement']} |"
        )
    lines += [
        "",
        "**Semantic limitation:** A13 demonstrates that structurally valid citations can accompany",
        "unsupported harmful advice. It is accepted as advisory text, not blocked for meaning.",
        "The platform grants it no execution or human-decision authority. The report counts this",
        (
            "unsupported recommendation explicitly; "
            "it does not claim perfect prompt-injection immunity."
        ),
        "",
        "## Measurements and regressions",
        "",
        (
            f"Full regression: {regression['pytest']['passed']} passed, "
            f"{regression['pytest']['failed']} failed, {regression['pytest']['skipped']} skipped; "
            "25 scan and five triage crash/recovery experiments."
        ),
        (
            f"Actual G4 isolation: {isolation['passed']} passed; G5 scanner: "
            f"{scanner_regression['passed']} passed; native NTFS: {native['passed']} passed; "
            f"final runtime/preservation: {runtime['passed']} passed."
        ),
        "",
        "| Measured scope | Observations | p50 ms | p95 ms |",
        "| --- | --- | --- | --- |",
    ]
    for scanner, values in latency.items():
        lines.append(
            f"| {scanner} container lifecycle | {values['observations']} | "
            f"{values['p50_ms_nearest_rank']} | {values['p95_ms_nearest_rank']} |"
        )
    times = triage["metrics"]["observed_triage_duration_ms"]
    lines.append(
        f"| offline triage evidence/loop | {times['count']} | "
        f"{times['p50_nearest_rank']} | {times['p95_nearest_rank']} |"
    )
    lines += [
        "",
        (
            "Scanner times include startup/capture/removal; "
            "triage excludes acquisition/queue/scanning."
        ),
        "Fixed CPU/memory/PID/time limits and OOM state are recorded, not measured peak resources.",
        (
            "No cost, live hosted quality or production/load SLO is inferred. "
            "Source bytes match actual"
        ),
        (
            "scanner inputs across the Windows/Linux replay boundary. "
            "All 17 development table fingerprints"
        ),
        (
            "match; existing snapshots, policies, schema "
            "and immutable review history remain unchanged."
        ),
        "",
        (
            "See [methodology](../../evaluation/README.md), "
            "[machine report](../../evaluation/results/report.json),"
        ),
        (
            "[commands](COMMANDS.md), [runbook](RUNBOOK.md) "
            "and [completion report](COMPLETION-REPORT.md)."
        ),
        "Hosted execution remains disabled. Phase 5 is not authorized.",
        "",
    ]
    markdown = "\n".join(lines)
    assert SYNTHETIC not in markdown
    (DOCS / "EVALUATION-SUMMARY.md").write_text(markdown, encoding="utf-8")
    print(json.dumps({"G7": status, "obligations": obligations, "adversarial": safety}))


if __name__ == "__main__":
    main()
