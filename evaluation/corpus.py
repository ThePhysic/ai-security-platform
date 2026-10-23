"""Frozen labels and source-only fixture materialization, independent of observations."""

import hashlib
import json
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parent
SYNTHETIC = "AKIA" + "Q" * 16


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load():
    frozen = json.loads((BASE / "frozen-v1.json").read_text(encoding="utf-8"))
    for name, expected in frozen["files"].items():
        path = (BASE / name).resolve()
        assert path.is_relative_to(BASE) and not path.is_symlink()
        assert sha(path) == expected, (
            "Frozen corpus changed; version explicitly, never relabel scores"
        )
    manifest = json.loads((BASE / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["cases"]) == 28
    assert len({c["id"] for c in manifest["cases"]}) == 28
    assert {c["split"] for c in manifest["cases"]} == {"development", "held_out"}
    for split in ("development", "held_out"):
        assert sum(c["split"] == split for c in manifest["cases"]) == 14
    assert len({tuple(sorted(c["files_sha256"].values())) for c in manifest["cases"]}) == 28
    return manifest


def materialize(case, destination):
    """Copy bytes only; synthetic secret exists only in private disposable source."""
    shutil.copytree(BASE / "fixtures" / case["id"], destination)
    if case["id"] == "secret-positive":
        path = destination / "credentials.txt"
        # Preserve the Windows materialization used for both actual scanner runs,
        # explicitly on Linux too. Text-mode newline translation must not change
        # the source bytes when genuine findings are replayed for triage.
        content = path.read_text().replace("SYNTHETIC_CREDENTIAL_SLOT", SYNTHETIC)
        path.write_bytes(content.replace("\r\n", "\n").replace("\n", "\r\n").encode())
    return destination


def rule_id(case):
    # Historical Trivy KSV display IDs have differing zero padding. The approved
    # adapter preserves AVDID KSV-0001. Labels retain the originally frozen KSV-001.
    return "KSV-0001" if case["target_rule"] == "KSV-001" else case["target_rule"]


def matched(case, findings):
    return [f for f in findings if f["rule_id"] == rule_id(case)]


def label_eligible(case):
    # Preserve v1 frozen labels. KSV-0001 checks escalation, not privileged=true.
    # These two binding mistakes are explicitly ungraded, never counted as FP/FN.
    return case["category"] != "kubernetes-privilege"


def ratio(numerator, denominator):
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator if denominator else None,
    }


def scanner_metrics(cases, observations):
    metrics = {}
    for split in ("development", "held_out", "all"):
        counts = {
            k: 0
            for k in (
                "tp",
                "fp",
                "fn",
                "tn",
                "unsupported",
                "incomplete",
                "expected_detectability_matches",
                "labelled_units",
                "ungraded_label_binding",
            )
        }
        rows = []
        for case in cases:
            if split != "all" and case["split"] != split:
                continue
            observed = observations[case["id"]][case["scanner"]]
            found = bool(matched(case, observed["result"]["findings"]))
            counts["expected_detectability_matches"] += found == case["expected_detected"]
            if not label_eligible(case):
                counts["ungraded_label_binding"] += 1
                status = "ungraded_label_binding"
            elif not case["coverage_supported"]:
                counts["unsupported"] += 1
                status = "unsupported"
            elif not observed["result"]["complete"]:
                counts["incomplete"] += 1
                status = "incomplete_not_clean"
            else:
                positive = case["security_label"] == "weakness_present"
                status = (
                    "tp" if positive and found else "fn" if positive else "fp" if found else "tn"
                )
                counts[status] += 1
                counts["labelled_units"] += 1
            rows.append(
                {
                    "id": case["id"],
                    "status": status,
                    "detected": found,
                    "expected_detected": case["expected_detected"],
                    "incidental_unlabelled_alerts": len(observed["result"]["findings"])
                    - len(matched(case, observed["result"]["findings"])),
                }
            )
        metrics[split] = counts | {
            "precision": ratio(counts["tp"], counts["tp"] + counts["fp"]),
            "recall": ratio(counts["tp"], counts["tp"] + counts["fn"]),
            "cases": rows,
        }
    return metrics
