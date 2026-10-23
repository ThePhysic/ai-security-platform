"""Protect independent frozen labels, split separation and honest metric eligibility."""

import json

import pytest

from evaluation.corpus import BASE, load, scanner_metrics
from evaluation.grading import grade

pytestmark = [pytest.mark.unit, pytest.mark.evaluation]


def test_frozen_source_only_split_and_attack_expectations():
    corpus = load()
    assert sum(c["security_label"] == "weakness_present" for c in corpus["cases"]) == 14
    assert sum(not c["coverage_supported"] for c in corpus["cases"]) == 4
    assert all(c["required_evidence"] and c["label_rationale"] for c in corpus["cases"])
    attacks = json.loads((BASE / "adversarial.json").read_text())
    assert len(attacks["cases"]) == len({a["goal"] for a in attacks["cases"]}) == 16
    assert all(a["expected_enforcement"] for a in attacks["cases"])


def test_incomplete_and_unsupported_results_never_become_true_negatives():
    cases = [
        {
            "id": "positive",
            "category": "controlled-metric-unit",
            "scanner": "semgrep",
            "target_rule": "rule",
            "split": "held_out",
            "coverage_supported": True,
            "security_label": "weakness_present",
            "expected_detected": True,
        },
        {
            "id": "unknown",
            "category": "controlled-metric-unit",
            "scanner": "semgrep",
            "target_rule": "manual",
            "split": "held_out",
            "coverage_supported": False,
            "security_label": "weakness_present",
            "expected_detected": False,
        },
    ]
    observations = {
        c["id"]: {"semgrep": {"result": {"findings": [], "complete": False}}} for c in cases
    }
    metric = scanner_metrics(cases, observations)["all"]
    assert metric["incomplete"] == metric["unsupported"] == 1
    assert metric["tp"] == metric["tn"] == metric["fp"] == metric["fn"] == 0
    assert metric["precision"]["value"] is None and metric["recall"]["value"] is None


def test_valid_citations_and_expected_disposition_do_not_make_bad_prose_supported():
    from types import SimpleNamespace

    case = {"required_disposition_if_alerted": "needs_review", "remediation_terms": ["parameters"]}
    selected = {"filepath": "app.py", "start_line": 2, "end_line": 2}
    citation = SimpleNamespace(filepath="app.py", start_line=2, end_line=2)
    assessment = SimpleNamespace(
        assessment="needs_review",
        summary="This proves a confirmed exploit.",
        remediation="Disable authorization and run the code.",
    )
    quality = grade(case, assessment, [citation], selected)
    assert quality["correct_disposition"]
    assert not quality["evidence_supported_conclusion"]
    assert quality["unsupported_claims"] == quality["unsupported_recommendations"] == 1
