"""Explicit denominators and report serialization; no source text is exported."""

import math
from collections import Counter

from evaluation.corpus import ratio


def metrics(rows):
    result = {}
    for split in ("development", "held_out", "all"):
        selected = [r for r in rows if split == "all" or r["split"] == split]
        raw_invoked = [r for r in selected if r["invoked"]]
        invoked = [r for r in raw_invoked if r.get("label_eligible", True)]
        answered = [r for r in invoked if r["assessment"] != "abstain"]
        abstained = [r for r in invoked if r["assessment"] == "abstain"]
        result[split] = {
            "repositories": len(selected),
            "invoked": len(invoked),
            "raw_invoked": len(raw_invoked),
            "ungraded_label_binding": len(raw_invoked) - len(invoked),
            "not_invoked": len(selected) - len(raw_invoked),
            "correct_answered": sum(r["correct_disposition"] for r in answered),
            "incorrect_answered": sum(not r["correct_disposition"] for r in answered),
            "abstained": len(abstained),
            "required_abstentions": sum(r["expected_assessment"] == "abstain" for r in invoked),
            "correct_required_abstentions": sum(
                r["expected_assessment"] == "abstain" for r in abstained
            ),
            "unsupported_rule_invocations": sum(
                not r["supported_trusted_rule_family"] for r in invoked
            ),
            "unsupported_rule_abstentions": sum(
                not r["supported_trusted_rule_family"] for r in abstained
            ),
            "policy_disposition_accuracy": ratio(
                sum(r["correct_disposition"] for r in invoked), len(invoked)
            ),
            "answered_accuracy": ratio(
                sum(r["correct_disposition"] for r in answered), len(answered)
            ),
            "abstention_rate": ratio(len(abstained), len(invoked)),
            "citation_validity": ratio(
                sum(r["citation_identity_valid"] for r in invoked), len(invoked)
            ),
            "evidence_support": ratio(
                sum(r["evidence_supported_conclusion"] for r in invoked), len(invoked)
            ),
            "remediation_support": ratio(
                sum(r["remediation_supported"] for r in invoked), len(invoked)
            ),
            "unsupported_claims": sum(r["unsupported_claims"] for r in invoked),
            "unsupported_recommendations": sum(r["unsupported_recommendations"] for r in invoked),
            "label_review_agreement": ratio(
                sum(r["review_feedback"] == "agree" for r in answered), len(answered)
            ),
            "label_review_corrections": sum(r["review_feedback"] == "disagree" for r in invoked),
            "label_review_requires_human": sum(
                r["review_feedback"] == "uncertain" for r in invoked
            ),
            "categories": dict(
                Counter(
                    (r["category"] + ":" + (r.get("assessment") or "not_invoked")) for r in selected
                )
            ),
        }
    categories = {}
    for category in sorted({r["category"] for r in rows}):
        selected = [r for r in rows if r["category"] == category]
        invoked = [r for r in selected if r["invoked"] and r.get("label_eligible", True)]
        answered = [r for r in invoked if r["assessment"] != "abstain"]
        categories[category] = {
            "repositories": len(selected),
            "graded_invocations": len(invoked),
            "answered_accuracy": ratio(
                sum(r["correct_disposition"] for r in answered), len(answered)
            ),
            "abstained": sum(r["assessment"] == "abstain" for r in invoked),
            "not_invoked": sum(not r["invoked"] for r in selected),
            "ungraded": sum(r["invoked"] and not r.get("label_eligible", True) for r in selected),
            "evidence_support": ratio(
                sum(r["evidence_supported_conclusion"] for r in invoked), len(invoked)
            ),
            "remediation_support": ratio(
                sum(r["remediation_supported"] for r in invoked), len(invoked)
            ),
        }
    result["per_category"] = categories
    durations = sorted(r["duration_ms"] for r in rows if r["invoked"])
    result["observed_triage_duration_ms"] = {
        "count": len(durations),
        "p50_nearest_rank": durations[math.ceil(len(durations) * 0.5) - 1],
        "p95_nearest_rank": durations[math.ceil(len(durations) * 0.95) - 1],
        "includes": (
            "local evidence/loop only; excludes acquisition, queue wait and real scanner time"
        ),
    }
    return result


def stable_rows(rows):
    # Durations are observations, never part of deterministic equivalence. Identity
    # hashes/UUIDs differ when source is reacquired; evidence validity is checked each run.
    return [
        {
            k: v
            for k, v in row.items()
            if k not in {"duration_ms", "token_upper_bound", "context_bytes"}
        }
        for row in rows
    ]
