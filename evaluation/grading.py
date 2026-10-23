"""Small explicit baseline rubric, separate from product structural validation.

This rubric checks the limited provider's conservative claims, not arbitrary prose
entailment. Ground-truth dispositions/evidence/guidance remain in the frozen manifest.
"""


def grade(case, assessment, source_citations, selected):
    expected = case["required_disposition_if_alerted"]
    disposition = assessment.assessment == expected
    summary = assessment.summary.lower()
    qualifiers = {
        "needs_review": ("reported risky construct", "exploitability remain unproven"),
        "likely_false_positive": ("fixed literal", "surrounding data flow"),
        "abstain": ("do not support", "reliable assessment"),
    }
    cautious_claim = all(term in summary for term in qualifiers[assessment.assessment])
    relevant_source = any(
        c.filepath == selected["filepath"]
        and c.start_line <= selected["start_line"] <= selected["end_line"] <= c.end_line
        for c in source_citations
    )
    recommendation = all(
        term in assessment.remediation.lower() for term in case["remediation_terms"]
    )
    return {
        "correct_disposition": disposition,
        "evidence_supported_conclusion": disposition and cautious_claim and relevant_source,
        "remediation_supported": recommendation,
        "unsupported_claims": int(not (disposition and cautious_claim and relevant_source)),
        "unsupported_recommendations": int(not recommendation),
    }
