"""Disposable PostgreSQL replay of genuine normalized outputs into the real triage loop.

This is evaluation-only fixture plumbing, not a production scan acceptance shortcut.
Source is reacquired inside Linux and evidence is rebound to its verified manifest.
"""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy.orm import Session

from ai_security_platform.agent.contracts import ReviewWrite, TriageSubmission
from ai_security_platform.agent.engine import investigate, validate_assessment
from ai_security_platform.agent.providers import DeterministicProvider, OpenAIProvider
from ai_security_platform.agent.tools import GUIDANCE, EvidenceTools
from ai_security_platform.jobs.triage import TriageController
from ai_security_platform.snapshots.store import SnapshotStore
from ai_security_platform.storage.models import (
    Finding,
    Job,
    JobAttempt,
    Project,
    Review,
    ScannerRun,
    ScanRun,
    SourceSnapshot,
)
from ai_security_platform.storage.session import session_factory
from ai_security_platform.storage.triage import accept_triage, write_review
from evaluation.corpus import SYNTHETIC, label_eligible, matched, materialize
from evaluation.grading import grade


def metadata(engine, store, directory, case, record, *, transform=None):
    source = materialize(case, directory)
    if transform is not None:
        transform(source)
    snapshot = store.create(source, label="controlled-evaluation-" + case["id"])
    if transform is None:
        assert all(
            observed["source_identity"]["content_digest"] == snapshot.manifest.content_digest
            for observed in record.values()
        ), "Actual scanner source differs from triage source"
    now = datetime.now(UTC)
    ids = {}
    with Session(engine, expire_on_commit=False) as session, session.begin():
        project = Project(name="Disposable labelled evaluation " + case["id"])
        session.add(project)
        session.flush()
        source = SourceSnapshot(
            project_id=project.id,
            spool_key=snapshot.manifest.snapshot_key,
            manifest_version=1,
            manifest_digest=snapshot.manifest_digest,
            content_digest=snapshot.manifest.content_digest,
            inclusion_policy_digest=snapshot.manifest.policy_digest,
            provenance_kind="local_cli",
            provenance_label="evaluation-only-real-output-replay",
            file_count=len(snapshot.files),
            byte_count=sum(map(len, snapshot.files.values())),
            verified=True,
        )
        session.add(source)
        session.flush()
        scan = ScanRun(
            project_id=project.id,
            snapshot_id=source.id,
            profile_id="evaluation-replay-real-1",
            profile_digest="a" * 64,
            status="succeeded"
            if all(r["result"]["complete"] for r in record.values())
            else "partial",
            created_at=now,
            started_at=now,
            completed_at=now,
        )
        session.add(scan)
        session.flush()
        for scanner_id, observed in record.items():
            result = observed["result"]
            scanner = ScannerRun(
                scan_run_id=scan.id,
                scanner_id=scanner_id,
                adapter_version="real-1",
                status="succeeded",
                coverage={"complete_execution": result["complete"], "warnings": result["warnings"]},
                provenance=result["provenance"],
            )
            session.add(scanner)
            session.flush()
            job = Job(
                scanner_run_id=scanner.id,
                state="succeeded",
                generation=1,
                attempts=1,
                request_id="evaluation_replay",
            )
            session.add(job)
            session.flush()
            session.add(
                JobAttempt(
                    job_id=job.id,
                    generation=1,
                    worker_id=uuid4(),
                    outcome="succeeded",
                    started_at=now,
                    completed_at=now,
                )
            )
            session.flush()
            for item in result["findings"]:
                value = dict(item)
                value["evidence"] = dict(value["evidence"]) | {
                    "manifest_digest": snapshot.manifest_digest
                }
                finding = Finding(
                    scan_run_id=scan.id,
                    scanner_run_id=scanner.id,
                    job_id=job.id,
                    attempt_generation=1,
                    **value,
                )
                session.add(finding)
                session.flush()
                ids[(scanner_id, item["occurrence_key"])] = finding.id
        return scan.id, ids


def accept(controller, finding_id):
    with controller.factory() as session:
        return accept_triage(
            session,
            controller.settings,
            finding_id,
            TriageSubmission(),
            uuid4().hex,
            "evaluation_triage",
        )


def assess(engine, settings, store, finding_id):
    controller = TriageController(session_factory(engine), settings)
    run = accept(controller, finding_id)
    lease = controller.claim()
    assert lease is not None and lease.triage_run_id == run.id
    tools = EvidenceTools(controller.factory, store, run.id)
    outcome = investigate(
        DeterministicProvider(),
        tools,
        lambda seq, cost, tokens: controller.authorize(lease, seq, cost, tokens),
    )
    validate_assessment(outcome.assessment, tools)
    provider_shape = OpenAIProvider(lambda *_: b"not sent").payload(
        str(finding_id), list(tools.evidence.values())
    )
    assert SYNTHETIC.encode() not in provider_shape
    assert SYNTHETIC not in outcome.assessment.model_dump_json() and SYNTHETIC not in str(
        outcome.trace
    )
    controller.finish_triage(lease, outcome, tools)
    with controller.factory() as session:
        assert session.get(Review, finding_id) is None
    return run, outcome, tools


def benchmark(engine, settings, directory, cases, observations):
    rows = []
    store = SnapshotStore(directory / "spool", require_readonly=False)
    for case in cases:
        scan_id, ids = metadata(
            engine, store, directory / uuid4().hex, case, observations[case["id"]]
        )
        targets = matched(case, observations[case["id"]][case["scanner"]]["result"]["findings"])
        if not targets:
            rows.append(
                {
                    "id": case["id"],
                    "split": case["split"],
                    "category": case["category"],
                    "invoked": False,
                    "reason": "no_primary_scanner_finding",
                }
            )
            continue
        # One primary alert per labelled repository is the declared sampling unit.
        selected = sorted(
            targets, key=lambda f: (f["filepath"], f["start_line"], f["occurrence_key"])
        )[0]
        finding_id = ids[(case["scanner"], selected["occurrence_key"])]
        run, outcome, tools = assess(engine, settings, store, finding_id)
        assessment = outcome.assessment
        expected = case["required_disposition_if_alerted"]
        verdict = {"needs_review": "confirmed", "likely_false_positive": "false_positive"}.get(
            assessment.assessment
        )
        supported = assessment.assessment == expected
        source = tools.source()
        valid = all(
            c.manifest_digest == source.manifest_digest
            and c.filepath in source.files
            and 1 <= c.start_line <= c.end_line <= len(source.files[c.filepath].splitlines())
            for c in assessment.citations
        )
        assert valid
        quality = grade(
            case, assessment, [c for c in assessment.citations if c.kind == "source"], selected
        )
        feedback = (
            "uncertain"
            if verdict is None
            else "agree"
            if verdict == case["reviewer_disposition"]
            else "disagree"
        )
        with Session(engine, expire_on_commit=False) as session:
            write_review(
                session,
                finding_id,
                ReviewWrite(
                    expected_revision=0,
                    disposition=case["reviewer_disposition"],
                    note=(
                        "Label-derived evaluation decision; "
                        "not an independent human reviewer study."
                    ),
                    triage_run_id=run.id,
                    feedback=feedback,
                ),
                "evaluation_review",
            )
        with Session(engine) as session:
            assert session.get(ScanRun, scan_id).status in {"succeeded", "partial"}
        rows.append(
            {
                "id": case["id"],
                "split": case["split"],
                "category": case["category"],
                "invoked": True,
                "label_eligible": label_eligible(case),
                "assessment": assessment.assessment,
                "expected_assessment": expected,
                "rule_id": selected["rule_id"],
                "reason": assessment.reason,
                "supported_trusted_rule_family": selected["rule_id"] in GUIDANCE,
                "correct_disposition": supported,
                "citation_identity_valid": valid,
                "citations": len(assessment.citations),
                **quality,
                "reviewer_proxy": case["reviewer_disposition"],
                "review_feedback": feedback,
                "duration_ms": outcome.usage["duration_ms"],
                "tool_calls": outcome.usage["tool_calls"],
                "provider_calls": outcome.usage["provider_calls"],
                "context_bytes": outcome.usage["context_bytes"],
                "token_upper_bound": outcome.usage["token_upper_bound"],
                "billing_measured": False,
            }
        )
    return rows
