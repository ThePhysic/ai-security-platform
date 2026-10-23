"""Read-only evidence, with authority supplied by the request rather than the model."""

import time
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ai_security_platform.agent.contracts import (
    Citation,
    ContextArgs,
    EmptyArgs,
    Evidence,
    FindingArgs,
    SourceArgs,
    StrictModel,
    ToolCall,
)
from ai_security_platform.agent.policy import LIMITS, SECRET, AgentError, Limits, plain, redact
from ai_security_platform.agent.rules import catalog
from ai_security_platform.scanners.real import CWE_BY_RULE
from ai_security_platform.snapshots.policy import SnapshotError, canonical, digest
from ai_security_platform.snapshots.store import SnapshotStore, VerifiedSnapshot
from ai_security_platform.storage.models import Finding, ScannerRun, TriageRun

ARGUMENTS: dict[str, type[StrictModel]] = {
    "finding": FindingArgs,
    "source": SourceArgs,
    "rule": FindingArgs,
    "coverage": EmptyArgs,
    "context": ContextArgs,
}
GUIDANCE = {
    "platform.python.eval": (
        "Replace dynamic eval with a constrained parser or explicit allowlisted operations."
    ),
    "platform.javascript.eval": (
        "Replace dynamic eval with explicit parsing and allowlisted operations."
    ),
    "platform.python.shell": (
        "Avoid shell interpretation; use fixed executable arguments and validate inputs."
    ),
    "platform.javascript.exec": (
        "Avoid shell interpretation; use fixed executable arguments and validate inputs."
    ),
    "platform.python.sql-format": (
        "Use driver parameters for values and allowlist dynamic identifiers."
    ),
    "platform.javascript.sql-concat": (
        "Use driver parameters for values and allowlist dynamic identifiers."
    ),
    "platform.ci.write-all": "Grant only the explicit workflow permissions required by the job.",
    "platform.ci.mutable-action": (
        "Pin reviewed action dependencies to immutable commit references."
    ),
}


class EvidenceTools:
    def __init__(
        self,
        factory: sessionmaker[Session],
        store: SnapshotStore,
        triage_id: UUID,
        *,
        limits: Limits = LIMITS,
    ):
        self.factory, self.store, self.limits = factory, store, limits
        with factory() as session:
            run = session.get(TriageRun, triage_id)
            if run is None:
                raise AgentError("evidence_unavailable")
            self.finding_id, self.scan_id, self.snapshot_id = (
                run.finding_id,
                run.scan_run_id,
                run.snapshot_id,
            )
            self.manifest_digest = run.manifest_digest
            from ai_security_platform.storage.models import SourceSnapshot

            snapshot = session.get(SourceSnapshot, self.snapshot_id)
            if snapshot is None or snapshot.retention_state != "published":
                raise AgentError("evidence_unavailable")
            self.snapshot_key = snapshot.spool_key
        self.started, self.calls, self.context_bytes = time.monotonic(), 0, 0
        self.evidence: dict[str, Evidence] = {}
        self.trace: list[dict[str, Any]] = []
        self._source: VerifiedSnapshot | None = None

    def check_time(self) -> None:
        if time.monotonic() - self.started >= self.limits.seconds:
            raise AgentError("time_budget")

    def finding(self, session: Session, identifier: UUID) -> Finding:
        # Only this requested finding is readable by source/rule/finding tools.
        # Context is a separate fixed same-scan query with a maximum of five items.
        if identifier != self.finding_id:
            raise AgentError("tool_denied")
        value = session.scalar(
            select(Finding).where(Finding.id == identifier, Finding.scan_run_id == self.scan_id)
        )
        if value is None:
            raise AgentError("evidence_unavailable")
        if SECRET.search(value.filepath) or SECRET.search(value.rule_id):
            raise AgentError("confidentiality_denied")
        return value

    def source(self) -> VerifiedSnapshot:
        if self._source is None:
            try:
                self._source = self.store.verify(self.snapshot_key, self.manifest_digest)
            except (SnapshotError, OSError):
                raise AgentError("evidence_unavailable") from None
        return self._source

    def call(self, call: ToolCall) -> Evidence:
        self.check_time()
        if (
            self.calls >= self.limits.tool_calls
            or len(canonical(call.model_dump(mode="json"))) > 1024
        ):
            raise AgentError("tool_budget")
        self.calls += 1
        try:
            args = ARGUMENTS[call.name].model_validate(call.arguments)
        except (ValueError, KeyError):
            raise AgentError("tool_denied") from None
        with self.factory() as session:
            target = self.finding(session, self.finding_id)
            scanner = session.get(ScannerRun, target.scanner_run_id)
            if scanner is None:
                raise AgentError("evidence_unavailable")
            start, end = target.start_line, target.end_line
            data: dict[str, Any]
            if call.name == "finding":
                assert isinstance(args, FindingArgs)
                self.finding(session, args.finding_id)
                data = {
                    "id": str(target.id),
                    "rule_id": plain(target.rule_id),
                    "category": target.category,
                    "severity": target.severity,
                    "filepath": target.filepath,
                    "start_line": start,
                    "end_line": end,
                    "synthetic": target.synthetic,
                }
            elif call.name == "rule":
                assert isinstance(args, FindingArgs)
                self.finding(session, args.finding_id)
                try:
                    trusted = catalog()
                except (OSError, ValueError, KeyError):
                    raise AgentError("evidence_unavailable") from None
                data = {
                    "rule_id": plain(target.rule_id),
                    "guidance": GUIDANCE.get(
                        target.rule_id, "Insufficient trusted rule context; abstain."
                    ),
                    "cwe": CWE_BY_RULE.get(target.rule_id, "unknown"),
                    "policy_version": "guidance-1",
                    "provenance": dict(scanner.provenance),
                    "definition": trusted["definitions"].get(target.rule_id),
                    "catalog_digest": trusted["catalog_digest"],
                    "rule_source_sha256": trusted["source_rules_sha256"],
                    "historical_policy_matches": scanner.provenance.get("policy_digest")
                    == trusted["scanner_policy_digest"],
                }
            elif call.name == "coverage":
                data = {"status": scanner.status, "coverage": dict(scanner.coverage)}
            elif call.name == "context":
                assert isinstance(args, ContextArgs)
                rows = list(
                    session.scalars(
                        select(Finding)
                        .where(
                            Finding.scan_run_id == self.scan_id,
                            Finding.filepath == target.filepath,
                            Finding.id != self.finding_id,
                        )
                        .order_by(Finding.id)
                        .limit(args.limit)
                    )
                )
                data = {
                    "findings": [
                        {
                            "id": str(row.id),
                            "rule_id": plain(row.rule_id),
                            "category": row.category,
                            "start_line": row.start_line,
                            "end_line": row.end_line,
                        }
                        for row in rows
                    ]
                }
            else:
                assert isinstance(args, SourceArgs)
                self.finding(session, args.finding_id)
                if (
                    not (max(1, start - 5) <= args.start_line <= args.end_line <= end + 5)
                    or args.end_line - args.start_line + 1 > self.limits.lines
                ):
                    raise AgentError("tool_denied")
                # Verify bytes outside the DB session/connection below.
                data = {"redacted_secret_finding": target.category == "secret"}
                start, end = args.start_line, args.end_line
        if call.name == "source":
            source = self.source()
            raw = source.files.get(target.filepath)
            if raw is None:
                raise AgentError("evidence_unavailable")
            try:
                lines = raw.decode("utf-8", errors="strict").splitlines()
            except UnicodeError:
                raise AgentError("evidence_unavailable") from None
            if end > len(lines):
                raise AgentError("tool_denied")
            excerpt = "\n".join(lines[start - 1 : end])
            if len(excerpt.encode()) > self.limits.excerpt_bytes:
                raise AgentError("context_budget")
            data["text"] = (
                "[redacted secret location]" if data["redacted_secret_finding"] else redact(excerpt)
            )
        # Tool output is schema-validated, bounded data with references to exact scope.
        payload_digest = digest(canonical(data))
        citation = Citation(
            evidence_id=digest(
                canonical(
                    [
                        str(self.snapshot_id),
                        self.manifest_digest,
                        call.name,
                        target.filepath,
                        start,
                        end,
                        payload_digest,
                    ]
                )
            ),
            kind=call.name,
            snapshot_id=self.snapshot_id,
            manifest_digest=self.manifest_digest,
            filepath=target.filepath,
            start_line=start,
            end_line=end,
            content_digest=payload_digest,
        )
        response = Evidence(citation=citation, data=data)
        size = len(canonical(response.model_dump(mode="json")))
        if (
            size > self.limits.response_bytes
            or self.context_bytes + size > self.limits.context_bytes
        ):
            raise AgentError("context_budget")
        self.check_time()
        self.context_bytes += size
        self.evidence[citation.evidence_id] = response
        self.trace.append(
            {
                "sequence": self.calls,
                "tool": call.name,
                "response_bytes": size,
                "evidence_id": citation.evidence_id,
            }
        )
        return response
