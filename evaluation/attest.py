"""Verify actual private scanner snapshots and attach source identity, no source export.

Supports adding this proof to observations captured before identity fields existed.
The scanner result, labels and actual source bytes are not changed or re-executed.
"""

import json
from uuid import uuid4

from ai_security_platform.snapshots.policy import digest
from ai_security_platform.snapshots.store import SnapshotStore
from evaluation.corpus import BASE, SYNTHETIC, load, materialize, scanner_metrics
from runner.boundary import ROOT


def main():
    manifest = load()
    path = BASE / "results/scanner-observations.json"
    report = json.loads(path.read_text())
    candidates = [
        p
        for p in (ROOT / ".local/phase4-evaluation").iterdir()
        if p.is_dir()
        and len(p.name) == 32
        and all((p / str(i) / "spool/published").is_dir() for i in range(2))
    ]
    candidates = [
        p
        for p in candidates
        if all(len(list((p / str(i) / "spool/published").iterdir())) == 28 for i in range(2))
    ]
    assert len(candidates) == 1, "Select an unambiguous complete original two-repetition spool"
    for repetition in range(2):
        store = SnapshotStore(candidates[0] / str(repetition) / "spool", require_readonly=False)
        snapshots = {}
        for directory in (store.root / "published").iterdir():
            raw = (directory / "manifest.json").read_bytes()
            snapshot = store.verify(directory.name, digest(raw))
            snapshots[snapshot.manifest.label.removeprefix("controlled-phase4-")] = snapshot
        for case in manifest["cases"]:
            actual = snapshots[case["id"]]
            expected = materialize(case, ROOT / ".cache" / ("phase4-attestation-" + uuid4().hex))
            assert {
                p.relative_to(expected).as_posix(): p.read_bytes()
                for p in expected.rglob("*")
                if p.is_file()
            } == actual.files
            for scanner in ("semgrep", "trivy"):
                record = report["repetitions"][repetition][case["id"]][scanner]
                assert all(
                    f["evidence"]["manifest_digest"] == actual.manifest_digest
                    for f in record["result"]["findings"]
                )
                record["source_identity"] = {
                    "content_digest": actual.manifest.content_digest,
                    "manifest_digest": actual.manifest_digest,
                }
    report["source_attestation"] = {
        "snapshots_verified": 56,
        "same_materialized_bytes": True,
        "source_exported": False,
        "line_endings": "explicit CRLF for synthetic secret slot; other fixture bytes unchanged",
    }
    report["baseline"] = scanner_metrics(manifest["cases"], report["repetitions"][0])
    text = json.dumps(report, indent=2) + "\n"
    assert SYNTHETIC not in text
    path.write_text(text, encoding="utf-8")
    print(
        json.dumps(
            {
                "actual_snapshots_verified": 56,
                "rebound_source_identity": "exact_bytes",
                "ungraded_binding_cases": 2,
            }
        )
    )


if __name__ == "__main__":
    main()
