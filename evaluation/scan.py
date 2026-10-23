"""Host-only evaluation through the accepted trusted launcher. No API admission change."""

import json
import time
from datetime import UTC, datetime
from uuid import uuid4

from ai_security_platform.scanners.real import normalize
from ai_security_platform.snapshots.policy import canonical
from ai_security_platform.snapshots.store import SnapshotStore
from evaluation.corpus import BASE, SYNTHETIC, load, materialize, scanner_metrics, sha
from runner.boundary import ROOT, DockerBoundary, Invocation
from runner.launcher import Launcher, exclusive_launcher


def semantic(result):
    return {
        "complete": result["complete"],
        "warnings": result["warnings"],
        "files_scanned": result["files_scanned"],
        "findings": sorted(
            [
                {
                    k: f[k]
                    for k in (
                        "rule_id",
                        "category",
                        "severity",
                        "filepath",
                        "start_line",
                        "end_line",
                    )
                }
                | {"evidence": {k: v for k, v in f["evidence"].items() if k != "manifest_digest"}}
                for f in result["findings"]
            ],
            key=lambda f: canonical(f),
        ),
    }


def main():
    manifest = load()
    output = BASE / "results"
    output.mkdir(exist_ok=True)
    with exclusive_launcher():
        launcher = Launcher(
            "http://127.0.0.1:18081", ROOT / ".local/phase4-evaluation/spool", "unused"
        )
        assert not launcher.boundary.command(
            "ps", "-aq", "--filter", "label=ai-security-platform.phase2b=scanner"
        ), "Stop the host launcher before evaluation"
        runs = []
        execution = uuid4().hex
        for repetition in range(2):
            # Keep the existing 32-snapshot quota: each independent 28-fixture
            # repetition gets its own private spool, never a larger product quota.
            launcher.boundary = DockerBoundary(
                ROOT / ".local/phase4-evaluation" / execution / str(repetition) / "spool"
            )
            store = SnapshotStore(launcher.boundary.spool, require_readonly=False)
            observations = {}
            for case in manifest["cases"]:
                directory = ROOT / ".cache" / ("phase4-fixture-" + uuid4().hex)
                materialize(case, directory)
                snapshot = store.create(directory, label="controlled-phase4-" + case["id"])
                record = {}
                for scanner in ("semgrep", "trivy"):
                    request = Invocation(
                        id=uuid4(),
                        job_id=uuid4(),
                        generation=1,
                        lease_token=uuid4(),
                        snapshot_key=snapshot.manifest.snapshot_key,
                        manifest_digest=snapshot.manifest_digest,
                        profile=scanner + "-v1",
                        registry_digest=launcher.registry_hash,
                    )
                    profile, database, provenance = launcher.profile(request)
                    started = time.monotonic()
                    identifier = launcher.boundary.create(
                        profile,
                        request.snapshot_key,
                        request.manifest_digest,
                        request.id,
                        database=database,
                    )
                    captured = launcher.boundary.capture(identifier, profile)
                    duration = round((time.monotonic() - started) * 1000, 2)
                    if captured.error_code:
                        raise RuntimeError(
                            "Bounded scanner execution failed: " + captured.error_code
                        )
                    result = normalize(
                        scanner, captured.stdout, captured.exit_code, snapshot, provenance
                    ).model_dump(mode="json")
                    assert SYNTHETIC not in json.dumps(result)
                    record[scanner] = {
                        "source_identity": {
                            "content_digest": snapshot.manifest.content_digest,
                            "manifest_digest": snapshot.manifest_digest,
                        },
                        "result": result,
                        "duration_ms": duration,
                        "exit_code": captured.exit_code,
                        "stdout_bytes": len(captured.stdout),
                        "stderr_bytes": len(captured.stderr),
                        "oom_killed": captured.oom_killed,
                        "limits": {
                            "memory": profile.memory,
                            "cpus": profile.cpus,
                            "pids": profile.pids,
                            "seconds": profile.seconds,
                        },
                    }
                observations[case["id"]] = record
                print(
                    json.dumps(
                        {
                            "repetition": repetition + 1,
                            "fixture": case["id"],
                            "counts": {s: len(r["result"]["findings"]) for s, r in record.items()},
                        }
                    ),
                    flush=True,
                )
            runs.append(observations)
        stable = all(
            semantic(runs[0][c["id"]][s]["result"]) == semantic(runs[1][c["id"]][s]["result"])
            for c in manifest["cases"]
            for s in ("semgrep", "trivy")
        )
        assert stable, "Scanner semantic results changed across repeated offline runs"
        report = {
            "version": "scanner-evaluation-1",
            "recorded_at": datetime.now(UTC).isoformat(),
            "dataset": manifest["version"],
            "manifest_sha256": sha(BASE / "manifest.json"),
            "freeze_sha256": sha(BASE / "frozen-v1.json"),
            "registry_digest": launcher.registry_hash,
            "registry": launcher.registry,
            "engine": launcher.boundary.ready(),
            "repetitions": runs,
            "semantic_reproducibility": stable,
            "baseline": scanner_metrics(manifest["cases"], runs[0]),
            "private_source_or_raw_scanner_output_persisted": False,
            "observed_peak_memory": None,
            "paid_cost": None,
            "live_hosted_calls": 0,
        }
        text = json.dumps(report, indent=2) + "\n"
        assert SYNTHETIC not in text
        (output / "scanner-observations.json").write_text(text, encoding="utf-8")
    print(json.dumps({"scanner_fixture_runs": 112, "reproducible": stable}), flush=True)


if __name__ == "__main__":
    main()
