"""Read-only frontend supply-chain/build/confidentiality checks; no source transmission."""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import dotenv_values  # noqa: E402

from scripts.validate_local import DEV, request, run  # noqa: E402


def main():
    web = ROOT / "web"
    package = json.loads((web / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((web / "package-lock.json").read_text(encoding="utf-8"))
    assert package["name"] == lock["name"] == "asp-security-dashboard"
    config = dotenv_values(ROOT / ".env")
    secrets = [
        value
        for name, value in config.items()
        if value and (name.endswith("TOKEN") or name.endswith("PASSWORD"))
    ]
    public = run("git", "diff", "--name-only").splitlines()
    public += run("git", "ls-files", "--others", "--exclude-standard").splitlines()
    assets = [path for path in (web / "dist").rglob("*") if path.is_file()]
    assert assets, "Run npm run build before asset validation"
    checks = {}
    checks["no_actual_credentials_in_changed_files_or_build"] = all(
        not any(secret.encode() in path.read_bytes() for secret in secrets)
        for path in [*(ROOT / name for name in public), *assets]
        if path.is_file()
    )
    source = "\n".join(path.read_text(encoding="utf-8") for path in (web / "src").glob("*"))
    checks["no_persistent_credential_or_unsafe_dom_api"] = not re.search(
        r"localStorage|sessionStorage|indexedDB|document\.cookie|dangerouslySetInnerHTML|"
        r"\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|"
        r"window\.open",
        source,
    )
    checks["no_environment_values_in_client_source"] = "import.meta.env" not in source
    checks["exact_direct_dependency_pins_and_private_package"] = package["private"] and all(
        re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
        for group in ("dependencies", "devDependencies")
        for version in package[group].values()
    )
    checks["lock_matches_declared_dependencies"] = all(
        lock["packages"][""][group] == package[group]
        for group in ("dependencies", "devDependencies")
    )
    checks["install_scripts_disabled"] = "ignore-scripts=true" in (web / ".npmrc").read_text(
        encoding="utf-8"
    )
    checks["no_source_maps_or_private_build_files"] = not any(
        path.suffix == ".map" or path.name.lower() == "agents.md" or path.name.startswith(".env")
        for path in assets
    )
    base = "http://127.0.0.1:18081"
    origin = "http://127.0.0.1:18082"
    response = request(
        base,
        "/api/v1/triage-config",
        config["ASP_API_TOKEN"],
        method="GET",
        headers={"Origin": origin},
    )
    checks["authenticated_exact_frontend_origin_allowed"] = (
        response.status_code == 200
        and response.headers.get("access-control-allow-origin") == origin
    )
    checks["hosted_remains_disabled"] = response.json()["hosted_enabled"] is False
    logs = run(
        *DEV,
        "--profile",
        "workers",
        "--profile",
        "triage",
        "logs",
        "--no-color",
        "api",
        "worker",
        "triage-worker",
    )
    checks["actual_credentials_absent_from_container_logs"] = all(
        secret not in logs for secret in secrets
    )
    assert all(checks.values()), [key for key, value in checks.items() if not value]
    audit = subprocess.run(["npm.cmd", "audit", "--json"], cwd=web, capture_output=True, text=True)
    audit_value = json.loads(audit.stdout)
    assert audit.returncode == 0
    target = ROOT / "docs/phase6"
    (target / "dependency-audit.json").write_text(
        json.dumps(
            {
                "package": "web/package.json",
                "command": "npm audit --json (cwd web)",
                "exit_code": audit.returncode,
                "audit": audit_value,
            },
            indent=2,
        )
        + "\n"
    )
    record = {
        "node": run("node", "--version"),
        "npm": run("npm.cmd", "--version"),
        "direct_dependencies": package["dependencies"],
        "development_dependencies": package["devDependencies"],
        "lock_sha256": hashlib.sha256((web / "package-lock.json").read_bytes()).hexdigest(),
        "assets": {
            str(path.relative_to(web)): {
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in assets
        },
        "checks": checks,
        "passed": len(checks),
        "failed": 0,
        "skipped": 0,
        "scope": (
            "Known local credentials and maintained source; "
            "not universal secret detection or dependency safety"
        ),
    }
    (target / "frontend-evidence.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"frontend_checks_passed": len(checks), "assets": len(assets)}))


if __name__ == "__main__":
    main()
