"""Strict offline demonstration verification; production CLI policy codes are unchanged."""

import base64
import json
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

EXECUTION_MODE = "offline replay of genuine controlled observations; not a new scan"
FILES = {"guardrails.json", "guardrails.sarif", "policy.json"}
MAX_FILE = 4194304
MAX_ENVELOPE = 16 * 1024 * 1024 + 1024


def safe_exception_type(error: Exception) -> str:
    name = type(error).__name__
    return (
        name
        if name
        in {
            "AssertionError",
            "ValidationError",
            "ValueError",
            "TypeError",
            "KeyError",
            "JSONDecodeError",
            "FileNotFoundError",
            "FileExistsError",
            "PermissionError",
            "OSError",
            "SnapshotError",
        }
        else "UnexpectedError"
    )


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def invalid_constant(_value):
    raise ValueError("invalid_json_number")


def read_bytes(directory: Path, name: str):
    path = directory / name
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("invalid_artifact_file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE + 1)
    if not 0 < len(raw) <= MAX_FILE:
        raise ValueError("invalid_artifact_size")
    return raw


def pack(directory: Path):
    # Sender is stdlib-only for the GitHub host. No paths or extraction instructions
    # cross stdin: exactly three bounded base64 strings carry the copied artifact bytes.
    if directory.is_symlink() or {path.name for path in directory.iterdir()} != FILES:
        raise ValueError("invalid_artifact_set")
    return json.dumps(
        {
            name: base64.b64encode(read_bytes(directory, name)).decode("ascii")
            for name in sorted(FILES)
        },
        separators=(",", ":"),
    ).encode("ascii")


def verify_stream(stream):
    raw = stream.read(MAX_ENVELOPE + 1)
    if len(raw) > MAX_ENVELOPE:
        raise ValueError("artifact_envelope_limit")
    bundle = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    if not isinstance(bundle, dict) or set(bundle) != FILES:
        raise ValueError("invalid_artifact_set")
    documents = {}
    for name, value in bundle.items():
        if not isinstance(value, str):
            raise ValueError("invalid_artifact_encoding")
        content = base64.b64decode(value, validate=True)
        if not 0 < len(content) <= MAX_FILE:
            raise ValueError("invalid_artifact_size")
        documents[name] = json.loads(
            content, object_pairs_hook=unique_object, parse_constant=invalid_constant
        )
    return verify_documents(documents)


def verify(directory: Path):
    from io import BytesIO

    return verify_stream(BytesIO(pack(directory)))


def verify_documents(documents):
    # Only the restricted Linux receiver needs the locked validation dependencies.
    import jsonschema

    from ai_security_platform.reporting.contracts import Report
    from ai_security_platform.reporting.core import encode, sarif
    from ai_security_platform.reporting.policy import Policy, evaluate

    report = documents["guardrails.json"]
    document = documents["guardrails.sarif"]
    policy = documents["policy.json"]
    for value, name in [(report, "report-v1.json"), (document, "sarif-2.1.0.json")]:
        schema = json.loads((ROOT / "tests/schemas" / name).read_text(encoding="utf-8"))
        jsonschema.validators.validator_for(schema)(schema).validate(value)
    Report.model_validate(report)
    if report["scan"]["profile_id"] != "offline-fixture-replay":
        raise ValueError("unexpected_execution_mode")
    if encode(document) != encode(sarif(report)):
        raise ValueError("inconsistent_sarif")
    expected = evaluate(report, Policy(required_scanners=["semgrep"]))
    expected["execution_mode"] = EXECUTION_MODE
    if (
        type(policy.get("exit_code")) is not int
        or policy["exit_code"] != 1
        or encode(policy) != encode(expected)
    ):
        raise ValueError("unexpected_demo_policy")
    return {"artifacts": 3, "policy_exit_code": 1, "verification": "passed"}


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--send"]:
            sys.stdout.buffer.write(pack(Path("artifacts")))
        elif sys.argv[1:] == ["--stdin"]:
            print(json.dumps(verify_stream(sys.stdin.buffer)))
        else:
            raise ValueError("invalid_verification_mode")
    except Exception as error:
        print(
            json.dumps(
                {
                    "error": "ci_artifact_verification_failed",
                    "error_type": safe_exception_type(error),
                }
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from None
