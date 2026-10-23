"""Small API demonstration; no credential options, generic file writes or target execution."""

import json
import time
from uuid import UUID, uuid4

from ai_security_platform.cli.main import Parser, call_api
from ai_security_platform.soc.scenarios import scenario


def main() -> int:
    parser = Parser(description="Optional synthetic SOC API demonstration")
    parser.add_argument("--api", default="http://127.0.0.1:18081")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("scenario", choices=["auth-burst", "session-grant", "clean", "incomplete"])
    demo.add_argument("--dataset", type=UUID)
    demo.add_argument("--key", default="demo-v1")
    demo.add_argument("--timeout", type=float, default=30)
    status = commands.add_parser("status")
    status.add_argument("run_id", type=UUID)
    history = commands.add_parser("history")
    history.add_argument("dataset_id", type=UUID)
    args = parser.parse_args()
    try:
        if args.command == "demo":
            if not 0.1 <= args.timeout <= 120:
                raise ValueError("invalid_timeout")
            dataset = args.dataset or uuid4()
            call_api(
                args.api, "/api/v1/soc/datasets", {"id": str(dataset), "label": "synthetic-demo"}
            )
            accepted = call_api(
                args.api,
                f"/api/v1/soc/datasets/{dataset}/events",
                scenario(args.scenario).model_dump(mode="json"),
                args.key,
            )
            deadline = time.monotonic() + args.timeout
            while True:
                status_result = call_api(
                    args.api,
                    f"/api/v1/soc/runs/{UUID(accepted['id'])}",
                    timeout=min(5, max(0.1, deadline - time.monotonic())),
                )
                if status_result["status"] in {"succeeded", "failed"}:
                    break
                if time.monotonic() >= deadline:
                    raise ValueError("wait_timeout")
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
            print(json.dumps({"accepted": accepted, "run": status_result}))
            return 0 if status_result["status"] == "succeeded" else 2
        path = (
            f"/api/v1/soc/runs/{args.run_id}"
            if args.command == "status"
            else f"/api/v1/soc/datasets/{args.dataset_id}/investigations"
        )
        print(json.dumps(call_api(args.api, path)))
        return 0
    except KeyboardInterrupt:
        print('{"code":"cancelled","remote_job_cancelled":false}')
        return 2
    except Exception:
        print('{"code":"soc_operation_failed","retryable":false}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
