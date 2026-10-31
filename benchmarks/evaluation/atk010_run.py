"""Intercepted authored ATK-010 controls; no model or external target calls."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import respx

URL = "http://synthetic.invalid/owned-atk010"
REFERENCE = "SYNTHETIC_ATK010_CONTROL_PRIVATE_7qJ9"
PUBLIC = "This is a public explanation of the requested topic."
MARKER = "AGENTSCAN-CRESCENDO-OK"


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


async def evaluate(output: Path) -> dict:
    from agentscan.attacks.exploit.crescendo import CrescendoModule
    from agentscan.attacks.registry import AttackRegistry
    from agentscan.core import runner
    from agentscan.core.models import RequestTemplate, Target

    if output.exists():
        raise FileExistsError("Use a new evaluation output directory.")
    manifest_path = Path(__file__).with_name("atk010_cases.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    module = CrescendoModule()
    scripts = module._load_scripts()
    assert tuple(row["id"] for row in scripts) == tuple(f"CRESC-{i:03}" for i in range(1, 7))
    assert all(len(row["turns"]) == 5 for row in scripts)
    output.mkdir(parents=True)
    registry = AttackRegistry()
    registry.register(module)
    registry._loaded = True
    arms = []
    for case in manifest["cases"]:
        arm = case["id"]
        journal = []

        def handle(request: httpx.Request, arm=arm, journal=journal) -> httpx.Response:
            body = json.loads(request.content)
            messages = body["messages"]
            turn = (len(messages) + 1) // 2
            assert [m["role"] for m in messages] == ["user", "assistant"] * (turn - 1) + ["user"]
            assert all(
                m["content"] == (MARKER if arm == "public_echo" else PUBLIC) for m in messages[1::2]
            )
            assert REFERENCE not in request.content.decode()
            reply = (
                REFERENCE
                if (arm == "private_turn_three" and turn == 3)
                or arm in {"request_budget", "incomplete_reference"}
                else MARKER
                if arm == "public_echo"
                else PUBLIC
            )
            status = 401 if arm == "authentication_error" else 200
            journal.append(
                {
                    "turn": turn,
                    "request_sha256": digest(request.content),
                    "response_sha256": digest(reply.encode()),
                    "status": status,
                }
            )
            return httpx.Response(
                status, json={"response": reply, "done": arm != "incomplete_reference"}
            )

        target = Target(
            url=URL,
            mode="EXPLOIT",
            canary_token=None if arm == "missing_reference" else REFERENCE,
            request_budget=1 if arm == "request_budget" else 30,
        )
        if arm == "supplied_reference":
            target.request_template = RequestTemplate(
                url=URL, message_path="message", json_body={"message": "", "context": REFERENCE}
            )
        provider = AsyncMock(side_effect=AssertionError("No model calls permitted"))
        with (
            patch.object(runner, "registry", registry),
            patch("agentscan.core.ai_client.AIClient.complete", provider),
            respx.mock(assert_all_called=False) as mock,
        ):
            route = mock.post(URL).mock(side_effect=handle)
            report = await runner.run_scan(target)
        provider.assert_not_called()
        actual = {
            "deliveries": route.call_count,
            "evaluated": report.tests_run,
            "findings": len(report.findings),
        }
        expected = {key: case[key] for key in actual}
        safe = report.model_dump_json()
        private_absent = REFERENCE not in safe
        arms.append(
            {
                "id": arm,
                "actual": actual,
                "expected": expected,
                "passed": actual == expected and private_absent,
                "status": report.status,
                "score": report.score,
                "journal": journal,
                "module_outcomes": report.module_outcomes,
            }
        )
    root = Path(__file__).resolve().parents[2]
    files = [
        Path(__file__),
        manifest_path,
        Path(__file__).with_name("atk010_METHOD.md"),
        root / "agentscan/attacks/exploit/crescendo.py",
        root / "agentscan/attacks/payloads/crescendo.yaml",
    ]
    result = {
        "method": manifest["method"],
        "passed": all(arm["passed"] for arm in arms),
        "scope": "authored engineering contracts only; no efficacy estimate",
        "files": {path.relative_to(root).as_posix(): digest(path.read_bytes()) for path in files},
        "arms": arms,
    }
    (output / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = asyncio.run(evaluate(args.output))
    print(
        json.dumps(
            {
                "passed": result["passed"],
                "arms": len(result["arms"]),
                "deliveries": sum(arm["actual"]["deliveries"] for arm in result["arms"]),
            }
        )
    )
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
