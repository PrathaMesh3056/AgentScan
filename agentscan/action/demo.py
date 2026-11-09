"""Run the scripted HTTP target through the text scanner and action verifier."""

from __future__ import annotations

import asyncio
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from uuid import uuid4

from agentscan.action.gateway import MockGateway
from agentscan.action.modules.act001 import UnauthorizedToolInvocation
from agentscan.action.receipts import verify_receipt_chain
from agentscan.core.models import ScanMode, Target
from agentscan.core.runner import run_scan

SCRIPTED_TARGET_LABEL = "SCRIPTED TARGET"
DEMO_NONCE = "SPIKE_ACTION_VERIFICATION_NONCE_7D31"
BENIGN_RESPONSE = "I can help with general customer support."


def _handler_for(gateway: MockGateway) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            size = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(size) or b"{}")
            message = body.get("message", "")
            response: dict[str, Any] = {"response": BENIGN_RESPONSE}
            if message == DEMO_NONCE:
                principal = body.get("principal", "")
                trace_id = str(uuid4())
                receipt = gateway.invoke(
                    principal=principal,
                    tool_name="delete_customer_record",
                    arguments={"customer_id": "cust-1001"},
                    trace_id=trace_id,
                )
                response.update(
                    {"trace_id": receipt.trace_id, "receipt_hash": receipt.evidence.hash}
                )
            encoded = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return Handler


def _post_demo_target(url: str, principal: str) -> dict[str, Any]:
    request_body = json.dumps({"message": DEMO_NONCE, "principal": principal}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


async def _run() -> int:
    print("Preparing scripted action-verification demo.", flush=True)
    run_dir = Path(".test-tmp/spike-action-verification").resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    gateway = MockGateway(run_dir / "mock-tool-state.json")
    gateway.tool.reset_state()
    print("Fake state initialized.", flush=True)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(gateway))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target_url = f"http://127.0.0.1:{server.server_port}/chat"
    target = Target(
        url=target_url,
        mode=ScanMode.SCAN,
        analysis_mode="deterministic",
        allowed_networks=["127.0.0.0/8"],
        attacker_model=None,
        judge_model=None,
        escalation_model=None,
    )
    try:
        print(f"{SCRIPTED_TARGET_LABEL}: local HTTP endpoint {target_url}", flush=True)
        initial_hash = gateway.tool.state_hash()
        golden_report = await run_scan(target)
        golden_text = json.dumps(golden_report.model_dump(mode="json"), indent=2, sort_keys=True)
        golden_path = run_dir / "text-only-golden.json"
        golden_path.write_text(golden_text + "\n", encoding="utf-8")
        print("\n=== TEXT-ONLY SCAN: GOLDEN OUTPUT (single run, full output) ===")
        print(golden_text)
        print(f"\nGolden text-only output stored at: {golden_path}")

        action = UnauthorizedToolInvocation()
        print("\n=== ALLOWED CASE: TEXT-ONLY SCAN ===")
        print("Reuses the exact golden report above; no rescan or finding filtering.")
        print("=== ALLOWED CASE: ACTION VERIFICATION ===")
        print(f"state_hash_before={initial_hash}")
        allowed_response = _post_demo_target(target_url, "principal:crm-operator")
        allowed_receipt = gateway.receipts[-1]
        allowed_after = gateway.tool.state_hash()
        allowed_scan = action.scan(gateway.receipts, allowed_response["trace_id"])
        print(f"target_response={json.dumps(allowed_response, sort_keys=True)}")
        print(f"state_hash_after={allowed_after}")
        print("receipt:")
        print(json.dumps(allowed_receipt.model_dump(mode="json"), indent=2, sort_keys=True))
        print(f"receipt_chain_verified={verify_receipt_chain(gateway.receipts)}")
        print(f"action_status={allowed_scan.status}; findings={len(allowed_scan.findings)}")

        print("\n=== DENIED CASE: TEXT-ONLY SCAN ===")
        print("Reuses the exact golden report above; no rescan or finding filtering.")
        print("=== DENIED CASE: ACTION VERIFICATION ===")
        denied_before = gateway.tool.state_hash()
        print(f"state_hash_before={denied_before}")
        denied_response = _post_demo_target(target_url, "principal:untrusted-agent")
        denied_receipt = gateway.receipts[-1]
        denied_after = gateway.tool.state_hash()
        denied_scan = action.scan(gateway.receipts, denied_response["trace_id"])
        print(f"target_response={json.dumps(denied_response, sort_keys=True)}")
        print(f"state_hash_after={denied_after}")
        print("receipt:")
        print(json.dumps(denied_receipt.model_dump(mode="json"), indent=2, sort_keys=True))
        print(f"receipt_chain_verified={verify_receipt_chain(gateway.receipts)}")
        print(f"action_status={denied_scan.status}; findings={len(denied_scan.findings)}")
        for finding in denied_scan.findings:
            print("action_finding:")
            print(json.dumps(finding.model_dump(mode="json"), indent=2, sort_keys=True))

        text_findings = golden_report.findings
        all_ok = (
            not text_findings
            and allowed_receipt.authorization.decision == "allow"
            and allowed_receipt.result.status == "success"
            and initial_hash != allowed_after
            and allowed_scan.status == "PASS"
            and denied_receipt.authorization.decision == "deny"
            and denied_receipt.result.status == "denied"
            and denied_before == denied_after
            and denied_scan.status == "FINDING"
            and bool(denied_scan.findings)
            and denied_scan.findings[0].receipt_hash == denied_receipt.evidence.hash
            and verify_receipt_chain(gateway.receipts)
        )
        print(f"\nDEMO_RESULT={'PASS' if all_ok else 'FAIL'}")
        if text_findings:
            print(f"text_only_findings={len(text_findings)} (full report printed above)")
        return 0 if all_ok else 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main() -> None:
    raise SystemExit(asyncio.run(_run()))


if __name__ == "__main__":
    main()
