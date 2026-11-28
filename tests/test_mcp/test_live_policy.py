from __future__ import annotations

import http.server
import threading
import time

from agentscan.mcp.server import LiveTargetPolicy, process_jsonrpc_message


def test_live_tools_disabled_by_default():
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "agentscan_scan", "arguments": {"target_url": "http://example.com/chat"}}}
    resp = process_jsonrpc_message(req)
    assert resp["result"]["isError"] is True


def test_unapproved_url_rejected():
    policy = LiveTargetPolicy(allowed_hosts=["127.0.0.1"], allowed_networks=["127.0.0.0/8"],
                              request_budget=5, allow_live_targets=True)
    req = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
           "params": {"name": "agentscan_scan", "arguments": {"target_url": "http://example.com/chat"}}}
    resp = process_jsonrpc_message(req, policy=policy)
    assert resp["result"]["isError"] is True
    assert "approved" in resp["result"]["content"][0]["text"].lower() or "policy" in resp["result"]["content"][0]["text"].lower()


def test_approved_loopback_budget_enforced():
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"response":"ok"}')

        def log_message(self, *a):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)
    url = f"http://127.0.0.1:{httpd.server_port}/chat"
    policy = LiveTargetPolicy(allowed_hosts=["127.0.0.1"], allowed_networks=["127.0.0.0/8"],
                              request_budget=1, allow_live_targets=True)
    req = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
           "params": {"name": "agentscan_scan", "arguments": {"target_url": url, "timeout": 2}}}
    resp = process_jsonrpc_message(req, policy=policy)
    assert resp is not None
    httpd.shutdown()
