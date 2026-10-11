# Minimal MCP stdio server (newline-delimited JSON-RPC) for connector tests.

from __future__ import annotations

import json
import sys


def read_message() -> dict | None:
    line = sys.stdin.buffer.readline(4194305)
    return json.loads(line) if line else None


def write_message(obj: dict) -> None:
    sys.stdout.buffer.write(json.dumps(obj).encode("utf-8") + b"\n")
    sys.stdout.buffer.flush()


TOOLS = [
    {"name": "echo", "description": "Echo the message argument.", "inputSchema": {"type": "object"}}
]


def main() -> None:
    sys.stderr.buffer.write(b"fixture stderr " * 80000)
    sys.stderr.buffer.flush()
    while True:
        msg = read_message()
        if msg is None:
            return
        mid = msg.get("id")
        method = msg.get("method")
        if method == "initialize":
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}, "resources": {}},
                        "serverInfo": {"name": "echo", "version": "0.0.1"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            write_message({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
        elif method == "resources/list":
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {"resources": [{"uri": "mcp://echo/note", "name": "note"}]},
                }
            )
        elif method == "resources/read":
            uri = (msg.get("params") or {}).get("uri", "")
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "contents": [
                            {"uri": uri, "mimeType": "text/plain", "text": f"resource:{uri}"}
                        ]
                    },
                }
            )
        elif method == "tools/call":
            args = (msg.get("params") or {}).get("arguments") or {}
            text = args.get("message") or args.get("input") or str(args)
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {"content": [{"type": "text", "text": f"{text}"}]},
                }
            )
        elif mid is not None:
            write_message(
                {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": str(method)}}
            )


if __name__ == "__main__":
    main()
