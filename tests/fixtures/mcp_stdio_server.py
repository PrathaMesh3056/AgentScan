# Minimal MCP stdio server (Content-Length framed JSON-RPC) for connector tests.

from __future__ import annotations

import json
import sys


def read_message() -> dict | None:
    headers: dict[str, str] = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        key, _, val = line.decode("utf-8", errors="replace").partition(":")
        headers[key.strip().lower()] = val.strip()
    n = int(headers.get("content-length", "0"))
    body = sys.stdin.buffer.read(n)
    return json.loads(body.decode("utf-8"))


def write_message(obj: dict) -> None:
    raw = json.dumps(obj).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw)
    sys.stdout.buffer.flush()


TOOLS = [
    {"name": "echo", "description": "Echo the message argument.", "inputSchema": {"type": "object"}}
]


def main() -> None:
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
