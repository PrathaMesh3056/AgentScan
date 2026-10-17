"""Bounded owned stdio catalog fixture; tools/call is always rejected."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

APPROVED_TOOL = {
    "name": "approved_echo",
    "description": "Echo one explicitly supplied synthetic message.",
    "inputSchema": {
        "type": "object",
        "properties": {"message": {"type": "string"}},
        "required": ["message"],
        "additionalProperties": False,
    },
    "annotations": {"readOnlyHint": True},
}


def _reply(message_id: int, *, result: dict[str, Any] | None = None) -> None:
    reply: dict[str, Any] = {"jsonrpc": "2.0", "id": message_id}
    if result is None:
        reply["error"] = {"code": -32601, "message": "Fixture method is unavailable."}
    else:
        reply["result"] = result
    sys.stdout.buffer.write(json.dumps(reply).encode("utf-8") + b"\n")
    sys.stdout.buffer.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument(
        "--catalog-mode", choices=("match", "changed", "malformed"), default="match"
    )
    args = parser.parse_args()
    tool = json.loads(json.dumps(APPROVED_TOOL))
    if args.catalog_mode == "changed":
        tool["description"] = "Description revised after operator review."
    elif args.catalog_mode == "malformed":
        tool["inputSchema"] = {"type": "string"}

    # Explicit fresh file, bounded message count/size, and no network or tools.
    with args.journal.open("x", encoding="utf-8") as journal:
        for _ in range(16):
            line = sys.stdin.buffer.readline(65_537)
            if not line:
                return
            if len(line) > 65_536 or not line.endswith(b"\n"):
                raise ValueError("Fixture input exceeds its framing limit.")
            message = json.loads(line)
            if not isinstance(message, dict) or not isinstance(message.get("method"), str):
                raise ValueError("Fixture requires an object containing a method.")
            method = message["method"]
            journal.write(json.dumps({"method": method, "pid": os.getpid()}) + "\n")
            journal.flush()
            message_id = message.get("id")
            if message_id is None:
                continue
            if method == "initialize":
                _reply(
                    message_id,
                    result={
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "owned-catalog-fixture", "version": "0.1"},
                    },
                )
            elif method == "tools/list":
                _reply(message_id, result={"tools": [tool]})
            elif method == "resources/list":
                _reply(message_id, result={"resources": []})
            else:
                _reply(message_id)


if __name__ == "__main__":
    main()
