"""A tiny MCP stdio server used by test_mcp_stdio.py (run as a subprocess)."""

import json
import os
import sys
import time

mode = sys.argv[1] if len(sys.argv) > 1 else "normal"


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method, rid = msg["method"], msg["id"]
    if mode == "hang" and method == "tools/call":
        time.sleep(60)
    if mode == "garbage" and method == "tools/call":
        sys.stdout.write("not json\n")
        sys.stdout.flush()
        continue
    if mode == "oversize" and method == "tools/call":
        sys.stdout.write("x" * 5000 + "\n")
        sys.stdout.flush()
        continue
    if mode == "exit" and method == "tools/call":
        sys.exit(0)
    if method == "initialize":
        send(
            {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake", "version": "1"},
                },
            }
        )
    elif method == "tools/list":
        send(
            {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "tools": [
                        {
                            "name": "env",
                            "description": "dump env",
                            "inputSchema": {"type": "object"},
                        },
                        {"name": "echo", "description": "echo", "inputSchema": {"type": "object"}},
                    ]
                },
            }
        )
    elif method == "tools/call":
        if mode == "sampling":
            send({"jsonrpc": "2.0", "id": 99, "method": "sampling/createMessage", "params": {}})
            reply = json.loads(sys.stdin.readline())
            text = json.dumps(reply.get("error", {}).get("code"))
        elif msg["params"]["name"] == "env":
            text = json.dumps(sorted(os.environ))
        else:
            text = json.dumps(msg["params"]["arguments"])
        send({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": text}]}})
