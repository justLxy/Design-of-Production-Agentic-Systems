"""Trace one operation, read_file, through the HW1 path and the HW2 MCP path, with one
malformed argument at each layer (for the REPORT's second comparison).

HW1 path: model request -> dispatcher -> in-process tool.
HW2 path: model request -> dispatcher -> MCP client -> server -> tool. The raw calls at
the end skip the dispatcher, as the staff driver does, so the server's own checks show.

Usage: python scripts/demo_call_paths.py <owasp checkout> <out dir>
Writes <out dir>/hw1/trace.jsonl, <out dir>/hw2/trace.jsonl and <out dir>/calls.json.
"""

import json
import sys
import time
from pathlib import Path

from vulnagent.config import REPO_ROOT
from vulnagent.dispatcher import LocalToolbox
from vulnagent.mcp_host import McpToolbox
from vulnagent.trace import TerminalStatus, Trace
from vulnagent.workspace import Workspace

ALERT = {"alert_id": "testcode-BenchmarkTest00011-py-47-B608", "path": "testcode/BenchmarkTest00011.py"}
CASE = ALERT["path"]

# (label, raw arguments string as the model would send it)
MODEL_CALLS = [
    ("ok", json.dumps({"path": CASE, "start_line": 45, "end_line": 47})),
    ("model: not JSON", '{"path": "' + CASE + '", "start_line": 45'),
    ("dispatcher: wrong type", json.dumps({"path": 5})),
    ("tool: bad line range", json.dumps({"path": CASE, "start_line": 50, "end_line": 45})),
]
# Sent straight to the MCP client, skipping the dispatcher.
RAW_CALLS = [
    ("server: unknown argument", {"path": CASE, "colour": "red"}),
    ("server: wrong type", {"path": CASE, "start_line": "45"}),
    ("tool: bad line range", {"path": CASE, "start_line": 50, "end_line": 45}),
]


def timed(fn):
    start = time.perf_counter()
    result = fn()
    return result, round((time.perf_counter() - start) * 1000, 2)


def main() -> None:
    owasp, out = Path(sys.argv[1]), Path(sys.argv[2])
    (out / "hw1").mkdir(parents=True, exist_ok=True)
    (out / "hw2").mkdir(parents=True, exist_ok=True)
    record: dict[str, list] = {"hw1": [], "hw2": [], "hw2_raw": []}

    trace = Trace(out / "hw1" / "trace.jsonl", "call-paths-hw1")
    with Workspace(owasp) as ws:
        toolbox = LocalToolbox(ws, trace)
        with toolbox.open_alert(ALERT):
            for i, (label, raw) in enumerate(MODEL_CALLS):
                obs, ms = timed(lambda: toolbox.dispatch(ALERT["alert_id"], f"c{i}", "read_file", raw))
                record["hw1"].append({"case": label, "ok": obs.ok, "ms": ms, "text": obs.text[:200]})
    trace.terminal(TerminalStatus.COMPLETED)

    trace = Trace(out / "hw2" / "trace.jsonl", "call-paths-hw2")
    toolbox = McpToolbox(REPO_ROOT / "mcp.json", owasp, trace)
    try:
        with toolbox.open_alert(ALERT):
            for i, (label, raw) in enumerate(MODEL_CALLS):
                obs, ms = timed(lambda: toolbox.dispatch(ALERT["alert_id"], f"c{i}", "read_file", raw))
                record["hw2"].append({"case": label, "ok": obs.ok, "ms": ms, "text": obs.text[:200]})
            for label, args in RAW_CALLS:
                (is_error, text), ms = timed(lambda: toolbox.conn.call_tool("read_file", args))
                record["hw2_raw"].append({"case": label, "ok": not is_error, "ms": ms, "text": text[:200]})
        record["read_file_schema"] = toolbox.tools["read_file"].input_schema
    finally:
        toolbox.close()
        trace.terminal(TerminalStatus.COMPLETED)

    (out / "calls.json").write_text(json.dumps(record, indent=2) + "\n")
    for path, rows in record.items():
        if path == "read_file_schema":
            continue
        for row in rows:
            print(f"{path:8} {row['case']:26} ok={row['ok']!s:5} {row['ms']:>8} ms  {row['text'][:90]!r}")


if __name__ == "__main__":
    main()
