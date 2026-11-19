"""Tests for the MCP host: discovery, dispatcher refusals and the refused_by layer."""

import json
import sys
from pathlib import Path

import pytest

from vulnagent.config import REPO_ROOT
from vulnagent.mcp_host import McpToolbox

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from check_run import check_trace  # noqa: E402

ALERT = {"alert_id": "testcode-BenchmarkTest00011-py-3-B608", "path": "testcode/BenchmarkTest00011.py"}


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    root = tmp_path_factory.mktemp("owasp")
    (root / "testcode").mkdir()
    (root / "testcode/BenchmarkTest00011.py").write_text("def f(x):\n    q = 'SELECT ' + x\n    return q\n")
    (root / "testcode/BenchmarkTest00012.py").write_text("def g(x):\n    return x\n")
    (root / "expectedresults-0.1.csv").write_text("BenchmarkTest00011,sqli,true,89\n")

    from vulnagent.trace import Trace, TerminalStatus
    trace_path = tmp_path_factory.mktemp("out") / "trace.jsonl"
    trace = Trace(trace_path, "test")
    toolbox = McpToolbox(REPO_ROOT / "mcp.json", root, trace)
    observations = {}
    try:
        with toolbox.open_alert(ALERT):
            calls = {
                "host_only": ("set_alert", {"alert_id": "BenchmarkTest00012"}),
                "unknown": ("run_shell", {"cmd": "ls"}),
                "bad_args": ("read_file", {"path": "x.py", "colour": "red"}),
                "bad_json": ("read_file", None),
                "server": ("read_file", {"path": "testcode/BenchmarkTest00012.py"}),
                "answer_key": ("read_file", {"path": "expectedresults-0.1.csv"}),
                "ok": ("read_file", {"path": "testcode/BenchmarkTest00011.py"}),
            }
            for key, (name, args) in calls.items():
                raw = '{"path": ' if args is None else json.dumps(args)
                observations[key] = toolbox.dispatch(ALERT["alert_id"], key, name, raw)
    finally:
        toolbox.close()
        trace.terminal(TerminalStatus.COMPLETED)
    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    return toolbox, observations, events


def test_discovery_offers_listed_tools_minus_host_only(run):
    toolbox, _, events = run
    discovery = [e for e in events if e["kind"] == "discovery"]
    assert len(discovery) == 1 and discovery[0]["server"] == "vulnagent"
    offered = set(discovery[0]["tools"])
    assert {"locate", "dataflow", "read_file", "edit", "rescan", "submit"} <= offered
    assert not offered & {"set_alert", "review_patch"}
    assert {spec["name"] for spec in toolbox.specs()} == offered


@pytest.mark.parametrize("key", ["host_only", "unknown", "bad_args", "bad_json"])
def test_dispatcher_refuses_before_the_server(run, key):
    _, observations, events = run
    assert not observations[key].ok
    result = [e for e in events if e["kind"] == "tool_result"][list(observations).index(key)]
    assert result["refused_by"] == "dispatcher" and result["via"] == "mcp"


@pytest.mark.parametrize("key", ["server", "answer_key"])
def test_server_refusals_are_marked_server(run, key):
    _, observations, events = run
    result = [e for e in events if e["kind"] == "tool_result"][list(observations).index(key)]
    assert not observations[key].ok and result["refused_by"] == "server"
    assert result["error"].startswith("refused")


def test_an_allowed_call_succeeds_and_the_trace_holds(run):
    _, observations, events = run
    assert observations["ok"].ok and "SELECT" in observations["ok"].text
    assert all(e.get("via") == "mcp" for e in events if e["kind"] in ("tool_request", "tool_result"))
    assert check_trace(events) == []
