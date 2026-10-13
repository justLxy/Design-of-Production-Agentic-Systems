"""Tests for the dispatcher (B3)."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from vulnagent.dispatcher import TOOLS, Dispatcher
from vulnagent.trace import Trace
from vulnagent.workspace import Workspace

REPO_ROOT = Path(__file__).resolve().parents[1]
OWASP = REPO_ROOT / "targets" / "owasp-benchmark-python"
CASE = "testcode/BenchmarkTest00011.py"
ALERT = "testcode-BenchmarkTest00011-py-47-B608"

pytestmark = pytest.mark.skipif(not OWASP.is_dir(), reason="OWASP target not cloned")


def events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture
def setup(tmp_path):
    trace_path = tmp_path / "trace.jsonl"
    with Workspace(OWASP) as ws, ws.investigating(CASE):
        yield Dispatcher(ws, Trace(trace_path, "test-run")), trace_path


def test_a_valid_request_runs_the_tool(setup):
    dispatcher, trace_path = setup
    obs = dispatcher.dispatch(ALERT, "c1", "read_file",
                              json.dumps({"path": CASE, "start_line": 45, "end_line": 48}))
    assert obs.ok and "SELECT username" in obs.text
    request, result = events(trace_path)
    assert request["kind"] == "tool_request" and request["args"]["path"] == CASE
    assert result["kind"] == "tool_result" and result["ok"] is True


def test_an_unknown_tool_is_refused(setup):
    dispatcher, trace_path = setup
    obs = dispatcher.dispatch(ALERT, "c1", "run_shell", '{"cmd": "ls"}')
    assert not obs.ok and obs.text.startswith("REFUSED: unknown tool")
    assert events(trace_path)[-1]["error"].startswith("unknown tool")


def test_invalid_json_is_refused(setup):
    dispatcher, trace_path = setup
    obs = dispatcher.dispatch(ALERT, "c1", "read_file", '{"path": ')
    assert not obs.ok and "not valid JSON" in obs.text
    assert events(trace_path)[0]["args"] == {"_raw": '{"path": '}


@pytest.mark.parametrize("args", [
    {"start_line": 1},                  # missing required path
    {"path": CASE, "mode": "w"},        # unexpected argument
    {"path": 5},                        # wrong type
    {"path": CASE, "start_line": 0},    # below minimum
])
def test_bad_arguments_are_refused(setup, args):
    dispatcher, _ = setup
    obs = dispatcher.dispatch(ALERT, "c1", "read_file", json.dumps(args))
    assert not obs.ok and obs.text.startswith("REFUSED: bad arguments")


def test_a_path_escape_is_refused_not_raised(setup):
    dispatcher, _ = setup
    obs = dispatcher.dispatch(ALERT, "c1", "read_file", '{"path": "/etc/passwd"}')
    assert not obs.ok and "absolute paths are refused" in obs.text


def test_every_request_is_immediately_followed_by_its_result(setup):
    dispatcher, trace_path = setup
    dispatcher.dispatch(ALERT, "c1", "list_dir", "{}")
    dispatcher.dispatch(ALERT, "c2", "nope", "{}")
    dispatcher.dispatch(ALERT, "c3", "search", '{"pattern": "("}')
    kinds = [e["kind"] for e in events(trace_path)]
    assert kinds == ["tool_request", "tool_result"] * 3


def test_a_crashing_tool_still_writes_its_result(setup, monkeypatch):
    dispatcher, trace_path = setup

    def boom(ws, **kwargs):
        raise RuntimeError("simulated bug")

    monkeypatch.setitem(TOOLS, "list_dir", replace(TOOLS["list_dir"], run=boom))
    with pytest.raises(RuntimeError):
        dispatcher.dispatch(ALERT, "c1", "list_dir", "{}")
    last = events(trace_path)[-1]
    assert last["kind"] == "tool_result" and last["ok"] is False


def test_specs_use_the_responses_function_format():
    specs = Dispatcher.specs()
    assert {s["name"] for s in specs} == {"read_file", "search", "list_dir"}
    assert all(s["type"] == "function" and "parameters" in s for s in specs)