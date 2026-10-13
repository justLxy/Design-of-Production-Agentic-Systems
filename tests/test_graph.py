"""Tests for the agent graph (B4, B7, B8) with a scripted model. No network calls."""

import itertools
import json
import sys
from pathlib import Path

import pytest

from vulnagent.graph import Agent
from vulnagent.llm import ModelReply, ToolCall
from vulnagent.trace import TerminalStatus, Trace
from vulnagent.workspace import Workspace

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from check_run import check_trace  # noqa: E402

OWASP = REPO_ROOT / "targets" / "owasp-benchmark-python"
pytestmark = pytest.mark.skipif(not OWASP.is_dir(), reason="OWASP target not cloned")

P11 = "testcode/BenchmarkTest00011.py"
P12 = "testcode/BenchmarkTest00012.py"


def make_alert(path: str, line: int) -> dict:
    slug = path.replace("/", "-").replace(".", "-")
    return {"alert_id": f"{slug}-{line}-B608", "test_id": "B608", "path": path, "line": line,
            "severity": "MEDIUM", "confidence": "LOW",
            "issue_text": "Possible SQL injection vector through string-based query construction.",
            "code": f"{line} sql = f'SELECT ...'"}


A11, A12 = make_alert(P11, 47), make_alert(P12, 48)
_ids = itertools.count(1)


def tool(name: str, **args) -> ToolCall:
    return ToolCall(f"call_{next(_ids)}", name, json.dumps(args))


def submit(path: str, label: int = 0, start: int = 45, end: int = 48) -> ToolCall:
    return tool("submit", label=label, rationale="The query is parameterised (line 47).",
                evidence=[{"path": path, "start_line": start, "end_line": end}])


def reply(*calls: ToolCall, text: str = "", finish: str | None = None,
          inp: int = 1000, out: int = 100) -> ModelReply:
    return ModelReply(text=text, tool_calls=list(calls),
                      finish_reason=finish or ("tool_calls" if calls else "stop"),
                      usage={"input": inp, "output": out}, output_items=[])


class ScriptedModel:
    """Plays back a fixed list of replies, one per model call."""

    model = "scripted"

    def __init__(self, replies: list[ModelReply]):
        self.replies = list(replies)
        self.calls = 0

    def complete(self, items: list[dict], tools: list[dict]) -> ModelReply:
        self.calls += 1
        return self.replies.pop(0)


def run(tmp_path, replies, alerts=(A11, A12), max_tokens=1_000_000, max_steps=100):
    """Run the agent with a scripted model; check the trace invariants; return the results."""
    cfg = {"budget": {"max_tokens": max_tokens, "output_allowance": 1000, "max_steps": max_steps}}
    trace_path = tmp_path / "trace.jsonl"
    trace = Trace(trace_path, "test-run")
    model = ScriptedModel(replies)
    with Workspace(OWASP) as ws:
        agent = Agent(cfg, ws, trace, model)
        status = agent.run(list(alerts))
    trace.terminal(status)

    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    assert check_trace(events) == []
    settles = [e["alert_id"] for e in events if e["kind"] == "state_change" and "alert_status" in e]
    assert sorted(settles) == sorted(a["alert_id"] for a in alerts)  # invariant 5: once each
    return status, agent.rows, events, model


def decisions(events: list[dict]) -> list[tuple[str, str]]:
    return [(e["decision"], e["by"]) for e in events if e["kind"] == "routing"]


def test_read_then_submit_classifies_every_alert(tmp_path):
    status, rows, events, _ = run(tmp_path, [
        reply(tool("read_file", path=P11, start_line=40, end_line=50)),
        reply(submit(P11, label=0)),
        reply(submit(P12, label=1)),
    ])
    assert status is TerminalStatus.COMPLETED
    assert (rows[A11["alert_id"]]["status"], rows[A11["alert_id"]]["label"]) == ("classified", 0)
    assert (rows[A12["alert_id"]]["status"], rows[A12["alert_id"]]["label"]) == ("classified", 1)
    assert decisions(events)[:4] == [("triage", "runtime"), ("tools", "model"),
                                     ("triage", "runtime"), ("submit", "model")]


def test_a_refused_submit_goes_back_to_the_model(tmp_path):
    status, rows, events, _ = run(tmp_path, [
        reply(submit(P11, start=50, end=999)),  # evidence past the end of the file
        reply(submit(P11)),
        reply(submit(P12)),
    ])
    assert status is TerminalStatus.COMPLETED
    assert rows[A11["alert_id"]]["status"] == "classified"
    refused = [e for e in events if e["kind"] == "tool_result" and not e["ok"]]
    assert refused[0]["tool"] == "submit"


def test_a_cut_off_reply_is_an_error_and_the_run_goes_on(tmp_path):
    status, rows, _, _ = run(tmp_path, [
        reply(finish="max_output_tokens"),
        reply(submit(P12)),
    ])
    assert status is TerminalStatus.COMPLETED
    assert (rows[A11["alert_id"]]["status"], rows[A11["alert_id"]]["label"]) == ("error", None)
    assert rows[A12["alert_id"]]["status"] == "classified"


def test_text_without_a_tool_call_is_nudged(tmp_path):
    status, _, events, _ = run(tmp_path, [
        reply(text="I think this is safe."),
        reply(submit(P11)),
        reply(submit(P12)),
    ])
    assert status is TerminalStatus.COMPLETED
    assert ("nudge", "runtime") in decisions(events)


def test_the_budget_cutoff_marks_the_rest_budget_exhausted(tmp_path):
    # 54_000 + 100 used leaves 900, less than the 1000-token output allowance alone.
    status, rows, events, model = run(tmp_path, [reply(submit(P11), inp=54_000)], max_tokens=55_000)
    assert status is TerminalStatus.BUDGET_EXHAUSTED
    assert rows[A11["alert_id"]]["status"] == "classified"
    assert (rows[A12["alert_id"]]["status"], rows[A12["alert_id"]]["label"]) == ("budget_exhausted", None)
    cutoff = [e for e in events if e["kind"] == "routing" and e["decision"] == "budget_exhausted"][0]
    assert cutoff["required"] > cutoff["remaining"]
    assert model.calls == 1


def test_a_zero_budget_never_calls_the_model(tmp_path):
    status, rows, _, model = run(tmp_path, [], max_tokens=0)
    assert status is TerminalStatus.BUDGET_EXHAUSTED
    assert {r["status"] for r in rows.values()} == {"budget_exhausted"}
    assert model.calls == 0


def test_max_steps_stops_the_run(tmp_path):
    status, rows, _, _ = run(tmp_path, [
        reply(tool("list_dir")),  # step 1: model call, step 2: tool
    ], max_steps=2)
    assert status is TerminalStatus.MAX_STEPS
    assert {r["status"] for r in rows.values()} == {"error"}


def test_repeating_the_same_request_is_no_progress(tmp_path):
    status, rows, events, _ = run(tmp_path, [reply(tool("list_dir")) for _ in range(4)])
    assert status is TerminalStatus.NO_PROGRESS
    assert {r["status"] for r in rows.values()} == {"error"}
    assert ("no_progress", "runtime") in decisions(events)