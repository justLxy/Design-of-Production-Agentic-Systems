"""Tests for the CodeAct execution kernel and toolbox, on a tiny project (no CLDK)."""

import json
import os
import sys

import pytest

from vulnagent.codeact import CodeActToolbox, KernelProcess
from vulnagent.config import REPO_ROOT
from vulnagent.trace import TerminalStatus, Trace

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from check_run import check_trace  # noqa: E402

CODE = "import os\n\n\ndef handler(request):\n    value = request.args.get('q')\n    return eval(value)\n"
ALERT = {"alert_id": "app-py-6-B307", "test_id": "B307", "path": "app.py", "line": 6,
         "severity": "MEDIUM", "confidence": "HIGH", "issue_text": "Use of possibly insecure function",
         "code": "6     return eval(value)"}


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text(CODE)
    (root / "expectedresults-0.1.csv").write_text("answer key\n")
    return root


@pytest.fixture
def toolbox(project, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_API_KEY", "not-for-the-kernel")
    guide = tmp_path / "guide.md"
    guide.write_text("Guide text.")
    trace = Trace(tmp_path / "trace.jsonl", "test")
    tb = CodeActToolbox({"codeact": {"prompt": str(guide), "timeout_s": 20}}, project, trace)
    yield tb, trace, tmp_path / "trace.jsonl"
    tb.close()


def run(tb, code, call="c"):
    return tb.dispatch(ALERT["alert_id"], call, "run_python", json.dumps({"code": code}))


def events_of(trace, path):
    trace.terminal(TerminalStatus.COMPLETED)
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_names_persist_and_the_last_expression_is_shown(toolbox):
    tb, _, _ = toolbox
    with tb.open_alert(ALERT):
        assert run(tb, "x = 41").ok
        obs = run(tb, "x + 1")
    assert obs.ok and "=> 42" in obs.text


def test_prints_and_subprocess_output_are_returned(toolbox):
    tb, _, _ = toolbox
    with tb.open_alert(ALERT):
        obs = run(tb, "import subprocess\nprint('from python')\nsubprocess.run(['echo', 'from a child'])\nNone")
    assert "from python" in obs.text and "from a child" in obs.text


def test_workspace_and_alert_are_predefined_and_the_answer_key_is_not_copied(toolbox):
    tb, _, _ = toolbox
    with tb.open_alert(ALERT):
        obs = run(tb, "import os\nprint(ALERT['path'], ALERT['line'], os.getcwd() == WORKSPACE)\n"
                      "sorted(os.listdir(WORKSPACE))")
    assert "app.py 6 True" in obs.text and "expectedresults" not in obs.text


def test_an_exception_returns_the_models_traceback(toolbox):
    tb, trace, path = toolbox
    with tb.open_alert(ALERT):
        obs = run(tb, "a = 1\nb = a / 0")
    assert not obs.ok and "ZeroDivisionError" in obs.text and "b = a / 0" in obs.text
    result = [e for e in events_of(trace, path) if e["kind"] == "tool_result"][-1]
    assert result["exception"] == "ZeroDivisionError" and "refused_by" not in result


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_an_os_permission_error_is_recorded_as_a_kernel_refusal(toolbox, tmp_path):
    tb, trace, path = toolbox
    locked = tmp_path / "locked.txt"
    locked.write_text("secret")
    locked.chmod(0)
    with tb.open_alert(ALERT):
        obs = run(tb, f"open({str(locked)!r}).read()")
    assert not obs.ok and "REFUSED by the sandbox" in obs.text
    events = events_of(trace, path)
    result = [e for e in events if e["kind"] == "tool_result"][-1]
    assert result["refused_by"] == "kernel" and result["via"] == "codeact"
    assert check_trace(events) == []


def test_the_kernel_gets_no_api_keys(toolbox):
    tb, _, _ = toolbox
    with tb.open_alert(ALERT):
        obs = run(tb, "import os\n'FAKE_API_KEY' in os.environ")
    assert "=> False" in obs.text


def test_dispatcher_refusals(toolbox):
    tb, trace, path = toolbox
    with tb.open_alert(ALERT):
        unknown = tb.dispatch(ALERT["alert_id"], "a", "read_file", json.dumps({"path": "app.py"}))
        extra = tb.dispatch(ALERT["alert_id"], "b", "run_python", json.dumps({"code": "1", "timeout": 5}))
        bad_json = tb.dispatch(ALERT["alert_id"], "c", "run_python", '{"code": ')
        evidence = tb.dispatch(ALERT["alert_id"], "d", "submit", json.dumps(
            {"label": 1, "rationale": "r", "evidence": [{"path": "app.py", "start_line": 5, "end_line": 99}]}))
    assert not any(o.ok for o in (unknown, extra, bad_json, evidence))
    results = [e for e in events_of(trace, path) if e["kind"] == "tool_result"]
    assert [e["refused_by"] for e in results] == ["dispatcher"] * 4


def test_submit_checks_evidence_against_the_workspace(toolbox):
    tb, _, _ = toolbox
    with tb.open_alert(ALERT):
        obs = tb.dispatch(ALERT["alert_id"], "s", "submit", json.dumps(
            {"label": 1, "rationale": "eval of a request value", "evidence": [
                {"path": "app.py", "start_line": 4, "end_line": 6}]}))
    assert obs.ok and obs.text.startswith("Accepted")


def test_review_accepts_a_fix_and_each_alert_starts_from_the_pinned_file(toolbox):
    tb, _, _ = toolbox
    fix = ("import os\np = os.path.join(WORKSPACE, ALERT['path'])\ns = open(p).read()\n"
           "s = s.replace('import os', 'import ast\\nimport os').replace('eval(value)', 'ast.literal_eval(value)')\n"
           "open(p, 'w').write(s)\nNone")
    with tb.open_alert(ALERT):
        assert run(tb, fix).ok
        review = tb.review(ALERT)
    assert review["status"] == "accepted" and "+    return ast.literal_eval(value)" in review["diff"]
    with tb.open_alert(ALERT):  # the next alert in this file sees the original code again
        assert tb.review(ALERT)["status"] == "rejected"
        assert "eval(value)" in (tb.workspace / "app.py").read_text()


def test_a_timeout_restarts_the_kernel(tmp_path):
    kernel = KernelProcess(sys.executable, tmp_path, timeout_s=3)
    try:
        kernel.bind("ALERT", {"path": "x.py"})
        assert kernel.run("x = 1")["ok"]
        stuck = kernel.run("import time\ntime.sleep(30)")
        assert stuck["error"]["type"] == "Timeout"
        after = kernel.run("print('x' in globals(), ALERT['path'])")
        assert after["ok"] and after["output"].strip() == "False x.py"  # names gone, ALERT bound again
    finally:
        kernel.stop()


def test_a_dead_kernel_is_restarted(tmp_path):
    kernel = KernelProcess(sys.executable, tmp_path, timeout_s=10)
    try:
        died = kernel.run("import os\nos._exit(3)")
        assert died["error"]["type"] == "KernelDied"
        assert kernel.run("1 + 1")["value"] == "2"
    finally:
        kernel.stop()


def test_the_system_prompt_is_the_rules_then_the_guide(toolbox):
    tb, _, _ = toolbox
    assert "Access rules." in tb.system_prompt and tb.system_prompt.rstrip().endswith("Guide text.")
    assert {s["name"] for s in tb.specs()} == {"run_python", "submit"}
