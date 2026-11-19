"""End-to-end runs of the command line on OWASP with a fake model. No network calls."""

import json
import re
import sys
from pathlib import Path

import pytest

from vulnagent import cli
from vulnagent.llm import ModelReply, ToolCall

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from check_run import check_report, check_trace  # noqa: E402

OWASP = REPO_ROOT / "targets" / "owasp-benchmark-python"
pytestmark = pytest.mark.skipif(not OWASP.is_dir(), reason="OWASP target not cloned")

CONFIG = """\
[scan]
paths = ["testcode/BenchmarkTest000*.py"]
exclude = []
min_severity = "MEDIUM"
bandit_version = "1.9.4"

[model]
provider = "openai"
name = "fake"

[budget]
max_tokens = {max_tokens}
output_allowance = 1000
max_steps = 500

[agent]
kind = "{kind}"

[mcp]
config = "mcp.json"

[codeact]
prompt = "{guide}"

[sandbox]
policy = "policy.yaml"
"""


FIX_00073 = [("eval(bar)", "ast.literal_eval(bar)"),
             ("import urllib.parse", "import ast\n\t\timport urllib.parse")]


class AutoSubmitModel:
    """Submits label 1 for every alert, citing the flagged line; crashes on call `crash_on`.

    In remediation it fixes BenchmarkTest00073 (eval -> ast.literal_eval) and leaves the rest alone.
    """

    model = "fake"

    def __init__(self, crash_on: int | None = None):
        self.calls = 0
        self.crash_on = crash_on
        self.fixed: set[str] = set()

    def complete(self, items: list[dict], tools: list[dict]) -> ModelReply:
        self.calls += 1
        if self.calls == self.crash_on:
            raise RuntimeError("simulated crash")
        path, line = re.search(r"File: (\S+), line (\d+)", items[1]["content"]).groups()
        usage = {"input": 2000, "output": 100}
        if any(str(item.get("content", "")).startswith("Remediation stage") for item in items):
            if path.endswith("BenchmarkTest00073.py") and path not in self.fixed:
                self.fixed.add(path)
                if any(t["name"] == "run_python" for t in tools):  # the CodeAct agent writes the fix as code
                    code = ("import os\np = os.path.join(WORKSPACE, ALERT['path'])\ns = open(p).read()\n"
                            f"for old, new in {FIX_00073!r}:\n    s = s.replace(old, new, 1)\n"
                            "open(p, 'w').write(s)\nNone")
                    calls = [ToolCall(f"call_{self.calls}", "run_python", json.dumps({"code": code}))]
                else:
                    calls = [ToolCall(f"call_{self.calls}_{i}", "edit",
                                      json.dumps({"path": path, "old": old, "new": new}))
                             for i, (old, new) in enumerate(FIX_00073)]
                return ModelReply("", calls, "tool_calls", usage, [])
            return ModelReply("Done.", [], "stop", usage, [])
        args = {"label": 1, "rationale": "Fake rationale.",
                "evidence": [{"path": path, "start_line": int(line), "end_line": int(line)}]}
        call = ToolCall(f"call_{self.calls}", "submit", json.dumps(args))
        return ModelReply("", [call], "tool_calls", {"input": 2000, "output": 100}, [])


def run_cli(tmp_path, monkeypatch, model, max_tokens=1_000_000, input_dir=OWASP, kind="mcp") -> Path:
    """Point the CLI at a temp config and output dir, with the fake model in place of OpenAI."""
    guide = tmp_path / "guide.md"
    guide.write_text("A CLDK guide.")
    config = tmp_path / "config.toml"
    config.write_text(CONFIG.format(max_tokens=max_tokens, kind=kind, guide=guide))
    out = tmp_path / "out"
    monkeypatch.setattr(cli, "ModelClient", lambda *args, **kwargs: model)
    monkeypatch.setattr(sys, "argv", ["vulnagent", "--input", str(input_dir),
                                      "--output", str(out), "--config", str(config)])
    return out


def load(out: Path) -> tuple[dict, list[dict]]:
    """Read the run's outputs and run the same checks as check_run.py."""
    events = [json.loads(line) for line in (out / "trace.jsonl").read_text().splitlines()]
    report = json.loads((out / "report.json").read_text())
    assert check_trace(events) == []
    assert check_report(report, events) == []
    return report, events


@pytest.mark.parametrize("kind", ["mcp", "codeact"])
def test_a_full_run_writes_a_valid_report(tmp_path, monkeypatch, kind):
    out = run_cli(tmp_path, monkeypatch, AutoSubmitModel(), kind=kind)
    cli.main()
    report, events = load(out)
    assert report["scan"]["alert_count"] == 18
    assert {r["status"] for r in report["alerts"]} == {"classified"}
    assert report["target"]["commit"] == "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
    assert events[-1]["status"] == "completed"
    assert [e["kind"] for e in events].count("discovery") == (1 if kind == "mcp" else 0)
    assert all(e["via"] == kind for e in events if e["kind"] in ("tool_request", "tool_result"))
    remediate = [e for e in events if e["kind"] == "routing" and e["decision"] == "remediate"]
    assert len(remediate) == 18 and {e["by"] for e in remediate} == {"runtime"}
    rows = {r["path"]: r["remediation"] for r in report["alerts"]}
    fixed = rows["testcode/BenchmarkTest00073.py"]
    assert fixed["status"] == "accepted" and "ast.literal_eval" in fixed["diff"]
    assert rows["testcode/BenchmarkTest00011.py"]["status"] == "rejected"  # labelled 1, no patch


def test_a_low_budget_run_shows_the_cutoff(tmp_path, monkeypatch):
    out = run_cli(tmp_path, monkeypatch, AutoSubmitModel(), max_tokens=10_000)
    cli.main()
    report, events = load(out)
    statuses = [r["status"] for r in report["alerts"]]
    assert statuses[0] == "classified" and statuses[-1] == "budget_exhausted"
    assert report["budget"]["exhausted"] is True
    assert events[-1]["status"] == "budget_exhausted"


def test_a_crash_still_writes_the_report_and_one_terminal(tmp_path, monkeypatch):
    out = run_cli(tmp_path, monkeypatch, AutoSubmitModel(crash_on=4))  # in the 2nd alert's remediation
    with pytest.raises(RuntimeError):
        cli.main()
    report, events = load(out)
    statuses = [r["status"] for r in report["alerts"]]
    assert statuses[:2] == ["classified", "classified"]
    assert set(statuses[2:]) == {"error"}
    assert events[-1]["status"] == "crashed"


def test_a_failed_scan_still_writes_an_empty_report(tmp_path, monkeypatch):
    out = run_cli(tmp_path, monkeypatch, AutoSubmitModel(), input_dir=tmp_path / "missing")
    with pytest.raises(Exception):
        cli.main()
    report, events = load(out)
    assert report["alerts"] == [] and report["scan"]["alert_count"] == 0
    assert events[-1]["status"] == "crashed"