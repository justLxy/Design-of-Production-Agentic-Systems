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
"""


class AutoSubmitModel:
    """Submits label 1 for every alert, citing the flagged line; crashes on call `crash_on`."""

    model = "fake"

    def __init__(self, crash_on: int | None = None):
        self.calls = 0
        self.crash_on = crash_on

    def complete(self, items: list[dict], tools: list[dict]) -> ModelReply:
        self.calls += 1
        if self.calls == self.crash_on:
            raise RuntimeError("simulated crash")
        path, line = re.search(r"File: (\S+), line (\d+)", items[1]["content"]).groups()
        args = {"label": 1, "rationale": "Fake rationale.",
                "evidence": [{"path": path, "start_line": int(line), "end_line": int(line)}]}
        call = ToolCall(f"call_{self.calls}", "submit", json.dumps(args))
        return ModelReply("", [call], "tool_calls", {"input": 2000, "output": 100}, [])


def run_cli(tmp_path, monkeypatch, model, max_tokens=1_000_000, input_dir=OWASP) -> Path:
    """Point the CLI at a temp config and output dir, with the fake model in place of OpenAI."""
    config = tmp_path / "config.toml"
    config.write_text(CONFIG.format(max_tokens=max_tokens))
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


def test_a_full_run_writes_a_valid_report(tmp_path, monkeypatch):
    out = run_cli(tmp_path, monkeypatch, AutoSubmitModel())
    cli.main()
    report, events = load(out)
    assert report["scan"]["alert_count"] == 18
    assert {r["status"] for r in report["alerts"]} == {"classified"}
    assert report["target"]["commit"] == "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
    assert events[-1]["status"] == "completed"


def test_a_low_budget_run_shows_the_cutoff(tmp_path, monkeypatch):
    out = run_cli(tmp_path, monkeypatch, AutoSubmitModel(), max_tokens=10_000)
    cli.main()
    report, events = load(out)
    statuses = [r["status"] for r in report["alerts"]]
    assert statuses[0] == "classified" and statuses[-1] == "budget_exhausted"
    assert report["budget"]["exhausted"] is True
    assert events[-1]["status"] == "budget_exhausted"


def test_a_crash_still_writes_the_report_and_one_terminal(tmp_path, monkeypatch):
    out = run_cli(tmp_path, monkeypatch, AutoSubmitModel(crash_on=3))
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