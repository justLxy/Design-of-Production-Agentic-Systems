"""Command line: vulnagent --input <checkout> --output <dir> --config <config.toml>."""

import argparse
import time
from pathlib import Path
import shutil

from dotenv import load_dotenv

from vulnagent.bandit_tool import run_bandit
from vulnagent.config import load_config
from vulnagent.graph import Agent
from vulnagent.llm import ModelClient
from vulnagent.report import build_report, summary, target_commit, write_report
from vulnagent.trace import TerminalStatus, Trace
from vulnagent.workspace import Workspace


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="vulnagent")
    parser.add_argument("--input", required=True, type=Path, help="Root of the target checkout")
    parser.add_argument("--output", required=True, type=Path,
                        help="Directory for report.json and trace.jsonl")
    parser.add_argument("--config", required=True, type=Path, help="Configuration file in .toml format")
    return parser.parse_args()


def discover(input_dir: Path, scan: dict, trace: Trace) -> list[dict]:
    """Discovery: run Bandit over the [scan] scope, recorded as one tool_request/tool_result pair."""
    trace.tool_request(None, "bandit", {
        "paths": scan["paths"],
        "exclude": scan["exclude"],
        "min_severity": scan["min_severity"],
    })
    try:
        alerts = run_bandit(input_dir, scan)
    except BaseException as e:
        trace.tool_result(None, "bandit", ok=False, error=f"{type(e).__name__}: {e}")
        raise
    trace.tool_result(None, "bandit", ok=True, alerts=len(alerts))
    return alerts


def main() -> None:
    load_dotenv()
    args = parse_args()
    cfg = load_config(args.config)
    args.output.mkdir(parents=True, exist_ok=True)
    # save a copy of the config next to the outputs
    saved_config = args.output / "config.toml"
    if args.config.resolve() != saved_config.resolve():
        shutil.copyfile(args.config, saved_config)
    trace = Trace(args.output / "trace.jsonl", f"{args.input.resolve().name}-{int(time.time())}")

    agent: Agent | None = None
    alerts: list[dict] = []
    status = TerminalStatus.CRASHED  # replaced only if agent.run() returns
    try:
        model = cfg["model"]
        client = ModelClient(model["provider"], model["name"], cfg["budget"]["output_allowance"],
                             model.get("reasoning_effort"))
        # create the agent before Bandit runs, so a later crash can still settle every alert
        agent = Agent(cfg, Workspace(args.input), trace, client)
        alerts = agent.alerts = discover(args.input, cfg["scan"], trace)
        with agent.ws:
            status = agent.run(alerts)
    except BaseException as e:
        if agent is not None:
            agent.settle_remaining("error", f"Not classified: the run crashed ({type(e).__name__}: {e}).",
                                   node="crash")
        raise
    finally:
        # always write the terminal event and report.json, also after a crash
        trace.terminal(status)
        report = build_report(
            str(args.input), target_commit(args.input), cfg["scan"], alerts,
            agent.rows if agent is not None else {},
            cfg["budget"]["max_tokens"], trace.used_tokens,
            agent.budget.exhausted if agent is not None else False,
        )
        write_report(args.output / "report.json", report)
        print(f"{status}: {summary(report)}")