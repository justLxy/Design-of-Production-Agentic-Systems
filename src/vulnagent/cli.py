import argparse
import time
from pathlib import Path

from dotenv import load_dotenv

from vulnagent.bandit_tool import BanditError, run_bandit
from vulnagent.config import load_config
from vulnagent.trace import TerminalStatus, Trace


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="vulnagent")
    parser.add_argument("--input", required=True, type=Path, help="Root of the target checkout")
    parser.add_argument("--output", required=True, type=Path, help="Directory for report.json and trace.jsonl")
    parser.add_argument("--config", required=True, type=Path, help="Configuration file in .toml format")
    args = parser.parse_args()

    cfg = load_config(args.config)
    args.output.mkdir(parents=True, exist_ok=True)
    run_id = f"{args.input.resolve().name}-{int(time.time())}"
    trace = Trace(args.output / "trace.jsonl", run_id)

    try:
        scan = cfg["scan"]
        trace.tool_request(None, "bandit", {
            "paths": scan["paths"],
            "exclude": scan["exclude"],
            "min_severity": scan["min_severity"],
        })
        try:
            alerts = run_bandit(args.input, scan)
        except BanditError as e:
            trace.tool_result(None, "bandit", ok=False, error=str(e))
            raise
        trace.tool_result(None, "bandit", ok=True, alerts=len(alerts))

        print(f"{len(alerts)} alerts")
        trace.terminal(TerminalStatus.COMPLETED)
    except BaseException:
        if not trace.closed:
            trace.terminal(TerminalStatus.CRASHED)
        raise