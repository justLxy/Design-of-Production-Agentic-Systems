"""report.json: one row per Bandit alert, in Bandit's (already sorted) order."""

import json
import os
import subprocess
from pathlib import Path

UNKNOWN_COMMIT = "0" * 40


def target_commit(input_dir: Path) -> str:
    """HEAD of the target checkout. git reads the original --input; nothing is written."""
    try:
        proc = subprocess.run(["git", "-C", str(input_dir), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return UNKNOWN_COMMIT
    commit = proc.stdout.strip()
    return commit if len(commit) == 40 else UNKNOWN_COMMIT


def build_report(input_arg: str, commit: str, scan: dict, alerts: list[dict],
                 rows: dict[str, dict], max_tokens: int, used_tokens: int,
                 exhausted: bool) -> dict:
    return {
        "target": {"input": input_arg, "commit": commit},
        "scan": {
            "bandit_version": scan["bandit_version"],
            "min_severity": scan["min_severity"],
            "alert_count": len(alerts),
        },
        "budget": {"max_tokens": max_tokens, "used_tokens": used_tokens, "exhausted": exhausted},
        "alerts": [rows[a["alert_id"]] for a in alerts if a["alert_id"] in rows],
    }


def write_report(path: Path, report: dict) -> None:
    """Write atomically: a crash mid-write never leaves a half-written report.json."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(report, indent=2) + "\n")
    os.replace(tmp, path)


def summary(report: dict) -> str:
    rows = report["alerts"]
    ones = sum(r["label"] == 1 for r in rows)
    zeros = sum(r["label"] == 0 for r in rows)
    nulls = sum(r["label"] is None for r in rows)
    budget = report["budget"]
    return (f"{len(rows)} alerts: label 1 = {ones}, label 0 = {zeros}, null = {nulls}; "
            f"used {budget['used_tokens']} of {budget['max_tokens']} tokens")