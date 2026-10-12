"""Discovery stage: run Bandit over the [scan] scope and parse its JSON report."""

import glob
import json
import re
import subprocess
import sys
import tempfile
from importlib.metadata import version
from pathlib import Path


class BanditError(Exception):
    """Bandit could not be run, or its output could not be parsed."""


def expand_paths(input_dir: Path, patterns: list[str]) -> list[str]:
    """Expand the [scan].paths globs relative to the target root."""
    paths = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern, root_dir=input_dir))
        if not matches:
            raise BanditError(f"scan path matched nothing: {pattern}")
        paths.extend(matches)
    return paths


def build_command(scan: dict, paths: list[str], out_file: Path) -> list[str]:
    """Translate a [scan] block into a Bandit command line."""
    cmd = [
        sys.executable, "-m", "bandit",
        "-q", "-r",
        "--severity-level", scan["min_severity"].lower(),
        "-f", "json", "-o", str(out_file),
    ]
    if scan["exclude"]:
        cmd += ["-x", ",".join(scan["exclude"])]
    return cmd + paths


def make_alert_id(path: str, line: int, test_id: str) -> str:
    """Build an id matching ^[A-Za-z0-9._-]+$, e.g. testcode-BenchmarkTest00011-py-47-B608."""
    slug = re.sub(r"[^A-Za-z0-9]+", "-", path).strip("-")
    return f"{slug}-{line}-{test_id}"


def parse_results(data: dict) -> list[dict]:
    """Turn Bandit's JSON into alert dicts, sorted by path, line, test_id."""
    alerts = []
    for result in data["results"]:
        path = result["filename"].removeprefix("./")
        alerts.append({
            "alert_id": make_alert_id(path, result["line_number"], result["test_id"]),
            "test_id": result["test_id"],
            "path": path,
            "line": result["line_number"],
            "severity": result["issue_severity"],
            "confidence": result["issue_confidence"],
            "issue_text": result["issue_text"],
            "code": result["code"],
        })
    alerts.sort(key=lambda a: (a["path"], a["line"], a["test_id"]))
    return alerts


def run_bandit(input_dir: Path, scan: dict) -> list[dict]:
    """Run Bandit from the target root and return the parsed alerts."""
    installed = version("bandit")
    if installed != scan["bandit_version"]:
        raise BanditError(f"bandit {installed} installed, {scan['bandit_version']} required")

    paths = expand_paths(input_dir, scan["paths"])

    # Write the JSON report to a temp dir
    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp) / "bandit.json"
        cmd = build_command(scan, paths, out_file)
        proc = subprocess.run(cmd, cwd=input_dir, capture_output=True, text=True)
        if proc.returncode not in (0, 1):
            raise BanditError(f"bandit exited {proc.returncode}: {proc.stderr.strip()}")
        try:
            data = json.loads(out_file.read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise BanditError(f"could not read bandit output: {e}") from e

    return parse_results(data)