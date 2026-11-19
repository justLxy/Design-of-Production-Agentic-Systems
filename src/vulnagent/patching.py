"""Patch diff and the three acceptance checks, shared by the MCP server and the code-action harness.

applies: the diff applies cleanly to the file at the pinned commit.
touches_flagged_line: the diff removes or changes the flagged line.
clean_rescan: the patched file still parses, and Bandit, run with --ignore-nosec, no
longer reports the alert's rule in the changed region.
"""

import ast
import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path

from vulnagent.bandit_tool import run_bandit

HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
NO_NEWLINE = "\\ No newline at end of file"


@dataclass
class Hunk:
    old_start: int
    old_len: int
    new_start: int
    new_len: int
    lines: list[tuple[str, str]] = field(default_factory=list)  # (" ", "-" or "+", text with newline)


def make_diff(path: str, before: str, after: str) -> str:
    """A unified diff from the pinned file to the edited one, or "" if nothing changed."""
    if before == after:
        return ""
    out = []
    for line in difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                     fromfile=f"a/{path}", tofile=f"b/{path}"):
        out.append(line if line.endswith("\n") else line + "\n" + NO_NEWLINE + "\n")
    return "".join(out)


def parse_hunks(diff: str) -> list[Hunk]:
    hunks: list[Hunk] = []
    for line in diff.splitlines(keepends=True):
        match = HUNK_HEADER.match(line)
        if match:
            old_start, old_len, new_start, new_len = match.groups()
            hunks.append(Hunk(int(old_start), int(old_len or 1), int(new_start), int(new_len or 1)))
        elif hunks and line.startswith(NO_NEWLINE):
            tag, text = hunks[-1].lines[-1]
            hunks[-1].lines[-1] = (tag, text.rstrip("\n"))
        elif hunks and line[:1] in (" ", "-", "+"):
            hunks[-1].lines.append((line[0], line[1:]))
    return hunks


def apply_diff(diff: str, original: str) -> str | None:
    """The patched text, or None if any hunk's context or removed lines do not match."""
    old = original.splitlines(keepends=True)
    out: list[str] = []
    pos = 0
    for hunk in parse_hunks(diff):
        start = hunk.old_start - 1 if hunk.old_len else hunk.old_start
        if start < pos:
            return None
        out.extend(old[pos:start])
        pos = start
        for tag, text in hunk.lines:
            if tag in (" ", "-"):
                if pos >= len(old) or old[pos] != text:
                    return None
                pos += 1
                if tag == " ":
                    out.append(text)
            else:
                out.append(text)
    out.extend(old[pos:])
    return "".join(out)


def touched_region(diff: str, line: int) -> tuple[int, int] | None:
    """New-file line range of the hunk that removes or changes `line`, or None if no hunk does."""
    for hunk in parse_hunks(diff):
        old_no = hunk.old_start
        for tag, _ in hunk.lines:
            if tag == "-" and old_no == line:
                return hunk.new_start, hunk.new_start + max(hunk.new_len, 1) - 1
            if tag in (" ", "-"):
                old_no += 1
    return None


def rescan(root: Path, rel_path: str) -> list[dict]:
    """Bandit 1.9.4, MEDIUM and up, on one file under root.

    --ignore-nosec: a "# nosec" comment hides a finding from Bandit without fixing anything.
    """
    scan = {"paths": [rel_path], "exclude": [], "min_severity": "MEDIUM", "bandit_version": "1.9.4",
            "ignore_nosec": True}
    return [{"test_id": a["test_id"], "line": a["line"], "severity": a["severity"],
             "confidence": a["confidence"], "issue_text": a["issue_text"]}
            for a in run_bandit(root, scan)]


def parses(source: str) -> bool:
    try:
        ast.parse(source)
    except (SyntaxError, ValueError):
        return False
    return True


def check_patch(path: str, original: str, current: str, scan_root: Path,
                line: int, test_id: str) -> dict:
    """The remediation fields for one alert: diff, the three checks, and the status."""
    diff = make_diff(path, original, current)
    if not diff:
        checks = {"applies": None, "touches_flagged_line": None, "clean_rescan": None}
        return {"status": "rejected", "diff": "", "checks": checks}
    region = touched_region(diff, line)
    if region is None:
        clean = None
    elif not parses(current):
        clean = False  # Bandit skips a file it cannot parse, so its silence would mean nothing
    else:
        start, end = region
        clean = not any(a["test_id"] == test_id and start <= a["line"] <= end
                        for a in rescan(scan_root, path))
    checks = {"applies": apply_diff(diff, original) == current,
              "touches_flagged_line": region is not None,
              "clean_rescan": clean}
    status = "accepted" if all(v is True for v in checks.values()) else "rejected"
    return {"status": status, "diff": diff, "checks": checks}
