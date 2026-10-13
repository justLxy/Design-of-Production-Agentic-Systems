"""Read-only tools the model can call. Every path goes through Workspace.resolve().

Each tool returns the observation text for the model, or raises ToolError /
PathEscapeError, which the dispatcher turns into a refusal observation.
"""

import re
from pathlib import Path

from vulnagent.workspace import PathEscapeError, Workspace

MAX_READ_LINES = 200
MAX_LINE_CHARS = 300
MAX_SEARCH_MATCHES = 50
MAX_SEARCH_FILE_BYTES = 1_000_000
MAX_LIST_ENTRIES = 200


class ToolError(Exception):
    """A tool refused a request; the message is shown to the model."""


# Every exception the dispatcher should turn into a refusal rather than a crash.
REFUSALS = (ToolError, PathEscapeError)


def _clip(line: str) -> str:
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + " [...]"


def _read_lines(file: Path, shown_as: str) -> list[str]:
    try:
        return file.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as e:
        raise ToolError(f"not a UTF-8 text file: {shown_as}") from e


def read_file(ws: Workspace, path: str, start_line: int = 1, end_line: int | None = None) -> str:
    """Return lines start_line..end_line (1-based, inclusive), numbered."""
    file = ws.resolve(path)
    if not file.is_file():
        raise ToolError(f"no such file: {path}")
    lines = _read_lines(file, path)
    total = len(lines)

    if end_line is None:
        end_line = start_line + MAX_READ_LINES - 1
    if start_line < 1 or end_line < start_line:
        raise ToolError(f"invalid line range {start_line}-{end_line}")
    if start_line > total:
        raise ToolError(f"{path} has only {total} lines")

    last = min(end_line, total, start_line + MAX_READ_LINES - 1)
    header = f"{path}, lines {start_line}-{last} of {total}"
    if last < min(end_line, total):
        header += f" (capped at {MAX_READ_LINES} lines; read again from line {last + 1})"
    body = "\n".join(f"{n:>5}| {_clip(lines[n - 1])}" for n in range(start_line, last + 1))
    return f"{header}\n{body}"


def search(ws: Workspace, pattern: str, path: str = ".") -> str:
    """Regex search over the text files under path; one 'path:line: text' per match."""
    try:
        regex = re.compile(pattern)
    except re.error as e:
        raise ToolError(f"invalid regex {pattern!r}: {e}") from e

    start = ws.resolve(path)
    if start.is_file():
        files = [start]
    elif start.is_dir():
        files = sorted(p for p in start.rglob("*") if p.is_file())
    else:
        raise ToolError(f"no such file or directory: {path}")

    matches: list[str] = []
    for file in files:
        rel = file.relative_to(ws.root).as_posix()
        try:
            real = ws.resolve(rel)  # a symlink inside the tree gets the same check
        except PathEscapeError:
            continue
        if real.stat().st_size > MAX_SEARCH_FILE_BYTES:
            continue
        try:
            lines = real.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(lines, 1):
            if regex.search(line):
                matches.append(f"{rel}:{n}: {_clip(line.strip())}")
                if len(matches) == MAX_SEARCH_MATCHES:
                    return "\n".join(matches) + (
                        f"\n[stopped at {MAX_SEARCH_MATCHES} matches; narrow the pattern or path]")

    if not matches:
        return f"no matches for {pattern!r} under {path}"
    return "\n".join(matches)


def list_dir(ws: Workspace, path: str = ".") -> str:
    """List a directory's entries; directories end with '/'."""
    directory = ws.resolve(path)
    if not directory.is_dir():
        raise ToolError(f"not a directory: {path}")
    names = sorted(p.name + ("/" if p.is_dir() else "") for p in directory.iterdir())
    shown = names[:MAX_LIST_ENTRIES]
    text = "\n".join(shown) if shown else "(empty directory)"
    if len(names) > MAX_LIST_ENTRIES:
        text += f"\n[{len(names) - MAX_LIST_ENTRIES} more entries not shown]"
    return text

def submit(ws: Workspace, label: int, rationale: str, evidence: list[dict]) -> str:
    """Validate a final answer: every evidence range must exist in the workspace copy."""
    for item in evidence:
        path, start, end = item["path"], item["start_line"], item["end_line"]
        file = ws.resolve(path)
        if not file.is_file():
            raise ToolError(f"evidence file not found: {path}")
        total = len(_read_lines(file, path))
        if not 1 <= start <= end <= total:
            raise ToolError(f"evidence lines {start}-{end} are not within {path} (lines 1-{total})")
    return f"Accepted: label {label} with {len(evidence)} evidence range(s)."