"""Read and write rules shared by the MCP server and the code-action harness.

Fixed rules: .git, the analysis cache, the answer key and the top-level results/
folder are never readable. Per-alert rules: on OWASP only the open case's files
are readable, and only the open alert's file is writable.
"""

import fnmatch
from pathlib import Path, PurePosixPath

from vulnagent.workspace import PathEscapeError, resolve

WITHHELD_ANY_DEPTH = (".git", ".codeanalyzer")
WITHHELD_NAME_GLOBS = ("expectedresults*.csv",)
WITHHELD_AT_ROOT = ("results",)
CASE_PREFIX = "BenchmarkTest"


class Refusal(PathEscapeError):
    """A request the access rules do not allow. The message is shown to the model."""


def case_of(path: str | PurePosixPath | None) -> str | None:
    """The OWASP case a path belongs to, e.g. BenchmarkTest00011, or None."""
    if path is None:
        return None
    stem = PurePosixPath(path).name.split(".")[0]
    return stem if stem.startswith(CASE_PREFIX) else None


def withheld_reason(rel: PurePosixPath) -> str | None:
    """Why a repo-relative path is never readable, or None if it is not withheld."""
    for part in rel.parts:
        if part in WITHHELD_ANY_DEPTH:
            return f"{rel} is withheld ({part} is never readable)"
        if any(fnmatch.fnmatch(part, glob) for glob in WITHHELD_NAME_GLOBS):
            return f"{rel} is withheld (it is the answer key)"
    if rel.parts and rel.parts[0] in WITHHELD_AT_ROOT:
        return f"{rel} is withheld (other scanners' results)"
    return None


class AccessPolicy:
    """The one path check for every tool, plus the open alert set by the host."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.open_path: str | None = None  # repo-relative path of the open alert's file

    @property
    def open_case(self) -> str | None:
        return case_of(self.open_path)

    def check(self, path: str) -> PurePosixPath:
        """Apply the read rules to a path without touching the disk.

        Runs before any file access, so a withheld path is refused even when it
        does not exist in the workspace.
        """
        p = PurePosixPath(path)
        if p.is_absolute():
            raise Refusal(f"absolute paths are refused: {path}")
        if ".." in p.parts:
            raise Refusal(f"'..' is refused: {path}")
        rel = PurePosixPath(*[part for part in p.parts if part != "."]) if p.parts else PurePosixPath(".")
        reason = withheld_reason(rel)
        if reason:
            raise Refusal(reason)
        case = case_of(rel)
        if case is not None and case != self.open_case:
            if self.open_case is None:
                raise Refusal(f"{rel} is a test case and no alert is open")
            raise Refusal(f"{rel} is not the open case ({self.open_case})")
        return rel

    def resolve(self, path: str) -> Path:
        """Read check: the rules above, then HW1's resolve (no '..', no symlink out)."""
        rel = self.check(path)
        real = resolve(self.root, str(rel))
        # A symlink inside the copy could point at a withheld file: check where it lands.
        self.check(real.relative_to(self.root).as_posix() or ".")
        return real

    def resolve_write(self, path: str) -> Path:
        """Write check: readable, and the open alert's file."""
        real = self.resolve(path)
        rel = real.relative_to(self.root).as_posix()
        if self.open_path is None:
            raise Refusal(f"no alert is open, so {rel} may not be edited")
        if rel != self.open_path:
            raise Refusal(f"{rel} may not be edited: only the open alert's file ({self.open_path}) may")
        return real

    def readable(self, path: str) -> bool:
        try:
            self.check(path)
        except Refusal:
            return False
        return True
