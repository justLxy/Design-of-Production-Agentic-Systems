"""A disposable copy of the target, with .git and the answers withheld from the agent.

Run level (every target): .git/ and expectedresults*.csv are never copied in;
nor is a top-level results/ (OWASP ships other scanners' findings there).

Every tool checks its paths with resolve() before reading anything.
"""

import shutil
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

NEVER_COPIED = (".git", "expectedresults*.csv")
NEVER_COPIED_AT_ROOT = ("results",)
CASE_GLOB = "BenchmarkTest*"


class PathEscapeError(Exception):
    """A tool path is absolute, contains '..', or resolves outside the workspace."""


def resolve(root: Path, path: str) -> Path:
    """Return path as an absolute path inside root, or raise PathEscapeError."""
    parts = Path(path).parts
    if Path(path).is_absolute():
        raise PathEscapeError(f"absolute paths are refused: {path!r}")
    if ".." in parts:
        raise PathEscapeError(f"'..' is refused: {path!r}")

    candidate = (root / path).resolve()
    if not candidate.is_relative_to(root):
        raise PathEscapeError(f"{path!r} resolves outside the workspace")
    return candidate


class Workspace:
    """Owns the disposable copy: created on enter, deleted on exit."""

    def __init__(self, source: Path):
        self.source = source.resolve()
        self.root: Path | None = None
        self._tmp: Path | None = None
        self._stash: Path | None = None

    def __enter__(self) -> "Workspace":
        self._tmp = Path(tempfile.mkdtemp(prefix="vulnagent-")).resolve()
        self.root = self._tmp / "repo"
        self._stash = self._tmp / "withheld"
        try:
            shutil.copytree(self.source, self.root, symlinks=True, ignore=self._ignore)
        except BaseException:
            shutil.rmtree(self._tmp, ignore_errors=True)
            raise
        return self

    def __exit__(self, *_: object) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)
        self.root = None

    def _ignore(self, directory: str, names: list[str]) -> set[str]:
        """copytree callback: the entries of directory that are never copied in."""
        ignored = set(shutil.ignore_patterns(*NEVER_COPIED)(directory, names))
        if Path(directory) == self.source:
            ignored |= set(names) & set(NEVER_COPIED_AT_ROOT)
        return ignored

    def resolve(self, path: str) -> Path:
        return resolve(self.root, path)

    def withheld(self) -> list[str]:
        """Files currently moved out of the copy, as repo-relative paths."""
        return sorted(str(p.relative_to(self._stash))
                      for p in self._stash.rglob("*") if p.is_file())

    @contextmanager
    def investigating(self, alert_path: str) -> Generator[None, None, None]:
        """Withhold every BenchmarkTest* file except the alert's own case, then restore them."""
        case = Path(alert_path).stem
        moved: list[Path] = []
        try:
            for path in sorted(self.root.rglob(CASE_GLOB)):
                if path.is_file() and path.stem != case:
                    rel = path.relative_to(self.root)
                    target = self._stash / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(path, target)
                    moved.append(rel)
            yield
        finally:
            for rel in moved:
                shutil.move(self._stash / rel, self.root / rel)