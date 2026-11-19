"""The MCP server: CLDK analysis, text, edit and rescan tools over one workspace copy.

    python -m vulnagent.server [--source DIR] [--workdir DIR]

The server serves a disposable copy of the target. With --source (or
VULNAGENT_SOURCE) it copies that directory; without it, it stages the granted
entries of VULNAGENT_TARGET_ROOT (default /target), so the staff driver can
start it in a fresh sandbox. Every path goes through AccessPolicy. Refusals are
tool errors whose text starts with "refused"; when the operating system denies
an access that passed the policy, the text starts with "refused (kernel)".

Parts of this file follow the lecture 6 reference server (reference/cldk_mcp_server.py).
"""

import argparse
import functools
import os
import re
import shutil
import sys
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, TypedDict

import jsonschema
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from vulnagent import tools as text_tools
from vulnagent.bandit_tool import BanditError
from vulnagent.patching import check_patch, make_diff, rescan as bandit_rescan
from vulnagent.policy import AccessPolicy, Refusal, case_of, withheld_reason

SERVER_NAME = "vulnagent"
HOST_ONLY = ("set_alert", "review_patch")
DEFAULT_ENTRIES = "testcode:helpers:app.py:radicale:python:scripts"
MAX_SITES = 100
ANALYSIS_WAIT_S = 900
CLDK_NAME_ERRORS = ("AmbiguousName", "SelectorNotInGraph")
ALERT_ID = re.compile(r"^(?P<slug>.+)-(?P<line>\d+)-(?P<test_id>B\d{3})$")
CASE_NAME = re.compile(r"^BenchmarkTest\d+$")


def log(message: str) -> None:
    print(f"[{SERVER_NAME}] {message}", file=sys.stderr, flush=True)


def keep_stdout_for_json_rpc() -> None:
    """Move the real stdout to a private fd and point fd 1 at stderr.

    The transport then owns the only handle on the real stdout, so prints and
    child processes (CLDK, Bandit) cannot write anything but JSON-RPC to it.
    """
    real = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = os.fdopen(real, "w", buffering=1, encoding="utf-8")


# Staging

def stage(source: Path | None, target_root: Path, entries: list[str], workdir: Path) -> tuple[Path, Path]:
    """Return (pristine, workspace): the read-only input and the disposable copy the tools serve."""
    workdir.mkdir(parents=True, exist_ok=True)
    if source is not None and source.is_dir():
        pristine = source.resolve()
    else:
        pristine = workdir / "pristine"
        pristine.mkdir(exist_ok=True)
        for entry in entries:
            src = target_root / entry
            try:
                if src.is_dir():
                    shutil.copytree(src, pristine / entry, symlinks=True, dirs_exist_ok=True)
                elif src.is_file():
                    (pristine / entry).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, pristine / entry)
            except OSError as e:  # an entry the policy does not grant, or one this target lacks
                log(f"skipped {src}: {e}")
    workspace = workdir / "target"
    if workspace.exists():
        shutil.rmtree(workspace)

    def ignore(directory: str, names: list[str]) -> set[str]:
        rel = PurePosixPath(Path(directory).relative_to(pristine).as_posix())
        return {n for n in names if withheld_reason(rel / n) is not None}

    shutil.copytree(pristine, workspace, symlinks=True, ignore=ignore)
    return pristine, workspace.resolve()


# CLDK, built in the background so initialize answers at once

class Analysis:
    def __init__(self, root: Path):
        self.root = root
        self.ready = threading.Event()
        self.error: Exception | None = None
        self.an: Any = None
        self.overview: dict[str, Any] = {}
        threading.Thread(target=self._build, daemon=True).start()

    def _build(self) -> None:
        started = time.time()
        try:
            from cldk import CLDK
            self.an = CLDK.python(project_path=str(self.root), analysis_level="program_dependency_graph")
            self.overview = {o.signature: o for o in self.an.get_callables_overview()}
            log(f"CLDK ready: {len(self.overview)} callables in {time.time() - started:.0f} s")
        except Exception as e:  # reported to every analysis call
            self.error = e
            log(f"CLDK failed: {type(e).__name__}: {e}")
        finally:
            self.ready.set()

    def get(self) -> Any:
        if not self.ready.wait(ANALYSIS_WAIT_S):
            raise ToolError("the CLDK analysis is still being built; try again later")
        if self.error is not None:
            raise ToolError(f"the CLDK analysis failed: {type(self.error).__name__}: {self.error}")
        return self.an


# Result shapes (the SDK validates every result against these)

class Located(TypedDict):
    path: str
    line: int
    signature: str | None
    name: str | None
    start_line: int | None
    end_line: int | None


class Source(TypedDict):
    signature: str
    path: str
    start_line: int
    end_line: int
    text: str


class Edge(TypedDict):
    from_line: int | None  # None: the value enters at the callable's entry (a parameter or a global)
    to_line: int | None
    var: str


class Dataflow(TypedDict):
    signature: str
    edges: list[Edge]


class Site(TypedDict):
    path: str
    line: int
    signature: str
    external: bool


class Sites(TypedDict):
    sites: list[Site]
    hidden: int


class EntryPoint(TypedDict):
    path: str
    line: int
    signature: str


class EntryPoints(TypedDict):
    entry_points: list[EntryPoint]
    total: int
    hidden: int
    frameworks: list[str]
    unresolved: dict[str, int]
    errors: list[str]


class Text(TypedDict):
    text: str


class Listing(TypedDict):
    path: str
    entries: list[str]


class Edited(TypedDict):
    path: str
    diff: str


class Finding(TypedDict):
    test_id: str
    line: int
    severity: str
    confidence: str
    issue_text: str


class Rescan(TypedDict):
    path: str
    alerts: list[Finding]


class EvidenceRange(TypedDict):
    path: str
    start_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]


class Submitted(TypedDict):
    alert_id: str
    label: int
    evidence: int


class Opened(TypedDict):
    alert_id: str
    path: str
    case: str | None


class Checks(TypedDict):
    applies: bool | None
    touches_flagged_line: bool | None
    clean_rescan: bool | None


class Review(TypedDict):
    path: str
    status: str
    diff: str
    checks: Checks


Line = Annotated[int, Field(ge=1)]


def build_server(pristine: Path, workspace: Path) -> MCPServer:
    policy = AccessPolicy(workspace)
    analysis = Analysis(workspace)
    state: dict[str, Any] = {"alert_id": None, "line": None, "test_id": None}

    def refused(message: str) -> ToolError:
        return ToolError(f"refused: {message}")

    def guarded(fn):
        """Turn rule violations into refusals and kernel denials into kernel refusals."""
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except (Refusal, text_tools.ToolError, text_tools.PathEscapeError) as e:
                raise refused(str(e)) from e
            except PermissionError as e:
                raise ToolError(f"refused (kernel): permission denied: {e.filename or e}") from e
        return wrapper

    def visible(path: str) -> bool:
        return bool(path) and policy.readable(path)

    def sites(nodes) -> Sites:
        shown: list[Site] = []
        hidden = 0
        for node in nodes:
            external = node.kind == "external"
            if not external and not visible(node.file):
                hidden += 1
                continue
            shown.append({"path": node.file, "line": node.line, "signature": node.callable, "external": external})
        return {"sites": shown[:MAX_SITES], "hidden": hidden + max(0, len(shown) - MAX_SITES)}

    def enclosing(path: str, line: int):
        rel = policy.check(path).as_posix()
        hit = analysis.get().locate(rel, line)
        if any(d.code == "file_not_in_graph" for d in hit.diagnostics or []):
            raise Refusal(f"{rel} is not in the analysed project")
        return rel, hit

    def alert_lookup(alert_id: str) -> tuple[str, int | None, str | None]:
        if CASE_NAME.match(alert_id):
            rel = f"testcode/{alert_id}.py"
            if not (workspace / rel).is_file():
                raise Refusal(f"no case named {alert_id}")
            return rel, None, None
        match = ALERT_ID.match(alert_id)
        if not match:
            raise Refusal(f"{alert_id} is not an alert id or an OWASP case name")
        slug = match["slug"]
        found = [p.relative_to(workspace).as_posix() for p in workspace.rglob("*.py")
                 if re.sub(r"[^A-Za-z0-9]+", "-", p.relative_to(workspace).as_posix()).strip("-") == slug
                 and withheld_reason(PurePosixPath(p.relative_to(workspace).as_posix())) is None]
        if len(found) != 1:
            raise Refusal(f"{alert_id} matches {len(found)} files in the workspace")
        return found[0], int(match["line"]), match["test_id"]

    mcp = MCPServer(SERVER_NAME, instructions=(
        "Analysis, text, edit and rescan tools over a disposable copy of the target. "
        "set_alert and review_patch are for the host only."))

    # Analysis tools (CLDK 2.0)

    @mcp.tool(description="The callable that encloses a line: its signature and line span, or nulls for module scope.")
    @guarded
    def locate(path: str, line: Line) -> Located:
        rel, hit = enclosing(path, line)
        if hit.callable is None:
            return {"path": rel, "line": line, "signature": None, "name": None, "start_line": None, "end_line": None}
        ov = analysis.overview.get(hit.callable.signature)
        return {"path": rel, "line": line, "signature": hit.callable.signature, "name": hit.callable.name,
                "start_line": ov.start_line if ov else None, "end_line": ov.end_line if ov else None}

    @mcp.tool(description="The numbered source of a callable, by the signature that locate returns.")
    @guarded
    def source(signature: Annotated[str, Field(min_length=1)]) -> Source:
        analysis.get()
        ov = analysis.overview.get(signature)
        if ov is None:
            raise Refusal(f"no callable has the signature {signature!r}; use locate to find one")
        policy.check(ov.path)
        body = analysis.an.get_method_bodies([signature]).get(signature, "")
        numbered = "\n".join(f"{n:>5}| {text}" for n, text in enumerate(body.splitlines(), ov.start_line))
        return {"signature": signature, "path": ov.path, "start_line": ov.start_line, "end_line": ov.end_line,
                "text": numbered}

    @mcp.tool(description=("Data-dependence edges inside the callable that encloses a line: each edge says the "
                           "value of var defined at from_line is used at to_line. from_line null means the value "
                           "enters at the callable's entry (a parameter, global or request object)."))
    @guarded
    def dataflow(path: str, line: Line) -> Dataflow:
        _, hit = enclosing(path, line)
        if hit.callable is None:
            raise Refusal(f"line {line} of {path} is at module scope, in no callable")
        page = analysis.an.get_ddg(hit.callable.signature, page_size=5000)

        def line_of(node_id: str) -> int | None:
            m = re.search(r"@(\d+):\d+$", node_id)
            return int(m.group(1)) if m else None

        edges = [{"from_line": line_of(e.src), "to_line": line_of(e.dst), "var": e.var} for e in page.edges]
        edges.sort(key=lambda e: (e["from_line"] or 0, e["to_line"] or 0, e["var"]))
        return {"signature": hit.callable.signature, "edges": edges}

    @mcp.tool(description=("Call sites that call a callable, by name. Add module (dotted, e.g. helpers.db_sqlite) "
                           "when the name is ambiguous. Sites in files you may not read are counted in hidden."))
    @guarded
    def callers(name: Annotated[str, Field(min_length=1)], module: str | None = None) -> Sites:
        try:
            return sites(analysis.get().callers_of(name, in_module=module))
        except Exception as e:
            if type(e).__name__ in CLDK_NAME_ERRORS:
                raise Refusal(str(e)) from e
            raise

    @mcp.tool(description=("What a callable calls, by name, including library calls (external: true). Add module "
                           "when the name is ambiguous."))
    @guarded
    def callees(name: Annotated[str, Field(min_length=1)], module: str | None = None) -> Sites:
        try:
            return sites(analysis.get().callees_of(name, in_module=module))
        except Exception as e:
            if type(e).__name__ in CLDK_NAME_ERRORS:
                raise Refusal(str(e)) from e
            raise

    @mcp.tool(description=("Route handlers and other entry points in files you may read, with CLDK's "
                           "entry-point coverage report (check it before trusting an empty list)."))
    @guarded
    def entry_points() -> EntryPoints:
        an = analysis.get()
        found = an.get_entrypoints()
        shown = [{"path": e.path, "line": e.start_line, "signature": e.signature} for e in found if visible(e.path)]
        cov = an.get_entrypoint_coverage()
        return {"entry_points": shown[:MAX_SITES], "total": len(found), "hidden": len(found) - len(shown[:MAX_SITES]),
                "frameworks": list(cov.frameworks_detected or []),
                "unresolved": {str(k): int(v) for k, v in (cov.unresolved or {}).items()},
                "errors": [str(x) for x in (cov.errors or [])]}

    # Text tools (HW1)

    @mcp.tool(description=f"Numbered lines of one file, at most {text_tools.MAX_READ_LINES} per call.")
    @guarded
    def read_file(path: str, start_line: Line = 1, end_line: Line | None = None) -> Text:
        return {"text": text_tools.read_file(policy, path, start_line, end_line)}

    @mcp.tool(description=f"Python regex over the files you may read; up to {text_tools.MAX_SEARCH_MATCHES} 'path:line: text' matches.")
    @guarded
    def search(pattern: Annotated[str, Field(min_length=1)], path: str = ".") -> Text:
        return {"text": text_tools.search(policy, pattern, path)}

    @mcp.tool(description="Entries of a directory you may read; directories end with '/'.")
    @guarded
    def list_dir(path: str = ".") -> Listing:
        directory = policy.resolve(path)
        if not directory.is_dir():
            raise Refusal(f"not a directory: {path}")
        rel = directory.relative_to(workspace)
        names = sorted(p.name + ("/" if p.is_dir() else "") for p in directory.iterdir()
                       if policy.readable((rel / p.name).as_posix()))
        return {"path": rel.as_posix() or ".", "entries": names[:text_tools.MAX_LIST_ENTRIES]}

    # Write tools

    @mcp.tool(description=("Replace the one exact occurrence of old with new in the open alert's file "
                           "(the only file you may edit). Returns the file's diff against the pinned commit."))
    @guarded
    def edit(path: str, old: Annotated[str, Field(min_length=1)], new: str) -> Edited:
        target = policy.resolve_write(path)
        text = target.read_text(encoding="utf-8")
        count = text.count(old)
        if count != 1:
            raise Refusal(f"old occurs {count} times in {path}; it must occur exactly once")
        target.write_text(text.replace(old, new, 1), encoding="utf-8")
        rel = target.relative_to(workspace).as_posix()
        before = (pristine / rel).read_text(encoding="utf-8")
        return {"path": rel, "diff": make_diff(rel, before, target.read_text(encoding="utf-8"))}

    @mcp.tool(description="Bandit 1.9.4 (MEDIUM and up) on one file of the workspace, as it is now.")
    @guarded
    def rescan(path: str) -> Rescan:
        target = policy.resolve(path)
        if not target.is_file():
            raise Refusal(f"not a file: {path}")
        rel = target.relative_to(workspace).as_posix()
        try:
            return {"path": rel, "alerts": bandit_rescan(workspace, rel)}
        except BanditError as e:
            raise ToolError(f"bandit failed: {e}") from e

    # The answer for the open alert

    @mcp.tool(description=("Submit the label for the open alert: 1 = potential vulnerability, 0 = not a "
                           "vulnerability, with a short rationale that cites line numbers and 1 to 5 evidence "
                           "ranges you read. Evidence must be in files you may read."))
    @guarded
    def submit(label: Literal[0, 1], rationale: Annotated[str, Field(min_length=1, max_length=2000)],
               evidence: Annotated[list[EvidenceRange], Field(min_length=1, max_length=5)]) -> Submitted:
        if state["alert_id"] is None:
            raise Refusal("no alert is open")
        text_tools.submit(policy, label, rationale, [dict(e) for e in evidence])
        return {"alert_id": state["alert_id"], "label": label, "evidence": len(evidence)}

    # Host-only controls

    @mcp.tool(description="Host only: open an alert by its id (or an OWASP case name) for the per-alert rules.",
              meta={"host_only": True})
    @guarded
    def set_alert(alert_id: Annotated[str, Field(min_length=1)]) -> Opened:
        rel, line, test_id = alert_lookup(alert_id)
        policy.open_path = rel
        state.update(alert_id=alert_id, line=line, test_id=test_id)
        return {"alert_id": alert_id, "path": rel, "case": case_of(rel)}

    @mcp.tool(description="Host only: the open alert's diff against the pinned commit and the three patch checks.",
              meta={"host_only": True})
    @guarded
    def review_patch() -> Review:
        if policy.open_path is None or state["line"] is None:
            raise Refusal("no alert id is open (set_alert with an alert id first)")
        rel = policy.open_path
        before = (pristine / rel).read_text(encoding="utf-8")
        after = (workspace / rel).read_text(encoding="utf-8")
        result = check_patch(rel, before, after, workspace, state["line"], state["test_id"])
        return {"path": rel, **result}

    mcp.middleware.append(strict_contracts(mcp))
    return mcp


def strict_contracts(mcp: MCPServer):
    """Middleware: strict argument schemas, and refusal text that starts with "refused".

    The SDK builds each input schema from the function signature but lets extra
    arguments through and prefixes errors with "Error executing tool <name>: ".
    Here every schema gets additionalProperties false, tools/list advertises that
    strict schema, and tools/call is validated against it before the tool runs.
    """
    schemas: dict[str, dict] = {}

    async def load() -> dict[str, dict]:
        if not schemas:
            for tool in await mcp.list_tools():
                schemas[tool.name] = {**tool.input_schema, "additionalProperties": False}
        return schemas

    def error(text: str) -> dict:
        return {"content": [{"type": "text", "text": text}], "isError": True}

    async def middleware(ctx, call_next):
        if ctx.method == "tools/call" and isinstance(ctx.params, dict):
            known = await load()
            name = ctx.params.get("name")
            args = ctx.params.get("arguments") or {}
            if name not in known:
                return error(f"refused: unknown tool {name!r}")
            problems = sorted(jsonschema.Draft202012Validator(known[name]).iter_errors(args), key=lambda e: list(e.path))
            if problems:
                where = "/".join(str(p) for p in problems[0].path) or "arguments"
                return error(f"refused: bad arguments for {name}: {where}: {problems[0].message}")
            result = await call_next(ctx)
            if isinstance(result, dict) and result.get("isError"):
                prefix = f"Error executing tool {name}: "
                for block in result.get("content", []):
                    if block.get("type") == "text" and block["text"].startswith(prefix):
                        block["text"] = block["text"][len(prefix):]
            return result
        result = await call_next(ctx)
        if ctx.method == "tools/list" and isinstance(result, dict):
            known = await load()
            for tool in result.get("tools", []):
                if tool.get("name") in known:
                    tool["inputSchema"] = known[tool["name"]]
        return result

    return middleware


def main() -> None:
    keep_stdout_for_json_rpc()
    parser = argparse.ArgumentParser(prog="vulnagent.server")
    parser.add_argument("--source", type=Path, default=os.environ.get("VULNAGENT_SOURCE"),
                        help="Directory with the target files to serve (default: stage from --target-root)")
    parser.add_argument("--target-root", type=Path, default=os.environ.get("VULNAGENT_TARGET_ROOT", "/target"))
    parser.add_argument("--entries", default=os.environ.get("VULNAGENT_TARGET_ENTRIES", DEFAULT_ENTRIES),
                        help="Colon-separated entries of --target-root to stage")
    parser.add_argument("--workdir", type=Path,
                        default=os.environ.get("VULNAGENT_WORKDIR", f"/sandbox/work/server-{os.getpid()}"))
    args = parser.parse_args()
    os.environ.setdefault("SYSTEM_PYTHON", sys.executable)

    source = Path(args.source) if args.source else None
    pristine, workspace = stage(source, Path(args.target_root), args.entries.split(":"), Path(args.workdir))
    log(f"serving {workspace} (pinned files in {pristine})")
    build_server(pristine, workspace).run()


if __name__ == "__main__":
    main()
