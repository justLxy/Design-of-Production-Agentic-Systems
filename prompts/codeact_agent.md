# CLDK in run_python

This guide covers cldk 2.0.0 with its analyzer codeanalyzer-python 1.5.3, the versions in your kernel. The
API changed a lot in 2.0, so use the names and signatures written here, not ones you remember.

## 1. Build the analysis once

Run this cell at the start of every alert. After the first build it does nothing (or, on a very large
project, switches to the alert's file in a few seconds):

```python
import os, time
from cldk import CLDK

def py_bytes():
    """Size of the .py files the analyzer would read (os.stat only, no file is opened)."""
    total = 0
    for d, dirs, names in os.walk(WORKSPACE):
        dirs[:] = [x for x in dirs if x not in (".codeanalyzer", ".git", "test", "tests")]
        total += sum(os.path.getsize(os.path.join(d, n)) for n in names if n.endswith(".py"))
    return total

if "FULL" not in globals():
    FULL = py_bytes() < 5_000_000      # OWASP 2.2 MB, Radicale 0.8 MB: True. SGLang 19 MB: False
want = None if FULL else [ALERT["path"]]
if "py" not in globals() or py.target_files != want:
    t0 = time.time()
    py = CLDK.python(WORKSPACE, analysis_level="system_dependency_graph", target_files=want)
    print(f"CLDK ready in {time.time() - t0:.0f} s")
```

- `CLDK.python(project_path, *, analysis_level="symbol_table", target_files=None, eager=False,
  backend=None) -> PythonAnalysis`. The default level has no data flow; `"program_dependency_graph"` adds
  control flow and control and data dependence inside each callable; `"system_dependency_graph"` also
  links callables, which the value queries (`resolve_value`, slices, `paths_between`, `flows_to_*`) need.
- Cost: the first build took 211 s and 1.5 GB on OWASP (1,236 files, 3,710 callables) and 268 s and 2.3 GB
  on Radicale (75 files); a fresh kernel then loads the cache in 25–50 s. If a build ever times out, use
  `"program_dependency_graph"` (Radicale: 46 s): section 4 still works, the value queries do not. SGLang
  as a whole took 37 minutes and 25 GB, so above 5 MB the cell analyses only `ALERT["path"]` (about 5 s);
  that analysis knows one file only, so search for callers in other files as text.
- The cache is in `WORKSPACE/.codeanalyzer/` (218 MB for OWASP): never read it; prune it when you walk
  directories. Pass only `WORKSPACE`, never `/target` (the sandbox refuses to list it), and never
  `eager=True` (it discards the cache). After a timeout the kernel restarts empty: resend this cell and
  section 4. Files under `test/` or `tests/`, `test_*.py` and `*_test.py` are not analysed in whole-project
  mode (`file_not_in_graph`), so read them as text. The analysis is a snapshot: classify before you edit.

## 2. Identifiers

- **path**: repo-relative, as in `ALERT["path"]` (`testcode/BenchmarkTest01234.py`, `radicale/app/put.py`).
  `LocateResult.module.path`, `PyCallableOverview.path` and `SliceNode.file` use the same form. `locate`
  also accepts `./x.py` or an absolute path; `get_python_module` needs the exact key.
- **signature**: the dotted name of a callable (`radicale.app.Application._handle_request`); nested
  functions include their enclosing ones, without `<locals>`:
  `testcode.BenchmarkTest01234.init.BenchmarkTest01234_post`. Arguments naming a callable (`name`, `callable`, `within`, `callee`, `src`/`dst`
  of call queries) take the signature or a dotted suffix ending at a `.` (`"db_sqlite.results"`); an exact
  match wins. Several matches raise `AmbiguousName` (`.candidates`), none raises `SelectorNotInGraph`;
  narrow with `in_class=` (a class) or `in_module=` (a path or dotted module), or more of the path. Library functions
  (`eval`, `Cursor.execute`) are not project callables and cannot be named.
- **module_name**: the last segment only (`BenchmarkTest01234`, `utils`); `get_method` wants it.
- **body-node id**: one node inside a callable, such as `can://target/python/<path>/init(app)/f()@46:2`
  (line 46, column 2), `...@entry` or `...@formal_in:1`. `LocateResult.node_id`, the `src`/`dst` of graph
  edges and `SliceNode.ref` are such ids. They are opaque: never build or parse one. Pass it to `get_source`,
  or map it to a line through the callable's `body` (see `pycallable`): each `BodyNode` has `.id`, `.kind`,
  `.span` (`.start`/`.end` are `(line, col)`) and `.of`. Synthetic nodes have no span: `entry`, `exit`,
  `formal_in` (a value entering: a parameter, a global `<global>:module::name` or a capture
  `<capture>:name`), `formal_out`, and `actual_in`/`actual_out` (an argument into a call, its return value).
- **SliceNode** `(file, line, callable, kind, name, defined_in, source, ref)`: a resolved position (a value
  vertex gets the callable's first line); `source` is `None` until `describe(nodes)`. Library callees have
  `kind="external"`, `file=""`, `line=0`.

## 3. Methods of `py`

The results are pydantic models: print the fields you need, never whole objects.

- `locate(path: str, line: int) -> LocateResult` never raises. `.callable` is a `CallableRef`
  (`signature`, `name`, `class_signature`), or `None` (then `.diagnostics[i].code` is `"module_scope"` or
  `"file_not_in_graph"`). `.span` and `.source` are the callable's (the module's text at module scope).
  `.body`/`.node_id` is the innermost node on the line, `None` on a `def`, blank or comment line. A
  decorator line belongs to its function.
  `locate_many(positions: Sequence[tuple[str, int]]) -> list[LocateResult]`.
- `get_source(node_id: str) -> str`: text of a callable (full signature) or body node, else `KeyError`.
  `get_method_bodies(signatures: list[str]) -> dict[str, str]` silently omits unknown signatures.
- `get_ddg(callable: str, *, in_class=None, page_size=10_000, cursor=None) -> EdgePage[DdgEdge]`: data
  dependence inside one callable. Each `DdgEdge` has `src`, `dst`, `var` (what flows; container elements
  appear as `name[*]`, attributes as `a.b`) and `prov` (`["ssa"]`, `["reaching-defs"]`, or the broader,
  alias-based `["points-to"]`). Iterate the page; it has `.total`, `.next_cursor` (`None` on the last page)
  and `.complete`. `get_cdg(...) -> EdgePage[CdgEdge]` (`dst` is control dependent on `src`) and `get_cfg`
  take the same arguments. They raise `AmbiguousName`, `SelectorNotInGraph`, `ValueError` (page arguments)
  and `CodeanalyzerUsageException` (level too low).
- `resolve_value(name: str, *, within: str) -> SliceNode`: `name` must enter `within` (a parameter, a
  global it reads such as `"request"`, or a capture); a local variable raises `SelectorNotInGraph`.
- `slice_backward(src: str, *, within: str, depth: int | None = 5, max_nodes: int = 10_000) -> Slice` and
  `slice_forward(...)`: what an entering value depends on or affects, across callables. Iterate the
  `Slice` for SliceNodes; it has `.total`, `.complete` and `.root`.
- `paths_between(src, dst, *, src_within, dst_within, depth=None, max_paths=10) -> FlowPaths`: the shortest
  flows between two entering values (usually `dst` is a callee's parameter). Each `FlowPath` has `.hops`,
  each with `frm`/`to` (SliceNode), `via` (`data`, `control`, `argument`, `return`, `summary`), `var` and
  `prov`. `flows_to_call(src, callee, *, within, depth=None) -> bool` and
  `flows_to_argument(src, callee, arg, *, within, depth=None) -> bool` need a project `callee`. These value
  queries raise `AmbiguousName`, `SelectorNotInGraph` and `ValueError`.
- `callers_of(name, *, in_class=None, in_module=None) -> list[SliceNode]` and `callees_of(...)` (including
  library calls such as `builtins.Cursor.execute`). An empty list means "none"; a bad name raises.
  `get_callsites_for(signatures: list[str]) -> dict[str, list[PyCallsite]]`: each `PyCallsite` has
  `method_name`, `start_line`, `callee_signature` and `arguments` (`.value`).
- `resolve_callable(name, *, in_class=None, in_module=None) -> SliceNode` (`.callable` = full signature),
  `reaches(src, dst, *, depth=None) -> bool`,
  `backward_cone(sinks: Sequence[str], *, depth=5, max_nodes=10_000) -> Slice` (callers that can reach).
- `get_callables_overview() -> list[PyCallableOverview]` (`signature, name, class_signature, kind, path,
  start_line, end_line, decorators`). `get_entrypoints()` returns the same type for callables invoked from
  outside, such as Flask routes; the route is in `pycallable(sig, path).entrypoints` (`route`,
  `http_methods`). `get_python_module(file_path) -> PyModule | None` (`module_name`, `functions`, `types`).

## 4. Helpers: define them once, reuse them for every alert

```python
from collections import defaultdict
from cldk.utils.exceptions import AmbiguousName, SelectorNotInGraph, CodeanalyzerUsageException

def show(path, start, end, mark=None):
    """Print lines start..end of a workspace file, numbered; '>' marks line `mark`."""
    with open(os.path.join(WORKSPACE, path), encoding="utf-8") as f:
        lines = f.read().splitlines()
    for n in range(max(1, start), min(end, len(lines)) + 1):
        print(f"{'>' if n == mark else ' '}{n:5} {lines[n - 1].expandtabs(4)}")

def callable_at(path, line):
    """(signature, first line, last line) of the innermost callable around path:line, or None."""
    r = py.locate(path, line)
    if r.callable is None:
        return print("no callable:", [d.message for d in r.diagnostics])
    return r.callable.signature, r.span.start[0], r.span.end[0]

def pycallable(sig, path):
    """The full PyCallable of `sig` (nested functions too), searched in the module at `path`."""
    mod = py.get_python_module(path)
    todo = [*mod.functions.values(), *mod.types.values()] if mod else []
    while todo:
        x = todo.pop()
        if getattr(x, "signature", None) == sig and hasattr(x, "body"):
            return x
        todo += [*x.callables.values(), *x.types.values()]
    return None

def value_sources(path, line, hops=10, prov=("ssa", "reaching-defs")):
    """Where do the values used on `line` come from? Walks data dependence backwards inside the
    callable and prints 'line <- source (vars)'. prov=None adds the broader points-to edges."""
    sig = py.locate(path, line).callable.signature
    body = pycallable(sig, path).body
    name = {b.id: b.span.start[0] if b.span else f"<{b.kind} {b.of or ''}>".replace(" >", ">")
            for b in body.values()}
    into = defaultdict(list)
    for e in py.get_ddg(sig, page_size=10**9):    # one page holds every edge
        if prov is None or set(e.prov) & set(prov):
            into[e.dst].append(e)
    cover = [b for b in body.values() if b.span and b.span.start[0] <= line <= b.span.end[0]]
    inner = min((b.span.end[0] - b.span.start[0] for b in cover if b.kind != "call"), default=0)
    frontier = {b.id for b in cover if b.span.end[0] - b.span.start[0] <= inner}
    seen = set(frontier)
    for _ in range(hops):
        nxt = set()
        for dst in frontier:
            srcs = defaultdict(set)
            for e in into[dst]:
                srcs[name[e.src]].add(e.var)
                if e.src not in seen:
                    seen.add(e.src)
                    nxt.add(e.src)
            if srcs:
                print(f"  {name[dst]} <- " + "; ".join(f"{s} ({', '.join(sorted(v))})" for s, v in srcs.items()))
        frontier = nxt
    return sig

def guards(path, line):
    """Lines of the if/while/for conditions that decide whether `line` runs."""
    sig = py.locate(path, line).callable.signature
    body = pycallable(sig, path).body
    by_id, up = {b.id: b for b in body.values()}, defaultdict(set)
    for e in py.get_cdg(sig):
        up[e.dst].add(e.src)
    todo = [b.id for b in body.values() if b.span and b.span.start[0] <= line <= b.span.end[0]]
    start, seen = set(todo), set(todo)
    while todo:
        for src in up[todo.pop()] - seen:
            seen.add(src)
            todo.append(src)
    return sorted({by_id[i].span.start[0] for i in seen - start if i in by_id and by_id[i].kind in ("branch", "loop")})

def who_calls(name, limit=8, **narrow):
    """Callers of a callable (signature or unique dotted suffix) and the lines of the calls."""
    try:
        target = py.resolve_callable(name, **narrow)
        callers = py.callers_of(target.callable)
    except (AmbiguousName, SelectorNotInGraph) as e:
        print(type(e).__name__, str(e)[:300])
        return []
    print(f"{len(callers)} caller(s) of {target.callable}")
    for n in callers[:limit]:
        sites = py.get_callsites_for([n.callable]).get(n.callable, [])
        lines = [s.start_line for s in sites if s.method_name == target.name]
        print(f"  {n.callable}  {n.file}:{n.line}  calls at lines {lines}")
    return callers
```

CLDK tells you which lines matter, and `show` lets you read them. Put lookups by a name you typed inside
`try/except (AmbiguousName, SelectorNotInGraph)` so one bad name does not end the cell. End a cell with a
statement (`_ = who_calls(sig)`), because a final expression has its repr printed.

## 5. Worked example: B608 at `testcode/BenchmarkTestNNNNN.py:46`

```python
p, ln = ALERT["path"], ALERT["line"]
sig, start, end = callable_at(p, ln)
EP = globals().get("EP") or {o.signature for o in py.get_entrypoints()}
print(sig, f"lines {start}-{end}", "(entry point)" if sig in EP else "")
show(p, max(start, ln - 15), min(end, ln + 5), mark=ln)
value_sources(p, ln)
print("guards:", guards(p, ln), "| callees:", [n.callable for n in py.callees_of(sig)])
_ = who_calls(sig)
```

Output (shortened):
```
testcode.BenchmarkTestNNNNN.init.BenchmarkTestNNNNN_post lines 28-55 (entry point)
    33         wrapped = helpers.separate_request.request_wrapper(request)
    34         param = wrapped.get_form_parameter("BenchmarkTestNNNNN")
    40         map8812['keyB-8812'] = param
    42         bar = map8812['keyB-8812']
>   46         sql = f'SELECT username from USERS where password = \'{bar}\''
    49         cur.execute(sql)
  46 <- 42 (bar)
  42 <- 38 (map8812[*]); 41 (map8812[*])
  40 <- 34 (param); 36 (param); 38 (map8812); 39 (map8812)
  34 <- 33 (wrapped, wrapped.get_form_parameter); <actual_out <return>> (<return>); ...
  33 <- 31 (...); <formal_in <global>:BenchmarkTestNNNNN::request> (BenchmarkTestNNNNN::request); ...
guards: [] | callees: [..., 'builtins.Cursor.execute', ..., 'helpers.separate_request.request_wrapper.get_form_parameter']
1 caller(s) of testcode.BenchmarkTestNNNNN.init.BenchmarkTestNNNNN_post
  testcode.BenchmarkTestNNNNN.init.BenchmarkTestNNNNN_get  testcode/BenchmarkTestNNNNN.py:24  calls at lines [25]
```

Read it bottom up: line 33 wraps the Flask global `request`, 34 takes `param` from the return value of
`get_form_parameter`, 40 stores it in a dict and 42 reads `bar` back. Dict entries merge into `map8812[*]`,
so read lines 38–42 to check the key. Line 46 builds the query from `bar`, with no guard. Next,
`print(py.get_source(py.resolve_callable("get_form_parameter").callable))` shows the helper, and
`py.flows_to_argument("request", "helpers.db_sqlite.results", "sql", within=sig)` (`True`) checks the flow
across callables. A walk that ends at `<formal_in x>` for a parameter `x` continues in the callers:
`who_calls(sig)`, then `value_sources(caller_path, call_line)`, or `py.slice_backward("x", within=sig)`.

## 6. Remediation (label 1 only)

Edit only `os.path.join(WORKSPACE, ALERT["path"])` by string replacement: the flagged line, plus only the
lines the fix cannot do without, keeping the file's indentation (OWASP uses tabs).

```python
import ast, difflib, json, subprocess
ORIGINALS = globals().get("ORIGINALS", {})

def patch(edits, add_above=None):
    """edits: [(line, old, new)] replace `old` once on that line and must include the flagged line.
    add_above: a line (e.g. "import ast") put above the flagged statement, same indentation."""
    path = os.path.join(WORKSPACE, ALERT["path"])
    with open(path, encoding="utf-8") as f:
        before = f.read()
    lines = before.splitlines(keepends=True)
    assert ALERT["line"] in [ln for ln, _, _ in edits], "the flagged line must change"
    for ln, old, new in edits:
        if old not in lines[ln - 1]:
            raise ValueError(f"{old!r} is not on line {ln}: {lines[ln - 1]!r}")
        lines[ln - 1] = lines[ln - 1].replace(old, new, 1)
    if add_above:
        stmts = [n for n in ast.walk(ast.parse(before)) if isinstance(n, ast.stmt)
                 and n.lineno <= ALERT["line"] <= n.end_lineno]
        j = min(stmts, key=lambda n: n.end_lineno - n.lineno).lineno - 1
        lines.insert(j, lines[j][: len(lines[j]) - len(lines[j].lstrip())] + add_above + "\n")
    after = "".join(lines)
    compile(after, path, "exec")                  # a SyntaxError stops here; nothing is written
    ORIGINALS.setdefault(ALERT["path"], before)   # the version before your first edit
    with open(path, "w", encoding="utf-8") as f:
        f.write(after)
    print("".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                       "a/" + ALERT["path"], "b/" + ALERT["path"])))

def undo():
    """Put the alert's file back as it was before your first patch()."""
    with open(os.path.join(WORKSPACE, ALERT["path"]), "w", encoding="utf-8") as f:
        f.write(ORIGINALS.pop(ALERT["path"]))

def rescan():
    """Run Bandit on the alert's file and say whether the alert's rule is still reported."""
    proc = subprocess.run(["bandit", "-q", "-f", "json", ALERT["path"]],
                          cwd=WORKSPACE, capture_output=True, text=True)
    if proc.returncode not in (0, 1):             # 0: no findings, 1: findings, else: failure
        return print("bandit failed:", proc.returncode, proc.stderr[-500:])
    report = json.loads(proc.stdout)
    if report["errors"]:                          # e.g. a syntax error: not a clean result
        print("bandit could not scan:", report["errors"])
    for r in report["results"]:
        print(r["test_id"], r["line_number"], r["issue_severity"], r["issue_confidence"], r["issue_text"][:70])
    same = [r["line_number"] for r in report["results"] if r["test_id"] == ALERT["test_id"]]
    print(f"{ALERT['test_id']} still reported at lines {same}" if same else f"{ALERT['test_id']} no longer reported")
```

For the example, `patch([(46, "f'SELECT username from USERS where password = \\'{bar}\\''",
"'SELECT username from USERS where password = ?'"), (49, "cur.execute(sql)", "cur.execute(sql, (bar,))")])`
printed a one-hunk diff, and `rescan()` then printed `B608 no longer reported`. Bandit flags any f-string
that builds SQL, even one without placeholders, so a SQL fix uses a plain string with `?` parameters.
`rescan` runs `bandit -q -f json <ALERT["path"]>` in WORKSPACE (or `[sys.executable, "-m", "bandit", ...]`
if `bandit` is not on PATH). The JSON has `results` and `errors`; each result has `test_id`, `filename`
(with a `./` prefix), `line_number`, `line_range`, `issue_severity`, `issue_confidence`, `issue_text` and
`code`. Bandit also exits with 0 when the file does not parse, so always read `errors`. If the rule is
still reported or the fix was wrong, call `undo()` and try again.

## 7. Common mistakes with this SDK version

- No `analysis_level`: `get_ddg`/`get_cdg`/`get_cfg` and the slices raise `CodeanalyzerUsageException`; at
  `"program_dependency_graph"` the value queries raise `SelectorNotInGraph`. The old
  `CLDK(language="python").analysis(...)` is deprecated: use `CLDK.python(WORKSPACE, ...)`.
- `page.has_more` and `slice.truncated` appear in SDK docstrings but do not exist (`AttributeError`): use
  `.next_cursor`, `.complete` and `.total`.
- `get_method`, `get_callers`, `get_callees` and `get_class_call_graph` do not reach nested functions (every
  OWASP handler is nested in `init`) and answer `None`, `{"caller_details": []}` or `[]`, which looks like
  "no callers". Use `callers_of`, `callees_of`, `resolve_callable`.
- Bare common names (`"init"`, `"__init__"`, `"get"`) raise `AmbiguousName` (OWASP has 1,230 `init`s): use the
  signature from `locate`, or `in_module=ALERT["path"]`.
- Passing a local variable to `resolve_value`, the slices or `paths_between`, or a library function to
  `flows_to_*`, `reaches` or `callers_of`, raises `SelectorNotInGraph`. Use `value_sources`/`get_ddg`.
- `locate` never raises: check `.callable` and `.diagnostics`. `get_python_module` with an absolute path
  returns `None`; `get_source` with a suffix raises `KeyError`.
- `points-to` edges over-approximate and container elements merge into `name[*]`, so confirm by reading
  the lines. Any call can raise, so most statements are control dependent on the call before them: use
  `guards`. `paths_between` returns only shortest paths (which may skip lines); value hops report the
  callable's first line.
- Printing a `PyCallable`, `PyModule`, `get_symbol_table()` or a whole slice floods the output (cut in the
  middle). The analysis covers the whole project: on OWASP, `callers_of` a helper lists about 80 test cases
  and slices reach other files, so print signatures and counts and never fetch another test case's source.
