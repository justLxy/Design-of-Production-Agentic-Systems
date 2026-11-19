"""Tests for the MCP server over real stdio, on a tiny OWASP-like project."""

import asyncio
import json
import sys
from pathlib import Path

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from vulnagent.patching import apply_diff, check_patch, make_diff, touched_region
from vulnagent.policy import AccessPolicy, Refusal

CASE_11 = '''from flask import request

def init(app):
    @app.route("/case11", methods=["POST"])
    def BenchmarkTest00011_post():
        param = request.cookies.get("c", "x")
        sql = "SELECT * FROM users WHERE name = '" + param + "'"
        cur = get_cursor()
        cur.execute(sql)
        return "ok"
'''


@pytest.fixture(scope="module")
def project(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("owasp")
    (root / "testcode").mkdir()
    (root / "testcode/BenchmarkTest00011.py").write_text(CASE_11)
    (root / "testcode/BenchmarkTest00012.py").write_text(CASE_11.replace("00011", "00012"))
    (root / "helpers").mkdir()
    (root / "helpers/db.py").write_text("def get_cursor():\n    return None\n")
    (root / "expectedresults-0.1.csv").write_text("BenchmarkTest00011,sqli,true,89\n")
    (root / ".git").mkdir()
    (root / ".git/HEAD").write_text("ref: refs/heads/main\n")
    return root


def run_session(project: Path, workdir: Path, calls: list[tuple[str, dict]]) -> tuple[list, list]:
    """Start the server over stdio, run the calls in order, return (tools, results)."""
    async def go():
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "vulnagent.server", "--source", str(project), "--workdir", str(workdir)],
                                       env={"SYSTEM_PYTHON": sys.executable, "PATH": "/usr/bin:/bin"})
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=600) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                results = []
                for name, args in calls:
                    res = await session.call_tool(name, args)
                    results.append((res.is_error, res.content[0].text if res.content else ""))
                return tools, results
    return asyncio.run(go())


@pytest.fixture(scope="module")
def session(project, tmp_path_factory):
    calls = [
        ("set_alert", {"alert_id": "testcode-BenchmarkTest00011-py-9-B608"}),
        ("read_file", {"path": "expectedresults-0.1.csv"}),
        ("read_file", {"path": "missing/expectedresults-0.1.csv"}),
        ("read_file", {"path": ".git/HEAD"}),
        ("read_file", {"path": "testcode/BenchmarkTest00012.py"}),
        ("edit", {"path": "../outside.py", "old": "a", "new": "b"}),
        ("edit", {"path": "helpers/db.py", "old": "None", "new": "1"}),
        ("read_file", {"path": 7}),
        ("read_file", {"path": "helpers/db.py", "extra": True}),
        ("no_such_tool", {}),
        ("dataflow", {"path": "testcode/BenchmarkTest00011.py", "line": 7}),
        ("edit", {"path": "testcode/BenchmarkTest00011.py",
                  "old": "sql = \"SELECT * FROM users WHERE name = '\" + param + \"'\"\n        cur = get_cursor()\n        cur.execute(sql)",
                  "new": "sql = \"SELECT * FROM users WHERE name = ?\"\n        cur = get_cursor()\n        cur.execute(sql, (param,))"}),
        ("review_patch", {}),
    ]
    tools, results = run_session(project, tmp_path_factory.mktemp("work"), calls)
    return {t.name: t for t in tools}, dict(zip(range(len(calls)), results))


def test_tools_list_marks_host_only_and_uses_strict_schemas(session):
    tools, _ = session
    assert {"locate", "source", "dataflow", "read_file", "edit", "rescan"} <= set(tools)
    assert {n for n, t in tools.items() if (t.meta or {}).get("host_only")} == {"set_alert", "review_patch"}
    assert all(t.input_schema.get("additionalProperties") is False for t in tools.values())


@pytest.mark.parametrize("index", [1, 2, 3, 4, 5, 6, 7, 8, 9])
def test_forbidden_or_malformed_calls_are_refused(session, index):
    _, results = session
    is_error, text = results[index]
    assert is_error and text.startswith("refused"), text


def test_the_answer_key_is_refused_even_where_it_does_not_exist(session):
    assert "answer key" in session[1][2][1]


def test_dataflow_returns_edges_into_the_query(session):
    is_error, text = session[1][10]
    assert not is_error
    edges = json.loads(text)["edges"]
    assert any(e["var"] == "param" and e["to_line"] == 7 for e in edges)


def test_a_parameterised_fix_is_accepted(session):
    is_error, text = session[1][12]
    review = json.loads(text)
    assert not is_error and review["status"] == "accepted", review
    assert review["checks"] == {"applies": True, "touches_flagged_line": True, "clean_rescan": True}


def test_policy_refuses_writes_outside_the_open_file(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    policy = AccessPolicy(tmp_path)
    with pytest.raises(Refusal):
        policy.resolve_write("a.py")  # no alert open
    policy.open_path = "a.py"
    assert policy.resolve_write("a.py") == (tmp_path / "a.py").resolve()
    with pytest.raises(Refusal):
        policy.resolve_write("b.py")


def test_diff_round_trip_and_flagged_line():
    before = "a\nb\nc\nd\n"
    after = "a\nB\nc\nd\n"
    diff = make_diff("f.py", before, after)
    assert apply_diff(diff, before) == after
    assert apply_diff(diff, "a\nX\nc\nd\n") is None
    assert touched_region(diff, 2) is not None and touched_region(diff, 4) is None


def test_an_unchanged_file_is_rejected_with_no_checks(tmp_path):
    result = check_patch("f.py", "x = 1\n", "x = 1\n", tmp_path, 1, "B608")
    assert result["status"] == "rejected" and result["diff"] == ""
