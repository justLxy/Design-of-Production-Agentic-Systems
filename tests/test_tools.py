"""Tests for the read-only tools (B2)."""

from pathlib import Path

import pytest

from vulnagent.tools import (MAX_READ_LINES, MAX_SEARCH_MATCHES, ToolError,
                             list_dir, read_file, search, submit)
from vulnagent.workspace import PathEscapeError, Workspace

REPO_ROOT = Path(__file__).resolve().parents[1]
OWASP = REPO_ROOT / "targets" / "owasp-benchmark-python"
CASE = "testcode/BenchmarkTest00011.py"

pytestmark = pytest.mark.skipif(not OWASP.is_dir(), reason="OWASP target not cloned")


@pytest.fixture
def ws():
    """A workspace investigating CASE, as the agent sees it during that alert."""
    with Workspace(OWASP) as workspace:
        with workspace.investigating(CASE):
            yield workspace


def test_read_file_returns_numbered_lines(ws):
    text = read_file(ws, CASE, 45, 48)
    assert text.splitlines()[0] == f"{CASE}, lines 45-48 of 57"
    assert "   47| " in text and "SELECT username" in text


def test_read_file_caps_long_ranges(ws):
    text = read_file(ws, "helpers/utils.py", 1, 10_000)
    numbered = [line for line in text.splitlines()[1:]]
    assert len(numbered) <= MAX_READ_LINES


@pytest.mark.parametrize("start, end", [(0, 5), (10, 5), (999, 1000)])
def test_read_file_refuses_bad_ranges(ws, start, end):
    with pytest.raises(ToolError):
        read_file(ws, CASE, start, end)


def test_read_file_refuses_a_withheld_sibling(ws):
    with pytest.raises(ToolError, match="no such file"):
        read_file(ws, "testcode/BenchmarkTest00012.py")


def test_read_file_refuses_escapes(ws):
    with pytest.raises(PathEscapeError):
        read_file(ws, "../withheld/testcode/BenchmarkTest00012.py")


def test_search_finds_code_in_the_case(ws):
    assert f"{CASE}:47:" in search(ws, r"SELECT username", "testcode")


def test_search_cannot_see_sibling_code_or_the_answer_key(ws):
    assert search(ws, r"def BenchmarkTest00012_post").startswith("no matches")
    assert search(ws, r"BenchmarkTest00012\.py").startswith("no matches")
    assert search(ws, r"sqli,(true|false)").startswith("no matches")


def test_search_stops_at_the_match_limit(ws):
    text = search(ws, r"the", "LICENSE")
    assert f"stopped at {MAX_SEARCH_MATCHES} matches" in text
    assert len(text.splitlines()) == MAX_SEARCH_MATCHES + 1


def test_search_refuses_an_invalid_regex(ws):
    with pytest.raises(ToolError, match="invalid regex"):
        search(ws, r"(unclosed")


def test_list_dir_hides_git_and_the_answer_key(ws):
    entries = list_dir(ws).splitlines()
    assert "testcode/" in entries and "helpers/" in entries
    assert ".git/" not in entries
    assert "expectedresults-0.1.csv" not in entries


def test_list_dir_refuses_a_file(ws):
    with pytest.raises(ToolError, match="not a directory"):
        list_dir(ws, CASE)

def test_submit_accepts_evidence_inside_a_file(ws):
    evidence = [{"path": CASE, "start_line": 45, "end_line": 48}]
    assert submit(ws, 0, "Parameterised query.", evidence).startswith("Accepted")


@pytest.mark.parametrize("evidence", [
    {"path": CASE, "start_line": 50, "end_line": 999},                          # past the end of the file
    {"path": "testcode/BenchmarkTest00012.py", "start_line": 1, "end_line": 2},  # a withheld sibling
])
def test_submit_refuses_evidence_that_does_not_exist(ws, evidence):
    with pytest.raises(ToolError):
        submit(ws, 0, "Some rationale.", [evidence])