"""Tests for the workspace boundary and withholding (B2)."""

import os
from pathlib import Path

import pytest

from vulnagent.workspace import PathEscapeError, Workspace

REPO_ROOT = Path(__file__).resolve().parents[1]
OWASP = REPO_ROOT / "targets" / "owasp-benchmark-python"
CASE = "testcode/BenchmarkTest00011.py"

pytestmark = pytest.mark.skipif(not OWASP.is_dir(), reason="OWASP target not cloned")


def test_git_and_answer_key_are_never_copied():
    with Workspace(OWASP) as ws:
        assert not (ws.root / ".git").exists()
        assert not (ws.root / "expectedresults-0.1.csv").exists()
        assert (ws.root / CASE).is_file()


def test_input_is_left_untouched():
    with Workspace(OWASP):
        pass
    assert (OWASP / ".git").is_dir()
    assert (OWASP / "expectedresults-0.1.csv").is_file()


def test_copy_is_removed_on_exit():
    with Workspace(OWASP) as ws:
        root = ws.root
    assert not root.exists()


def test_resolve_accepts_a_path_inside_the_copy():
    with Workspace(OWASP) as ws:
        assert ws.resolve(CASE) == ws.root / CASE


@pytest.mark.parametrize("bad", ["../README.md", "testcode/../../x", "/etc/passwd"])
def test_resolve_refuses_dotdot_and_absolute_paths(bad):
    with Workspace(OWASP) as ws:
        with pytest.raises(PathEscapeError):
            ws.resolve(bad)


def test_resolve_refuses_a_symlink_out_of_the_copy():
    with Workspace(OWASP) as ws:
        os.symlink("/etc", ws.root / "escape")
        with pytest.raises(PathEscapeError):
            ws.resolve("escape/passwd")


def test_other_cases_are_withheld_during_an_alert():
    with Workspace(OWASP) as ws:
        with ws.investigating(CASE):
            visible = sorted(p.name for p in ws.root.rglob("BenchmarkTest*"))
            assert visible == ["BenchmarkTest00011.html", "BenchmarkTest00011.py"]
            assert not ws.resolve("testcode/BenchmarkTest00012.py").exists()
            assert len(ws.withheld()) == 2458


def test_withheld_cases_are_restored_after_the_alert():
    with Workspace(OWASP) as ws:
        before = sorted(ws.root.rglob("BenchmarkTest*"))
        with ws.investigating(CASE):
            pass
        assert sorted(ws.root.rglob("BenchmarkTest*")) == before
        assert ws.withheld() == []


def test_withheld_cases_are_restored_even_if_the_alert_crashes():
    with Workspace(OWASP) as ws:
        before = sorted(ws.root.rglob("BenchmarkTest*"))
        with pytest.raises(RuntimeError):
            with ws.investigating(CASE):
                raise RuntimeError("simulated crash")
        assert sorted(ws.root.rglob("BenchmarkTest*")) == before

def test_other_scanners_results_are_never_copied():
    with Workspace(OWASP) as ws:
        assert not (ws.root / "results").exists()
        assert (ws.root / "data").is_dir()