"""The CodeAct agent's tools: run_python, which runs model-written code in the
execution kernel (vulnagent.kernel), and submit.

The dispatcher sees one run_python call as one action and cannot check what the
script does inside. Per-alert rules are only in the prompt; the sandbox policy is
what actually stops a script, and a script stopped by it raises PermissionError,
which the harness records as refused_by kernel.
"""

import contextlib
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from functools import partial
from pathlib import Path
from types import SimpleNamespace

import jsonschema

from vulnagent import tools as text_tools
from vulnagent.config import REPO_ROOT
from vulnagent.dispatcher import TOOLS as LOCAL_TOOLS, Dispatcher, Observation
from vulnagent.patching import check_patch
from vulnagent.prompts import codeact_system_prompt
from vulnagent.server import stage
from vulnagent.trace import Trace
from vulnagent.workspace import resolve

DEFAULT_PROMPT = "prompts/codeact_agent.md"
DEFAULT_TIMEOUT_S = 600  # the first CLDK build on OWASP takes about two to three minutes
MAX_CODE_CHARS = 20_000
STARTUP_TIMEOUT_S = 60
SECRET_ENV = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL", re.IGNORECASE)

RUN_PYTHON = {
    "type": "function",
    "name": "run_python",
    "description": (
        "Run Python 3.12 code in a persistent kernel whose working directory is the workspace copy "
        "of the target. Names you define stay defined in later calls. WORKSPACE (path of the copy) "
        "and ALERT (the open alert) are predefined. Returns stdout and stderr, the value of a final "
        "expression, and the traceback if the code raises."),
    "parameters": {
        "type": "object",
        "properties": {"code": {"type": "string", "minLength": 1, "maxLength": MAX_CODE_CHARS}},
        "required": ["code"],
        "additionalProperties": False,
    },
}
SUBMIT = {"type": "function", "name": "submit", "description": LOCAL_TOOLS["submit"].description,
          "parameters": LOCAL_TOOLS["submit"].parameters}
SPECS = {spec["name"]: spec for spec in (RUN_PYTHON, SUBMIT)}


class KernelProcess:
    """The kernel subprocess, restarted after a timeout or a crash."""

    def __init__(self, python: str, workspace: Path, timeout_s: float):
        self.python = python
        self.workspace = workspace
        self.timeout_s = timeout_s
        self.bound: dict[str, object] = {}  # names to bind again after a restart
        self.proc: subprocess.Popen | None = None
        self.pid: int | None = None  # the detached kernel (proc is only its short-lived parent)
        self.replies: queue.Queue[str | None] = queue.Queue()
        self.start()

    def start(self) -> None:
        # The model's code runs here, so it gets no API key (outside the sandbox the real
        # one is in our environment; inside it is a placeholder).
        env = {k: v for k, v in os.environ.items() if not SECRET_ENV.search(k)}
        self.proc = subprocess.Popen(
            [self.python, "-m", "vulnagent.kernel", "--workspace", str(self.workspace), "--detach"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8",
            bufsize=1, env=env, cwd=self.workspace, start_new_session=True)
        self.replies = queue.Queue()
        threading.Thread(target=self._read, args=(self.proc, self.replies), daemon=True).start()
        try:
            hello = self.replies.get(timeout=STARTUP_TIMEOUT_S)
        except queue.Empty:
            hello = None
        self.proc.wait()  # the parent exits at once after forking
        if hello is None:
            raise RuntimeError(f"the execution kernel did not start ({self.python})")
        self.pid = json.loads(hello)["pid"]
        for name, value in self.bound.items():
            self._send({"op": "set", "name": name, "value": value})

    @staticmethod
    def _read(proc: subprocess.Popen, replies: queue.Queue) -> None:
        for line in proc.stdout:
            replies.put(line)
        replies.put(None)  # EOF: the kernel exited

    def bind(self, name: str, value: object) -> None:
        self.bound[name] = value
        self._send({"op": "set", "name": name, "value": value})

    def run(self, code: str) -> dict:
        return self._send({"op": "exec", "code": code})

    def _send(self, request: dict) -> dict:
        try:
            self.proc.stdin.write(json.dumps(request) + "\n")
            self.proc.stdin.flush()
            line = self.replies.get(timeout=self.timeout_s)
        except queue.Empty:
            self.restart()
            return _harness_error("Timeout", f"the code ran longer than {self.timeout_s:.0f} s and was stopped. "
                                  "The kernel was restarted, so every name from earlier calls is gone "
                                  "(load CLDK again; its cache makes that faster).")
        except (BrokenPipeError, OSError):
            line = None
        if line is None:
            self.restart()
            return _harness_error("KernelDied", "the kernel process exited. It was restarted, "
                                  "so every name from earlier calls is gone.")
        return json.loads(line)

    def restart(self) -> None:
        self.stop()
        self.start()

    def stop(self) -> None:
        """Close stdin (the kernel exits at EOF); kill it if it is still busy."""
        if self.proc is None:
            return
        with contextlib.suppress(OSError):
            self.proc.stdin.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                if self.replies.get(timeout=max(0.0, deadline - time.monotonic())) is None:
                    return  # EOF: it exited
            except queue.Empty:
                break
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)  # its group: the kernel and its children
        except (PermissionError, ProcessLookupError):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(self.pid, signal.SIGKILL)  # the sandbox may not allow signalling a group


def _harness_error(kind: str, message: str) -> dict:
    return {"ok": False, "output": "", "value": None,
            "error": {"type": kind, "message": message, "permission": False, "traceback": ""}}


def format_result(result: dict) -> str:
    """What the model sees after run_python."""
    parts = []
    if result.get("output"):
        parts.append(result["output"].rstrip("\n"))
    if result.get("value") is not None:
        parts.append(f"=> {result['value']}")
    error = result.get("error")
    if error:
        if error.get("traceback"):
            parts.append(error["traceback"].rstrip("\n"))
        else:
            parts.append(f"{error['type']}: {error['message']}")
        if error.get("permission"):
            parts.append("REFUSED by the sandbox (operating-system kernel): this access is outside the policy "
                         "and will not succeed if you retry it.")
    return "\n".join(parts) if parts else "(no output)"


class CodeActToolbox:
    """run_python and submit, behind the toolbox interface the agent loop uses."""

    via = "codeact"
    can_remediate = True
    remediation_hint = (
        "Make the change with run_python, by plain string replacement on the file at "
        "os.path.join(WORKSPACE, ALERT['path']), print the diff, then run bandit on that file as your "
        "guide shows to check that the rule is no longer reported at the flagged place.")

    def __init__(self, cfg: dict, input_dir: Path, trace: Trace):
        self.trace = trace
        settings = cfg.get("codeact", {})
        prompt_path = REPO_ROOT / settings.get("prompt", DEFAULT_PROMPT)
        self.system_prompt = codeact_system_prompt(prompt_path.read_text(encoding="utf-8"))
        python = settings.get("kernel_python") or sys.executable
        if not Path(python).exists():  # configs name the interpreter inside the sandbox image
            python = sys.executable
        self.workdir = Path(tempfile.mkdtemp(prefix="vulnagent-codeact-"))
        self.pristine, self.workspace = stage(Path(input_dir), Path("/target"), [], self.workdir)
        self.ws = SimpleNamespace(resolve=partial(resolve, self.workspace))  # for submit's evidence check
        self.kernel = KernelProcess(python, self.workspace, float(settings.get("timeout_s", DEFAULT_TIMEOUT_S)))
        self.alert: dict | None = None

    def specs(self) -> list[dict]:
        return list(SPECS.values())

    def dispatch(self, alert_id: str, call_id: str, name: str, raw_args: str) -> Observation:
        name = name or "(missing)"
        args, problem = _parse(raw_args)
        self.trace.tool_request(alert_id, name, args, via=self.via)
        if problem is None:
            if name not in SPECS:
                problem = f"unknown tool {name!r}; available tools: {', '.join(SPECS)}"
            else:
                try:
                    jsonschema.validate(args, SPECS[name]["parameters"])
                except jsonschema.ValidationError as e:
                    problem = f"bad arguments for {name}: {e.message}"
        if problem is not None:
            return self._refuse(alert_id, call_id, name, problem)

        if name == "submit":
            try:
                text = text_tools.submit(self.ws, **args)
            except (*text_tools.REFUSALS, OSError, ValueError) as e:
                return self._refuse(alert_id, call_id, name, str(e))
            self.trace.tool_result(alert_id, name, ok=True, via=self.via, chars=len(text))
            return Observation(call_id, name, True, text)

        result = self.kernel.run(args["code"])
        text = format_result(result)
        error = result.get("error")
        if error is None:
            self.trace.tool_result(alert_id, name, ok=True, via=self.via, chars=len(text))
            return Observation(call_id, name, True, text)
        message = f"{error['type']}: {error['message']}"
        if error.get("permission"):
            self.trace.tool_result(alert_id, name, ok=False, error=f"refused (kernel): {message}",
                                   via=self.via, refused_by="kernel", exception=error["type"])
        else:
            self.trace.tool_result(alert_id, name, ok=False, error=message, via=self.via,
                                   exception=error["type"])
        return Observation(call_id, name, False, text)

    def decline(self, alert_id: str, call_id: str, name: str, raw_args: str, reason: str) -> Observation:
        args, _ = _parse(raw_args)
        self.trace.tool_request(alert_id, name or "(missing)", args, via=self.via)
        return self._refuse(alert_id, call_id, name or "(missing)", reason)

    def _refuse(self, alert_id: str, call_id: str, name: str, reason: str) -> Observation:
        self.trace.tool_result(alert_id, name, ok=False, error=f"refused: {reason}", via=self.via,
                               refused_by="dispatcher")
        return Observation(call_id, name, False, f"REFUSED: {reason}")

    @contextlib.contextmanager
    def open_alert(self, alert: dict) -> Iterator[None]:
        """Start the alert from the pinned file and bind ALERT in the kernel."""
        rel = alert["path"]
        if (self.pristine / rel).is_file():
            shutil.copyfile(self.pristine / rel, self.workspace / rel)
        fields = ("alert_id", "test_id", "path", "line", "severity", "confidence", "issue_text", "code")
        self.kernel.bind("ALERT", {k: alert.get(k) for k in fields})
        self.alert = alert
        self.trace.state_change(alert["alert_id"], "open_alert", path=rel)
        try:
            yield
        finally:
            self.alert = None

    def review(self, alert: dict) -> dict:
        """The three patch checks on the alert's file, run by the harness, not the model."""
        rel = alert["path"]
        before = (self.pristine / rel).read_text(encoding="utf-8")
        try:
            after = (self.workspace / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            after = ""  # deleted or garbled by the script: the diff will not apply
        result = check_patch(rel, before, after, self.workspace, alert["line"], alert["test_id"])
        return {"status": result["status"], "diff": result["diff"], "checks": result["checks"]}

    def close(self) -> None:
        self.kernel.stop()
        shutil.rmtree(self.workdir, ignore_errors=True)


_parse = Dispatcher._parse
