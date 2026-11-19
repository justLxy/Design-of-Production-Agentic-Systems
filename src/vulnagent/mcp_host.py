"""The MCP host: starts the server from mcp.json, discovers its tools, and routes
every model tool call through the dispatcher checks and then the MCP client.

The host process never opens a target file: reads, edits, evidence checks and
patch reviews all happen in the server.
"""

import contextlib
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio.from_thread
import jsonschema
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from vulnagent.dispatcher import Observation
from vulnagent.prompts import MCP_REMEDIATION, MCP_SYSTEM_PROMPT
from vulnagent.trace import Trace

HOST_ONLY = {"set_alert", "review_patch"}
CALL_TIMEOUT_S = 900  # the first analysis call waits for CLDK to build


def load_server_config(path: Path) -> tuple[str, str, list[str], dict[str, str]]:
    """(name, command, args, env) of the first server in an mcp.json."""
    servers = json.loads(path.read_text())["mcpServers"]
    name, entry = next(iter(servers.items()))
    command = entry["command"]
    if not Path(command).exists() and shutil.which(command) is None:
        # mcp.json names the interpreter inside the sandbox image; outside it, use ours.
        command = sys.executable
    env = dict(entry.get("env", {}))
    if "SYSTEM_PYTHON" in env and not Path(env["SYSTEM_PYTHON"]).exists():
        env["SYSTEM_PYTHON"] = sys.executable
    return name, command, list(entry.get("args", [])), env


class McpConnection:
    """A synchronous wrapper around an MCP stdio client session."""

    def __init__(self, command: str, args: list[str], env: dict[str, str]):
        self._stack = contextlib.ExitStack()
        try:
            self._portal = self._stack.enter_context(anyio.from_thread.start_blocking_portal())
            params = StdioServerParameters(command=command, args=args, env=env)
            read, write = self._stack.enter_context(self._portal.wrap_async_context_manager(stdio_client(params)))
            self.session = self._stack.enter_context(self._portal.wrap_async_context_manager(
                ClientSession(read, write, read_timeout_seconds=CALL_TIMEOUT_S)))
            self._portal.call(self.session.initialize)
        except BaseException:
            self._stack.close()
            raise

    def list_tools(self) -> list[Any]:
        return self._portal.call(self.session.list_tools).tools

    def call_tool(self, name: str, args: dict) -> tuple[bool, str]:
        """(is_error, text) of one tools/call."""
        result = self._portal.call(self.session.call_tool, name, args)
        text = "\n".join(block.text for block in result.content if getattr(block, "type", "") == "text")
        return bool(result.is_error), text

    def close(self) -> None:
        self._stack.close()


def refused_by(text: str) -> str | None:
    """Which layer refused a failed call, from the server's error text."""
    if text.startswith("refused (kernel)"):
        return "kernel"
    if text.startswith("refused"):
        return "server"
    return None


class McpToolbox:
    """The MCP agent's tools: whatever the server lists, minus the host-only ones."""

    via = "mcp"
    system_prompt = MCP_SYSTEM_PROMPT
    can_remediate = True
    remediation_hint = MCP_REMEDIATION
    write_tools = frozenset({"edit"})  # the runtime declines these while classifying

    def __init__(self, mcp_config: Path, input_dir: Path, trace: Trace, analysis_scope: list[str] | None = None):
        self.trace = trace
        name, command, args, env = load_server_config(mcp_config)
        self.workdir = Path(tempfile.mkdtemp(prefix="vulnagent-server-"))
        env = {**env, "VULNAGENT_SOURCE": str(input_dir.resolve()), "VULNAGENT_WORKDIR": str(self.workdir),
               "VULNAGENT_ANALYSIS_SCOPE": ":".join(analysis_scope or [])}
        env.setdefault("PATH", os.environ.get("PATH", "/usr/bin:/bin"))
        self.conn = McpConnection(command, args, env)
        listed = self.conn.list_tools()
        self.host_only = HOST_ONLY | {t.name for t in listed if (t.meta or {}).get("host_only")}
        self.tools = {t.name: t for t in listed if t.name not in self.host_only}
        trace.discovery(name, sorted(self.tools))

    def specs(self) -> list[dict]:
        """The discovered tools in the Responses API function format."""
        return [{"type": "function", "name": t.name, "description": t.description or "", "parameters": t.input_schema}
                for t in self.tools.values()]

    def dispatch(self, alert_id: str, call_id: str, name: str, raw_args: str) -> Observation:
        """Dispatcher checks first, then the MCP call. Refusals come back as observations."""
        name = name or "(missing)"
        args, problem = _parse(raw_args)
        self.trace.tool_request(alert_id, name, args, via=self.via)
        if problem is None:
            if name in self.host_only:
                problem = f"{name} is a host-only tool and is never offered to the model"
            elif name not in self.tools:
                problem = f"unknown tool {name!r}; available tools: {', '.join(sorted(self.tools))}"
            else:
                errors = sorted(jsonschema.Draft202012Validator(self.tools[name].input_schema).iter_errors(args),
                                key=lambda e: list(e.path))
                if errors:
                    where = "/".join(str(p) for p in errors[0].path) or "arguments"
                    problem = f"bad arguments for {name}: {where}: {errors[0].message}"
        if problem is not None:
            return self._refuse(alert_id, call_id, name, problem)

        try:
            is_error, text = self.conn.call_tool(name, args)
        except BaseException as e:
            self.trace.tool_result(alert_id, name, ok=False, error=f"{type(e).__name__}: {e}", via=self.via)
            raise
        if is_error:
            layer = refused_by(text)
            extra = {"refused_by": layer} if layer else {}
            self.trace.tool_result(alert_id, name, ok=False, error=text or "error", via=self.via, **extra)
            return Observation(call_id, name, False, text if layer else f"ERROR: {text}")
        self.trace.tool_result(alert_id, name, ok=True, via=self.via, chars=len(text))
        return Observation(call_id, name, True, text)

    def decline(self, alert_id: str, call_id: str, name: str, raw_args: str, reason: str) -> Observation:
        """Record a request the runtime will not run, as a request/result pair."""
        args, _ = _parse(raw_args)
        self.trace.tool_request(alert_id, name or "(missing)", args, via=self.via)
        return self._refuse(alert_id, call_id, name or "(missing)", reason)

    def _refuse(self, alert_id: str, call_id: str, name: str, reason: str) -> Observation:
        self.trace.tool_result(alert_id, name, ok=False, error=f"refused: {reason}", via=self.via,
                               refused_by="dispatcher")
        return Observation(call_id, name, False, f"REFUSED: {reason}")

    @contextlib.contextmanager
    def open_alert(self, alert: dict) -> Iterator[None]:
        """Point the server's per-alert rules at this alert (host-only set_alert)."""
        is_error, text = self.conn.call_tool("set_alert", {"alert_id": alert["alert_id"]})
        if is_error:
            raise RuntimeError(f"set_alert failed for {alert['alert_id']}: {text}")
        self.trace.state_change(alert["alert_id"], "set_alert", path=json.loads(text)["path"])
        yield

    def review(self, alert: dict) -> dict:
        """The open alert's remediation fields from the server (host-only review_patch)."""
        is_error, text = self.conn.call_tool("review_patch", {})
        if is_error:
            raise RuntimeError(f"review_patch failed for {alert['alert_id']}: {text}")
        review = json.loads(text)
        return {"status": review["status"], "diff": review["diff"], "checks": review["checks"]}

    def close(self) -> None:
        self.conn.close()
        shutil.rmtree(self.workdir, ignore_errors=True)


def _parse(raw_args: str) -> tuple[dict, str | None]:
    try:
        args = json.loads(raw_args or "{}")
    except json.JSONDecodeError as e:
        return {"_raw": raw_args}, f"arguments are not valid JSON: {e}"
    if not isinstance(args, dict):
        return {"_raw": raw_args}, "arguments must be a JSON object"
    return args, None
