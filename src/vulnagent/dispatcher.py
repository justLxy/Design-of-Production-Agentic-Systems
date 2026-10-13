"""The dispatcher: the only path from a model's tool request to a tool.

It validates every request, runs it, records the tool_request/tool_result pair
in the trace, and builds the observation. Only the dispatcher creates
observations; the model never writes one.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass

import jsonschema

from vulnagent import tools
from vulnagent.trace import Trace
from vulnagent.workspace import Workspace


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict  # JSON Schema: sent to the model and used to validate its arguments
    run: Callable[..., str]


@dataclass(frozen=True)
class Observation:
    tool_call_id: str
    tool: str
    ok: bool
    text: str

    def as_message(self) -> dict:
        """The tool message appended to the conversation."""
        return {"role": "tool", "tool_call_id": self.tool_call_id, "content": self.text}


TOOLS: dict[str, Tool] = {tool.name: tool for tool in [
    Tool(
        name="read_file",
        description=(f"Read lines of a repository file, numbered. "
                     f"At most {tools.MAX_READ_LINES} lines per call."),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repository-relative path."},
                "start_line": {"type": "integer", "minimum": 1},
                "end_line": {"type": "integer", "minimum": 1},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        run=tools.read_file,
    ),
    Tool(
        name="search",
        description=(f"Regex search over repository text files. "
                     f"Returns up to {tools.MAX_SEARCH_MATCHES} 'path:line: text' matches."),
        parameters={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "minLength": 1, "description": "Python regex."},
                "path": {"type": "string", "description": "File or directory to search; default '.'."},
            },
            "required": ["pattern"],
            "additionalProperties": False,
        },
        run=tools.search,
    ),
    Tool(
        name="list_dir",
        description="List a repository directory; subdirectories end with '/'.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory; default '.'."},
            },
            "additionalProperties": False,
        },
        run=tools.list_dir,
    ),
]}


class Dispatcher:
    def __init__(self, ws: Workspace, trace: Trace):
        self.ws = ws
        self.trace = trace

    @staticmethod
    def specs() -> list[dict]:
        """Tool definitions in the OpenAI function-calling format."""
        return [
            {"type": "function",
             "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}
            for t in TOOLS.values()
        ]

    def dispatch(self, alert_id: str, call_id: str, name: str, raw_args: str) -> Observation:
        """Validate and run one tool request. Refusals come back as observations, never raised."""
        name = name or "(missing)"
        args, problem = self._parse(raw_args)
        self.trace.tool_request(alert_id, name, args)
        if problem is None:
            problem = self._check(name, args)
        if problem is not None:
            return self._refuse(alert_id, call_id, name, problem)

        try:
            text = TOOLS[name].run(self.ws, **args)
        except (*tools.REFUSALS, OSError, ValueError, TypeError) as e:
            return self._refuse(alert_id, call_id, name, str(e))
        except BaseException as e:
            # Invariant 6 the request still gets its result before the crash propagates
            self.trace.tool_result(alert_id, name, ok=False, error=f"{type(e).__name__}: {e}")
            raise

        self.trace.tool_result(alert_id, name, ok=True, chars=len(text))
        return Observation(call_id, name, True, text)

    @staticmethod
    def _parse(raw_args: str) -> tuple[dict, str | None]:
        try:
            args = json.loads(raw_args or "{}")
        except json.JSONDecodeError as e:
            return {"_raw": raw_args}, f"arguments are not valid JSON: {e}"
        if not isinstance(args, dict):
            return {"_raw": raw_args}, "arguments must be a JSON object"
        return args, None

    @staticmethod
    def _check(name: str, args: dict) -> str | None:
        tool = TOOLS.get(name)
        if tool is None:
            return f"unknown tool {name!r}; available tools: {', '.join(TOOLS)}"
        try:
            jsonschema.validate(args, tool.parameters)
        except jsonschema.ValidationError as e:
            return f"bad arguments for {name}: {e.message}"
        return None

    def _refuse(self, alert_id: str, call_id: str, name: str, reason: str) -> Observation:
        self.trace.tool_result(alert_id, name, ok=False, error=reason)
        return Observation(call_id, name, False, f"REFUSED: {reason}")