"""Append-only run trace: one JSON event per line in trace.jsonl"""

import json
import time
from enum import StrEnum
from pathlib import Path

import jsonschema

from vulnagent.config import REPO_ROOT

TRACE_SCHEMA = json.loads((REPO_ROOT / "trace.schema.json").read_text())


class EventKind(StrEnum):
    MODEL_CALL = "model_call"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"
    ROUTING = "routing"
    STATE_CHANGE = "state_change"
    TERMINAL = "terminal"


class TerminalStatus(StrEnum):
    COMPLETED = "completed"                # every alert was settled normally
    BUDGET_EXHAUSTED = "budget_exhausted"  # token budget ran out before all alerts were classified
    MAX_STEPS = "max_steps"                # failsafe: step limit reached
    NO_PROGRESS = "no_progress"            # failsafe: the agent stopped making progress
    CRASHED = "crashed"                    # an unhandled exception ended the run


class TraceClosedError(Exception):
    """An event was emitted after the terminal event."""


class Trace:
    """Writes trace.jsonl and owns the step counter and the usage ledger."""

    def __init__(self, path: Path, run_id: str):
        self.run_id = run_id
        self.closed = False
        self._step = 0
        self._usage_total = {"input": 0, "output": 0}
        self._file = open(path, "w", encoding="utf-8")

    @property
    def used_tokens(self) -> int:
        """The budget charge: input + output summed over every model_call."""
        return self._usage_total["input"] + self._usage_total["output"]

    @property
    def usage_total(self) -> dict:
        return dict(self._usage_total)

    def emit(self, kind: EventKind, alert_id: str | None, **fields) -> dict:
        """Validate one event, append it as a line, and flush."""
        if self.closed:
            raise TraceClosedError(f"cannot emit {kind} after the terminal event")
        event = {
            "step": self._step + 1,
            "ts": time.time(),
            "run_id": self.run_id,
            "alert_id": alert_id,
            "kind": kind,
            **fields,
        }
        # Validate before advancing the counter
        jsonschema.validate(event, TRACE_SCHEMA)
        self._file.write(json.dumps(event) + "\n")
        self._file.flush()
        self._step += 1
        return event

    # One helper per kind

    def model_call(self, alert_id: str | None, role: str, model: str, usage: dict, **extra) -> dict:
        event = self.emit(EventKind.MODEL_CALL, alert_id, role=role, model=model, usage=usage, **extra)
        for key, value in usage.items():
            self._usage_total[key] = self._usage_total.get(key, 0) + value
        return event

    def tool_request(self, alert_id: str | None, tool: str, args: dict) -> dict:
        return self.emit(EventKind.TOOL_REQUEST, alert_id, tool=tool, args=args)

    def tool_result(self, alert_id: str | None, tool: str, ok: bool,
                    error: str | None = None, **extra) -> dict:
        fields = {"tool": tool, "ok": ok, **extra}
        if not ok:
            fields["error"] = error or "unknown error"
        return self.emit(EventKind.TOOL_RESULT, alert_id, **fields)

    def routing(self, alert_id: str | None, decision: str, by: str, **extra) -> dict:
        return self.emit(EventKind.ROUTING, alert_id, decision=decision, by=by, **extra)

    def state_change(self, alert_id: str | None, node: str, **extra) -> dict:
        return self.emit(EventKind.STATE_CHANGE, alert_id, node=node, **extra)

    def settle(self, alert_id: str, node: str, alert_status: str, label: int | None,
               **extra) -> dict:
        """Record an alert's final row; call exactly once per alert."""
        return self.state_change(alert_id, node, alert_status=alert_status, label=label, **extra)

    def terminal(self, status: TerminalStatus, **extra) -> dict:
        """Write the single last event and close the file."""
        event = self.emit(EventKind.TERMINAL, None, status=status,
                          usage_total=self.usage_total, **extra)
        self.closed = True
        self._file.close()
        return event