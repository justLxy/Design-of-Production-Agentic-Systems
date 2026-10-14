"""Main agent loop: one tool-use loop per alert.

Before every model call it checks max_steps, then the budget. The tools and
nudge steps update the no-progress counter. Any of these three can stop the run.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

import openai

from vulnagent.budget import Budget
from vulnagent.dispatcher import Dispatcher
from vulnagent.llm import ModelClient, ModelReply, ToolCall
from vulnagent.prompts import NUDGE, SYSTEM_PROMPT, alert_prompt
from vulnagent.trace import TerminalStatus, Trace
from vulnagent.workspace import Workspace

NO_PROGRESS_LIMIT = 3
ROLE = "classifier"


class RunStopped(Exception):
    """The budget or a failsafe ended the run early."""

    def __init__(self, status: TerminalStatus, reason: str):
        super().__init__(reason)
        self.status = status


@dataclass
class AlertState:
    """Lives while one alert is investigated."""

    alert: dict
    items: list[dict]  # the conversation sent to the model; append-only
    seen_calls: set[str] = field(default_factory=set)  # tool requests already run
    stalled: int = 0  # consecutive turns without new information
    counted_tokens: int = 0  # provider's count for items[:counted_items] (last input + output)
    counted_items: int = 0

class Agent:
    def __init__(self, cfg: dict, ws: Workspace, trace: Trace, client: ModelClient):
        self.ws = ws
        self.trace = trace
        self.client = client
        self.max_steps = cfg["budget"]["max_steps"]
        self.budget = Budget(cfg["budget"]["max_tokens"], cfg["budget"]["output_allowance"], trace)
        self.dispatcher = Dispatcher(ws, trace)
        self.tools = Dispatcher.specs()
        self.alerts: list[dict] = []
        self.rows: dict[str, dict] = {}  # alert_id -> settled report row
        self.steps = 0  # model calls + tool executions, for max_steps

    # Run level

    def run(self, alerts: list[dict]) -> TerminalStatus:
        """Investigate every alert in order; return the run's terminal status."""
        self.alerts = alerts
        try:
            for alert in alerts:
                self._investigate(alert)
        except RunStopped as stop:
            if stop.status is TerminalStatus.BUDGET_EXHAUSTED:
                self.settle_remaining("budget_exhausted", "", node="budget")
            else:
                self.settle_remaining("error", f"Not classified: the run stopped ({stop}).",
                                      node=stop.status.value)
            return stop.status
        return TerminalStatus.COMPLETED

    def settle_remaining(self, status: str, rationale: str, node: str) -> None:
        """Give every alert that has no row yet its final row (cutoff, failsafe or crash)."""
        for alert in self.alerts:
            if alert["alert_id"] not in self.rows:
                self._settle(alert, node, status, None, rationale, [])

    # Alert level

    def _investigate(self, alert: dict) -> None:
        aid = alert["alert_id"]
        self.trace.routing(aid, "triage", by="runtime")
        s = AlertState(alert, items=[
            {"role": "developer", "content": SYSTEM_PROMPT},
            {"role": "user", "content": alert_prompt(alert)},
        ])
        with self.ws.investigating(alert["path"]):
            while aid not in self.rows:
                reply = self._triage(s)
                if reply is not None:
                    self._route(s, reply)

    def _triage(self, s: AlertState) -> ModelReply | None:
        """Check max_steps and the budget, then make one model call."""
        aid = s.alert["alert_id"]
        if self.steps >= self.max_steps:
            self.trace.routing(aid, "max_steps", by="runtime", steps=self.steps)
            raise RunStopped(TerminalStatus.MAX_STEPS, f"max_steps={self.max_steps} reached")
        check = self.budget.check(s.items, self.tools, s.counted_tokens, s.counted_items)
        if not check.ok:
            self.trace.routing(aid, "budget_exhausted", by="runtime",
                               remaining=check.remaining, required=check.required)
            raise RunStopped(TerminalStatus.BUDGET_EXHAUSTED, "token budget exhausted")

        self.steps += 1
        try:
            reply = self.client.complete(s.items, self.tools)
        except openai.APIError as e:
            self.trace.routing(aid, "error", by="runtime", reason=f"model call failed: {type(e).__name__}")
            self._settle(s.alert, "triage", "error", None, f"The model call failed: {e}", [])
            return None
        self.trace.model_call(aid, ROLE, self.client.model, reply.usage,
                              finish_reason=reply.finish_reason)
        s.items += reply.output_items
        s.counted_tokens = reply.usage["input"] + reply.usage["output"]
        s.counted_items = len(s.items)
        return reply

    def _route(self, s: AlertState, reply: ModelReply) -> None:
        """Decide where to go after a model reply."""
        aid = s.alert["alert_id"]
        if reply.tool_calls:
            submits = any(c.name == "submit" for c in reply.tool_calls)
            self.trace.routing(aid, "submit" if submits else "tools", by="model")
            self._run_tools(s, reply.tool_calls)
        elif reply.finish_reason != "stop":
            self.trace.routing(aid, "error", by="runtime", reason=f"reply incomplete: {reply.finish_reason}")
            self._settle(s.alert, "triage", "error", None,
                         f"The model reply was cut off ({reply.finish_reason}) before it called a tool.", [])
        else:
            self._track_progress(s, progressed=False)
            self.trace.routing(aid, "nudge", by="runtime")
            s.items.append({"role": "user", "content": NUDGE})
            self.trace.routing(aid, "triage", by="runtime")

    def _run_tools(self, s: AlertState, calls: list[ToolCall]) -> None:
        """Run the tool calls from one reply in order. submit is handled here too."""
        aid = s.alert["alert_id"]
        progressed = False
        for i, call in enumerate(calls):
            self.steps += 1
            obs = self.dispatcher.dispatch(aid, call.id, call.name, call.arguments)
            s.items.append(obs.as_item())
            if call.name == "submit" and obs.ok:
                # Calls after an accepted submit are not run, but each one is still recorded.
                for rest in calls[i + 1:]:
                    self.dispatcher.decline(aid, rest.id, rest.name, rest.arguments,
                                            "not run: this alert was already submitted")
                args = json.loads(call.arguments)
                self._settle(s.alert, "submit", "classified", args["label"],
                             args["rationale"], args["evidence"])
                return
            key = _call_key(call)
            progressed |= obs.ok and key not in s.seen_calls
            s.seen_calls.add(key)
        self._track_progress(s, progressed)
        self.trace.routing(aid, "triage", by="runtime")

    def _track_progress(self, s: AlertState, progressed: bool) -> None:
        """Stop the run after too many turns in a row without new information."""
        s.stalled = 0 if progressed else s.stalled + 1
        if s.stalled >= NO_PROGRESS_LIMIT:
            self.trace.routing(s.alert["alert_id"], "no_progress", by="runtime", stalled_turns=s.stalled)
            raise RunStopped(TerminalStatus.NO_PROGRESS, f"{s.stalled} turns without new information")

    def _settle(self, alert: dict, node: str, status: str, label: int | None,
                rationale: str, evidence: list[dict]) -> None:
        """Write the alert's one settling state_change and its report row."""
        aid = alert["alert_id"]
        if aid in self.rows:
            raise RuntimeError(f"{aid} is already settled")
        self.trace.settle(aid, node, status, label)
        self.rows[aid] = {
            "alert_id": aid,
            "test_id": alert["test_id"],
            "path": alert["path"],
            "line": alert["line"],
            "severity": alert["severity"],
            "confidence": alert["confidence"],
            "label": label,
            "status": status,
            "rationale": rationale,
            "evidence": [{"path": Path(e["path"]).as_posix(),
                          "start_line": e["start_line"], "end_line": e["end_line"]}
                         for e in evidence],
        }


def _call_key(call: ToolCall) -> str:
    """A tool request's identity, ignoring argument order and whitespace."""
    try:
        args = json.dumps(json.loads(call.arguments), sort_keys=True)
    except json.JSONDecodeError:
        args = call.arguments
    return f"{call.name}:{args}"