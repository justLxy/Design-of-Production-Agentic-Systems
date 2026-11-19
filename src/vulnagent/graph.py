"""Main agent loop: per alert, a classification loop and, for label 1, a remediation loop.

Before every model call it checks max_steps, then the budget. The tools and
nudge steps update the no-progress counter. Any of these three can stop the run.
After an alert is settled, the runtime (never the model) routes it to
remediation if its label is 1 and skips remediation otherwise.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

import openai

from vulnagent.budget import Budget
from vulnagent.llm import ModelClient, ModelReply, ToolCall
from vulnagent.prompts import NUDGE, alert_prompt, remediation_prompt
from vulnagent.trace import TerminalStatus, Trace

NO_PROGRESS_LIMIT = 3
REMEDIATION_TURNS = 8  # model turns allowed in one alert's remediation stage


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
    def __init__(self, cfg: dict, toolbox, trace: Trace, client: ModelClient):
        # toolbox: LocalToolbox (HW1, in process), McpToolbox or CodeActToolbox
        self.toolbox = toolbox
        self.trace = trace
        self.client = client
        self.max_steps = cfg["budget"]["max_steps"]
        self.budget = Budget(cfg["budget"]["max_tokens"], cfg["budget"]["output_allowance"], trace)
        self.tools = toolbox.specs()
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
                self._skip_remediation(alert["alert_id"])

    # Alert level

    def _investigate(self, alert: dict) -> None:
        aid = alert["alert_id"]
        self.trace.routing(aid, "triage", by="runtime")
        s = AlertState(alert, items=[
            {"role": "developer", "content": self.toolbox.system_prompt},
            {"role": "user", "content": alert_prompt(alert)},
        ])
        with self.toolbox.open_alert(alert):
            while aid not in self.rows:
                reply = self._triage(s)
                if reply is not None:
                    self._route(s, reply)
            self._remediation_stage(s)

    def _triage(self, s: AlertState) -> ModelReply | None:
        """Classification turn: one model call; an API failure settles the alert as error."""
        try:
            return self._call_model(s, "classifier")
        except openai.APIError as e:
            aid = s.alert["alert_id"]
            self.trace.routing(aid, "error", by="runtime", reason=f"model call failed: {type(e).__name__}")
            self._settle(s.alert, "triage", "error", None, f"The model call failed: {e}", [])
            return None

    def _call_model(self, s: AlertState, role: str) -> ModelReply:
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
        reply = self.client.complete(s.items, self.tools)
        self.trace.model_call(aid, role, self.client.model, reply.usage,
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

    def _run_tools(self, s: AlertState, calls: list[ToolCall], stage: str = "classification") -> None:
        """Run the tool calls from one reply in order. submit settles the alert, but only while classifying."""
        aid = s.alert["alert_id"]
        progressed = False
        for i, call in enumerate(calls):
            self.steps += 1
            reason = None
            if stage == "remediation" and call.name == "submit":
                reason = "submit is only for the classification stage"
            elif stage == "classification" and call.name in getattr(self.toolbox, "write_tools", ()):
                reason = f"{call.name} is only for the remediation stage, after you submit label 1"
            if reason is not None:
                obs = self.toolbox.decline(aid, call.id, call.name, call.arguments, reason)
                s.items.append(obs.as_item())
                s.seen_calls.add(_call_key(call))
                continue
            obs = self.toolbox.dispatch(aid, call.id, call.name, call.arguments)
            s.items.append(obs.as_item())
            if call.name == "submit" and obs.ok:
                # Calls after an accepted submit are not run, but each one is still recorded.
                for rest in calls[i + 1:]:
                    self.toolbox.decline(aid, rest.id, rest.name, rest.arguments,
                                            "not run: this alert was already submitted")
                args = json.loads(call.arguments)
                self._settle(s.alert, "submit", "classified", args["label"],
                             args["rationale"], args["evidence"])
                return
            key = _call_key(call)
            progressed |= obs.ok and key not in s.seen_calls
            s.seen_calls.add(key)
        self._track_progress(s, progressed)
        self.trace.routing(aid, "triage" if stage == "classification" else "remediator", by="runtime")

    # Remediation

    def _remediation_stage(self, s: AlertState) -> None:
        """The runtime's routing decision: label 1 goes to remediation, everything else is skipped."""
        aid = s.alert["alert_id"]
        row = self.rows[aid]
        if row["status"] != "classified" or row["label"] != 1:
            self._skip_remediation(aid)
            return
        if not getattr(self.toolbox, "can_remediate", False):
            self._skip_remediation(aid, reason="this toolbox has no write tools")
            return
        self.trace.routing(aid, "remediate", by="runtime", label=1)
        try:
            self._remediate(s)
        finally:
            # Also after a cutoff or failsafe inside remediation: record what the file looks like now.
            remediation = self.toolbox.review(s.alert)
            row["remediation"] = remediation
            self.trace.state_change(aid, "remediation", checks=remediation["checks"],
                                    status=remediation["status"])

    def _remediate(self, s: AlertState) -> None:
        aid = s.alert["alert_id"]
        s.items.append({"role": "user", "content": remediation_prompt(s.alert, self.toolbox.remediation_hint)})
        s.seen_calls.clear()
        s.stalled = 0
        for _ in range(REMEDIATION_TURNS):
            try:
                reply = self._call_model(s, "remediator")
            except openai.APIError as e:
                self.trace.routing(aid, "end_remediation", by="runtime",
                                   reason=f"model call failed: {type(e).__name__}")
                return
            if reply.tool_calls:
                self.trace.routing(aid, "tools", by="model")
                self._run_tools(s, reply.tool_calls, stage="remediation")
            else:
                by = "model" if reply.finish_reason == "stop" else "runtime"
                self.trace.routing(aid, "end_remediation", by=by, finish_reason=reply.finish_reason)
                return
        self.trace.routing(aid, "end_remediation", by="runtime", reason=f"{REMEDIATION_TURNS} turns used")

    def _skip_remediation(self, aid: str, reason: str | None = None) -> None:
        row = self.rows[aid]
        extra = {"reason": reason} if reason else {}
        self.trace.routing(aid, "skip_remediation", by="runtime", label=row["label"],
                           alert_status=row["status"], **extra)
        self.trace.state_change(aid, "remediation", checks=row["remediation"]["checks"],
                                status=row["remediation"]["status"])

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
            "remediation": skipped_remediation(),
        }


def skipped_remediation() -> dict:
    """The remediation object for an alert that got no patch."""
    return {"status": "skipped", "diff": "",
            "checks": {"applies": None, "touches_flagged_line": None, "clean_rescan": None}}


def _call_key(call: ToolCall) -> str:
    """A tool request's identity, ignoring argument order and whitespace."""
    try:
        args = json.dumps(json.loads(call.arguments), sort_keys=True)
    except json.JSONDecodeError:
        args = call.arguments
    return f"{call.name}:{args}"