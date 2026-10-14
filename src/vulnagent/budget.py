"""Token budget for the whole run.

Used tokens are input + output as reported by the provider (cache tokens are
not counted). Before each model call, check() tests whether the estimated
input plus the output allowance still fits in the budget.
"""

import json
from dataclasses import dataclass

from vulnagent.trace import Trace

CHARS_PER_TOKEN = 3
MESSAGE_OVERHEAD = 50  # rough guess for role and formatting tokens


@dataclass(frozen=True)
class BudgetCheck:
    ok: bool
    remaining: int
    required: int


def estimate_input_tokens(messages: list[dict], tools: list[dict]) -> int:
    chars = len(json.dumps(messages)) + len(json.dumps(tools))
    return chars // CHARS_PER_TOKEN + MESSAGE_OVERHEAD


class Budget:
    def __init__(self, max_tokens: int, output_allowance: int, trace: Trace):
        self.max_tokens = max_tokens
        self.output_allowance = output_allowance
        self.trace = trace
        self.exhausted = False

    @property
    def used(self) -> int:
        """The charge so far: the trace's input + output ledger."""
        return self.trace.used_tokens

    @property
    def remaining(self) -> int:
        return max(0, self.max_tokens - self.used)

    def check(self, items: list[dict], tools: list[dict],
              counted_tokens: int = 0, counted_items: int = 0) -> BudgetCheck:
        """Return whether the next model call fits in the budget.

        counted_tokens is the last call's input + output, which already covers
        items[:counted_items], so only the newer items are estimated. Once a
        check fails, every later check fails too.
        """
        if counted_items:
            estimate = counted_tokens + estimate_input_tokens(items[counted_items:], [])
        else:
            estimate = estimate_input_tokens(items, tools)
        required = estimate + self.output_allowance
        if self.exhausted or required > self.remaining:
            self.exhausted = True
            return BudgetCheck(False, self.remaining, required)
        return BudgetCheck(True, self.remaining, required)