"""The run's token budget.

Charge: input + output exactly as the provider reported them, read from the
trace's ledger (cache_read and cache_write are never charged).
Check: before every model call, refuse the call unless the estimated input plus
the full output allowance fits in what remains.
"""

import json
from dataclasses import dataclass

from vulnagent.trace import Trace

CHARS_PER_TOKEN = 3
MESSAGE_OVERHEAD = 50 # rough allowance for the provider's role and formatting tokens


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

    def check(self, messages: list[dict], tools: list[dict]) -> BudgetCheck:
        """Call before every model call. Once a check fails, every later check fails."""
        required = estimate_input_tokens(messages, tools) + self.output_allowance
        if self.exhausted or required > self.remaining:
            self.exhausted = True
            return BudgetCheck(False, self.remaining, required)
        return BudgetCheck(True, self.remaining, required)