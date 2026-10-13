"""OpenAI Responses API client: one call per model step, usage exactly as the provider reports it.
"""

from dataclasses import dataclass
from typing import Any

from openai import OpenAI

REQUEST_TIMEOUT_S = 120


@dataclass(frozen=True)
class ToolCall:
    id: str  # the call_id that the matching function_call_output must echo
    name: str
    arguments: str  # raw JSON string


@dataclass(frozen=True)
class ModelReply:
    text: str
    tool_calls: list[ToolCall]
    finish_reason: str  # "tool_calls", "stop", or why the response is incomplete
    usage: dict[str, int]
    output_items: list[dict]  # the response's output, appended to the conversation as-is


def usage_from(raw: Any) -> dict[str, int]:
    """Map the Responses API usage object to the trace's counters. No summed total."""
    usage = {"input": raw.input_tokens, "output": raw.output_tokens}
    details = getattr(raw, "input_tokens_details", None)
    if details is not None:
        if getattr(details, "cached_tokens", None) is not None:
            usage["cache_read"] = details.cached_tokens
        if getattr(details, "cache_write_tokens", None) is not None:
            usage["cache_write"] = details.cache_write_tokens
    return usage


def finish_reason_of(response: Any, tool_calls: list[ToolCall]) -> str:
    if tool_calls:
        return "tool_calls"
    if response.status == "incomplete":
        details = getattr(response, "incomplete_details", None)
        return getattr(details, "reason", None) or "incomplete"
    return "stop"


class ModelClient:
    def __init__(self, provider: str, model: str, output_allowance: int,
                 reasoning_effort: str | None = None, client: Any = None):
        if provider != "openai":
            raise ValueError(f"unsupported provider {provider!r}; only 'openai' is implemented")
        self.model = model
        self.output_allowance = output_allowance
        self.reasoning_effort = reasoning_effort
        self._client = client or OpenAI(timeout=REQUEST_TIMEOUT_S)

    def complete(self, items: list[dict], tools: list[dict]) -> ModelReply:
        """One model call. The output allowance is sent as max_output_tokens."""
        request: dict = {
            "model": self.model,
            "input": items,
            "tools": tools,
            "max_output_tokens": self.output_allowance,
        }
        if self.reasoning_effort:
            request["reasoning"] = {"effort": self.reasoning_effort}
        response = self._client.responses.create(**request)

        calls = [ToolCall(item.call_id, item.name, item.arguments)
                 for item in response.output if item.type == "function_call"]
        return ModelReply(
            text=response.output_text or "",
            tool_calls=calls,
            finish_reason=finish_reason_of(response, calls),
            usage=usage_from(response.usage),
            output_items=[item.model_dump(exclude_none=True) for item in response.output],
        )