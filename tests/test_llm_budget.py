"""Tests for the model client (B6) and the budget (B6, B7). No network calls."""

from types import SimpleNamespace as NS

import pytest

from vulnagent.budget import Budget
from vulnagent.llm import ModelClient, usage_from
from vulnagent.trace import Trace


class FakeItem(NS):
    """An output item shaped like the SDK's pydantic models."""

    def model_dump(self, exclude_none: bool = False) -> dict:
        return {k: v for k, v in vars(self).items() if not (exclude_none and v is None)}


def fake_response(output=(), text="", status="completed", incomplete_reason=None,
                  input_tokens=100, output_tokens=20, cached=0, cache_write=None):
    """An object shaped like the OpenAI SDK's Response."""
    usage = NS(input_tokens=input_tokens, output_tokens=output_tokens,
               total_tokens=input_tokens + output_tokens,
               input_tokens_details=NS(cached_tokens=cached, cache_write_tokens=cache_write))
    details = NS(reason=incomplete_reason) if incomplete_reason else None
    return NS(output=list(output), output_text=text, status=status,
              incomplete_details=details, usage=usage)


class FakeOpenAI:
    """Records the request and returns a canned response."""

    def __init__(self, response):
        self.response = response
        self.request: dict = {}
        self.responses = NS(create=self._create)

    def _create(self, **kwargs):
        self.request = kwargs
        return self.response


def client_for(response, **kwargs) -> tuple[ModelClient, FakeOpenAI]:
    fake = FakeOpenAI(response)
    return ModelClient("openai", "gpt-6-luna", 4000, client=fake, **kwargs), fake


def test_usage_maps_provider_counters_without_a_total():
    usage = usage_from(fake_response(input_tokens=5210, output_tokens=190, cached=4000).usage)
    assert usage == {"input": 5210, "output": 190, "cache_read": 4000}


def test_usage_records_cache_write_only_when_reported():
    assert usage_from(fake_response(cache_write=300).usage)["cache_write"] == 300


def test_the_output_allowance_and_reasoning_effort_are_sent():
    client, fake = client_for(fake_response(text="hi"), reasoning_effort="low")
    client.complete([], [])
    assert fake.request["max_output_tokens"] == 4000
    assert fake.request["reasoning"] == {"effort": "low"}
    assert fake.request["model"] == "gpt-6-luna"


def test_function_calls_are_parsed_and_kept_for_the_conversation():
    call = FakeItem(type="function_call", call_id="call_1", name="read_file",
                    arguments='{"path": "a.py"}', id="fc_1")
    reasoning = FakeItem(type="reasoning", id="rs_1", summary=[])
    client, _ = client_for(fake_response(output=[reasoning, call]))
    reply = client.complete([], [])
    assert reply.finish_reason == "tool_calls"
    assert reply.tool_calls[0].id == "call_1" and reply.tool_calls[0].name == "read_file"
    assert [item["type"] for item in reply.output_items] == ["reasoning", "function_call"]


def test_a_truncated_reply_reports_why():
    client, _ = client_for(fake_response(status="incomplete", incomplete_reason="max_output_tokens"))
    reply = client.complete([], [])
    assert reply.finish_reason == "max_output_tokens" and reply.text == ""


def test_only_the_openai_provider_is_supported():
    with pytest.raises(ValueError):
        ModelClient("anthropic", "x", 100, client=object())


def test_budget_charges_input_plus_output_but_not_cache(tmp_path):
    trace = Trace(tmp_path / "trace.jsonl", "t")
    budget = Budget(max_tokens=10_000, output_allowance=100, trace=trace)
    trace.model_call("a1", "classifier", "gpt-6-luna", {"input": 1000, "output": 200, "cache_read": 900})
    trace.model_call("a1", "classifier", "gpt-6-luna", {"input": 1500, "output": 300, "cache_read": 1200})
    assert budget.used == 3000
    assert budget.remaining == 7000


def test_check_refuses_when_estimate_plus_allowance_does_not_fit(tmp_path):
    trace = Trace(tmp_path / "trace.jsonl", "t")
    budget = Budget(max_tokens=1000, output_allowance=900, trace=trace)
    messages = [{"role": "user", "content": "x" * 600}]  # about 200 + 50 estimated input tokens
    check = budget.check(messages, [])
    assert not check.ok and check.required > check.remaining
    assert budget.exhausted


def test_a_refused_check_is_sticky(tmp_path):
    trace = Trace(tmp_path / "trace.jsonl", "t")
    budget = Budget(max_tokens=1000, output_allowance=900, trace=trace)
    budget.check([{"role": "user", "content": "x" * 600}], [])
    assert not budget.check([], []).ok  # would fit on its own, but the cutoff already happened


def test_a_zero_budget_refuses_the_first_call(tmp_path):
    budget = Budget(max_tokens=0, output_allowance=1, trace=Trace(tmp_path / "trace.jsonl", "t"))
    assert not budget.check([], []).ok

def test_check_uses_the_providers_count_for_the_conversation_so_far(tmp_path):
    budget = Budget(max_tokens=10_000, output_allowance=100, trace=Trace(tmp_path / "trace.jsonl", "t"))
    earlier = [{"role": "user", "content": "x" * 30_000}]  # about 10_000 tokens by the estimate
    new = [{"type": "function_call_output", "call_id": "c1", "output": "y" * 300}]
    assert not budget.check(earlier + new, []).ok  # estimating everything does not fit...
    budget.exhausted = False
    check = budget.check(earlier + new, [], counted_tokens=2_000, counted_items=1)
    assert check.ok and check.required < 2_500  # ...the provider counted 2_000 for the first item