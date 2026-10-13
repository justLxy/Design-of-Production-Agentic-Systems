"""Manual check: one real tool-call round trip against the configured model."""

from dotenv import load_dotenv

from vulnagent.dispatcher import Dispatcher
from vulnagent.llm import ModelClient

load_dotenv()
client = ModelClient("openai", "gpt-6-luna", 4000, reasoning_effort="low")
tools = Dispatcher.specs()

items: list[dict] = [{"role": "user", "content":
                      "Use read_file to read lines 1-5 of README.md, then quote its first line."}]
reply = client.complete(items, tools)
print("call 1:", reply.finish_reason, reply.tool_calls, reply.usage)

items += reply.output_items
items.append({"type": "function_call_output", "call_id": reply.tool_calls[0].id,
              "output": "README.md, lines 1-1 of 1\n    1| # Hello from a fake README"})
reply = client.complete(items, tools)
print("call 2:", reply.finish_reason, repr(reply.text), reply.usage)