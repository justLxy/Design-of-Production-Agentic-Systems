# Agent prompts

- `codeact_generation_prompt.md`: the exact prompt I gave Claude Code to write the CodeAct prompt
  file (rubric item C5). Claude Code ran it in a clone of the CLDK Python SDK at tag v2.0.0.
- `codeact_agent.md`: the file it wrote, which I reviewed. The CodeAct harness reads it from the
  path in `[codeact] prompt` of the config and appends it to the system prompt, after the rules
  shared with the MCP agent (labels, evidence and access rules).

The MCP agent's system prompt is short and lives in the code, because its tools already carry
their own descriptions and schemas from `tools/list`.
