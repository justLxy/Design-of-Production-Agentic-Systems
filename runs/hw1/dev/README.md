# Development runs

Runs I made while building and tuning the agent. REPORT.md cites the two OWASP runs in C2 and
`radicale-full` in C3. I used the two Radicale runs to pick the token budgets.
The files are unedited outputs of `vulnagent`.

They were made before `cli.py` started saving `config.toml` next to the outputs. The
`config.toml` in each folder was rebuilt afterwards from the settings listed here. All of them used `provider = "openai"`, `name = "gpt-6-luna"`,
`reasoning_effort = "low"`, `output_allowance = 4000` and the required `[scan]` block for
the target.

| Run | Target | max_tokens | max_steps | Prompt |
|---|---|---|---|---|
| radicale-low | Radicale | 15,000 | 300 | v1 |
| radicale-full | Radicale | 500,000 | 300 | v1 |
| owasp-full-prompt-v1 | OWASP | 800,000 | 500 | v1 |
| owasp-full-prompt-v2 | OWASP | 800,000 | 500 | v2 |

Prompt v2 adds two bullets to `SYSTEM_PROMPT` in `src/vulnagent/prompts.py` (judge a
function by its default behaviour in Python 3.12, and check whether any input that passes
a validation check can still cause harm). The final runs use prompt v2.
