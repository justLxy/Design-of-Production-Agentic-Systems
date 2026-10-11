# hw1-agent-architectures

COMS E6998-019 HW1: build an agent that scans a pinned Python repository with
Bandit and labels each alert. The assignment is in
[briefs/hw1.pdf](briefs/hw1.pdf) (source: `briefs/hw1.tex`).

There is no starter code. You design and write every part of the agent.

| File | What it is |
|---|---|
| `briefs/hw1.pdf` | The assignment brief |
| `briefs/scan/*.toml` | The required `[scan]` block for each target |
| `briefs/report.example.json` | An example `report.json`: 3 of the 18 OWASP rows, showing the format (rationales are placeholders) |
| `config.schema.json` | JSON Schema the config your agent reads (`--config`, TOML) must validate against |
| `report.schema.json` | JSON Schema your `report.json` must validate against |
| `trace.schema.json` | JSON Schema each line of your `trace.jsonl` must validate against |
| `briefs/trace.example.jsonl` | The example trajectory behind `briefs/report.example.json` |

Clone targets into `targets/` (git-ignored). Your own `README.md` must tell us how to run your agent end to end, with `configs/full.toml` and `configs/low.toml` (brief, Section 10).
