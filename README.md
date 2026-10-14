# Design of Production Agentic Systems

## Intro

`vulnagent` is an LLM agent that triages the output of a static security scanner. It runs
Bandit on a Python codebase, then investigates each alert the way a reviewer would, by
reading the surrounding code and following where the data comes from, and decides whether
the alert is a real potential vulnerability or a false positive. Every decision comes with
a short explanation and the lines of code it is based on.

The agent is built to stay inside clear limits. It only reads a sandboxed copy of the
code, never runs or edits it, works within a fixed token budget, and records every step it
takes so a run can be checked afterwards. The design and the results are in
[REPORT.md](REPORT.md).

## Setup

You need Python 3.12 and git. On macOS I used Homebrew (`brew install python@3.12`). On
Ubuntu 24.04 `sudo apt install python3.12 python3.12-venv` works. Then, from a fresh clone:

```bash
git clone https://github.com/justLxy/Design-of-Production-Agentic-Systems.git

cd Design-of-Production-Agentic-Systems
```


```bash
python3.12 -m venv .venv

.venv/bin/pip install -r requirements.lock

.venv/bin/pip install --no-deps -e .
```

`requirements.lock` pins all dependencies, including `bandit==1.9.4`.

The agent reads one environment variable, `OPENAI_API_KEY`. You can export it in the shell,
or copy `.env.example` to `.env` at the repository root and fill in the key (the agent
loads it with python-dotenv, and `.env` is in `.gitignore`). A key that is already
exported in the shell wins over the one in `.env`.

## Targets

The agent takes the root of a target checkout as `--input`. I kept my checkouts in
`targets/`, which is git-ignored. To get the same pinned commits:

```bash
git clone https://github.com/Kozea/Radicale targets/radicale

git -C targets/radicale checkout eff8027f3dc4910be1659ee71f4b4a454ade5a8c

git clone https://github.com/sgl-project/sglang targets/sglang

git -C targets/sglang checkout bbe9c7eeb520b0a67e92d133dfc137a3688dc7f2

git clone https://github.com/OWASP-Benchmark/BenchmarkPython targets/owasp-benchmark-python

git -C targets/owasp-benchmark-python checkout f1291485808b66e20ddb6b01b10dc71b3df8c8ba
```

The agent never changes the checkout. It copies it to a temp folder first and only the copy
is visible to the model, without `.git/`, the OWASP answer key and the other OWASP test
cases (see A7 in the report).

## Running

The command has the form from the brief:

```bash
.venv/bin/vulnagent --input <target checkout root> --output <out dir> --config <config.toml>
```

For example, Radicale with the full budget and then with the low budget:

```bash
.venv/bin/vulnagent --input targets/radicale --output out/radicale-full --config configs/full.toml
```

```bash
.venv/bin/vulnagent --input targets/radicale --output out/radicale-low --config configs/low.toml
```

The output folder gets `report.json`, `trace.jsonl` and a copy of the config as
`config.toml`. When the run ends the agent prints one line with the terminal status and the
label counts, for example
`completed: 10 alerts: label 1 = 6, label 0 = 4, null = 0; used 178288 of 800000 tokens`.
If the run crashes, the command exits with an error, but `report.json` and `trace.jsonl`
are still written and the trace ends with a `crashed` terminal event. I suggest writing to
`out/` (git-ignored) so the committed runs in `runs/` are not overwritten.

In my final runs a full run took about 100 s and 178k tokens on Radicale, 282 s and 419k
tokens on SGLang, and 150 s and 88k tokens on OWASP.

## Configs

There are two configs, and both validate against `config.schema.json`:

| File | max_tokens | What it is for |
|---|---|---|
| `configs/full.toml` | 800,000 | enough for a complete run on all three targets (SGLang, the biggest, used 419k) |
| `configs/low.toml` | 60,000 | runs out partway through Radicale; in my run 3 alerts were classified and the other 7 got `budget_exhausted` |

Everything else is the same in both: `provider = "openai"`, `name = "gpt-6-luna"`,
`reasoning_effort = "low"`, `output_allowance =
4000` and `max_steps = 500`. Both have the Radicale `[scan]` block. To run another target,
replace the `[scan]` block with that target's block from `briefs/scan/` and keep the rest.

The six configs I used for my own runs, with the block already swapped, are in
`configs/runs/<target>-<budget>.toml` (target is `radicale`, `sglang` or `owasp`).

## What is in the repository

| Path | Contents |
|---|---|
| `src/vulnagent/` | the agent: CLI, Bandit wrapper, workspace, tools, dispatcher, model client, budget, graph, tracer, report |
| `configs/` | `full.toml`, `low.toml`, and the six configs in `configs/runs/` |
| `runs/<target>-<budget>/` | the six final runs cited in the report, unedited, each with its `config.toml` |
| `runs/dev/` | earlier runs from development that the report also cites; their settings are in `runs/dev/README.md` |
| `REPORT.md` | design report (Part A), results (C2), limitations and alternatives (C3), contribution statement |
| `requirements.lock` | pinned dependencies |
