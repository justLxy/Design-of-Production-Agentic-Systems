# Design of Production Agentic Systems

## Intro

`vulnagent` runs Bandit on a Python codebase, labels each alert 1 for a potential vulnerability
or 0 for a false positive, and tries to fix the alerts labelled 1. The MCP agent uses tools on an
MCP server that I wrote over CLDK 2.0.0. The CodeAct agent writes Python that my harness runs in an
execution kernel. Both run inside an OpenShell sandbox. The report is [REPORT.md](REPORT.md), and
the HW1 version is at the git tag `hw1-submission`.

## Setup

I used macOS on Apple Silicon with Docker Desktop. You need Python 3.12, git and Docker.
On macOS you can install Python with `brew install python@3.12`, and on Ubuntu 24.04 with
`sudo apt install python3.12 python3.12-venv`.

```bash
git clone https://github.com/justLxy/Design-of-Production-Agentic-Systems.git
```

```bash
cd Design-of-Production-Agentic-Systems
```

```bash
python3.12 -m venv .venv
```

```bash
.venv/bin/pip install -r requirements.lock
```

```bash
.venv/bin/pip install --no-deps -e .
```

`requirements.lock` pins every dependency, including `bandit==1.9.4`, `cldk==2.0.0` and
`mcp==2.3.0`. The sandbox image installs the same file.

OpenShell 0.1.4:

```bash
curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.4/install.sh -o /tmp/openshell-install.sh
```

```bash
OPENSHELL_VERSION=v0.1.4 sh /tmp/openshell-install.sh
```

With Docker Desktop, sandbox creation failed until I wrote `~/.config/openshell/gateway.toml`
with Docker Desktop's socket and the `grpc_endpoint` from the brief. After writing the file,
restart the gateway with `brew services restart nvidia/openshell/openshell`.

```toml
[openshell]
version = 2
[openshell.gateway]
compute_driver = "docker"
[openshell.drivers.docker]
socket_path = "/Users/<you>/.docker/run/docker.sock"
grpc_endpoint = "https://host.docker.internal:17670"
```

If `~/.docker/daemon.json` sets `"dns"`, remove that setting and restart Docker Desktop. With my
DNS override the sandbox supervisor could not resolve `host.docker.internal`.

Environment variables:

- `OPENAI_API_KEY`, read by the agent. Inside the sandbox it holds a placeholder from the
  OpenShell provider.
- `SYSTEM_PYTHON`, read by CLDK and set in `mcp.json`.
- `VULNAGENT_SOURCE`, `VULNAGENT_TARGET_ROOT`, `VULNAGENT_TARGET_ENTRIES`, `VULNAGENT_WORKDIR`
  and `VULNAGENT_ANALYSIS_SCOPE`, read by the MCP server.

## Model provider

`providers/openai.yaml` is OpenShell's OpenAI profile with `binaries` changed to the interpreter
in my image. Import it and create the provider from `OPENAI_API_KEY` in your shell.

```bash
openshell provider profile import -f providers/openai.yaml --global
```

```bash
openshell provider create --name openai --type openai --global-profile --credential OPENAI_API_KEY
```

## Sandbox image

Each image has one target's pinned checkout at `/target`, the agent and its dependencies under
`/app`, and a user with UID 1000 who owns `/sandbox`. Build them from the repository root.

```bash
docker build -t vulnagent-owasp:hw2 --build-arg TARGET_REPO=https://github.com/OWASP-Benchmark/BenchmarkPython --build-arg TARGET_COMMIT=f1291485808b66e20ddb6b01b10dc71b3df8c8ba .
```

```bash
docker build -t vulnagent-radicale:hw2 --build-arg TARGET_REPO=https://github.com/Kozea/Radicale --build-arg TARGET_COMMIT=eff8027f3dc4910be1659ee71f4b4a454ade5a8c .
```

```bash
docker build -t vulnagent-sglang:hw2 --build-arg TARGET_REPO=https://github.com/sgl-project/sglang --build-arg TARGET_COMMIT=bbe9c7eeb520b0a67e92d133dfc137a3688dc7f2 .
```

The injection runs use the same OWASP build with `fixtures/injection.patch` applied.

```bash
docker build -t vulnagent-owasp-injected:hw2 --build-arg TARGET_REPO=https://github.com/OWASP-Benchmark/BenchmarkPython --build-arg TARGET_COMMIT=f1291485808b66e20ddb6b01b10dc71b3df8c8ba --build-arg INJECT=1 .
```

## Launch commands

Each command creates a sandbox from `policy.yaml` with the `openai` provider, copies the code
directories of `/target` to `/sandbox/work/target` and runs the agent on that copy. Delete an
existing sandbox of the same name first with `openshell sandbox delete <name>`.

The MCP agent on OWASP:

```bash
openshell sandbox create --name vulnagent-mcp --from vulnagent-owasp:hw2 --policy policy.yaml --provider openai --detach -- sleep infinity && openshell sandbox exec -n vulnagent-mcp --no-login-shell --no-tty --env HOME=/sandbox -- sh -c 'mkdir -p /sandbox/work/target && cp -R /target/testcode /target/helpers /target/app.py /sandbox/work/target/ && vulnagent --input /sandbox/work/target --output /sandbox/work/mcp-owasp --config /app/configs/mcp.toml'
```

The CodeAct agent on OWASP:

```bash
openshell sandbox create --name vulnagent-codeact --from vulnagent-owasp:hw2 --policy policy.yaml --provider openai --detach -- sleep infinity && openshell sandbox exec -n vulnagent-codeact --no-login-shell --no-tty --env HOME=/sandbox -- sh -c 'mkdir -p /sandbox/work/target && cp -R /target/testcode /target/helpers /target/app.py /sandbox/work/target/ && vulnagent --input /sandbox/work/target --output /sandbox/work/codeact-owasp --config /app/configs/codeact.toml'
```

For Radicale or SGLang, use that target's image, copy `/target/radicale` or `/target/python`
and `/target/scripts` instead of the OWASP entries, and pass `/app/configs/runs/radicale-mcp.toml`
or `/app/configs/runs/sglang-mcp.toml`. These are `configs/mcp.toml` with the staff `[scan]` block.

The agent writes `report.json`, `trace.jsonl` and `config.toml` to its `--output` directory. To
copy them out of the sandbox:

```bash
openshell sandbox download vulnagent-mcp /sandbox/work/mcp-owasp out/mcp-owasp
```

## Configs

`configs/mcp.toml` and `configs/codeact.toml` differ only in `[agent] kind`. Both use the OWASP
`[scan]` block, `gpt-6-luna` with `reasoning_effort = "low"`, 3,000,000 tokens and
`max_steps = 2000`. They also have three tables of my own. `[mcp]` names `mcp.json`, `[codeact]`
names the CodeAct prompt file, the kernel's interpreter and a 600 s limit per code action, and
`[target]` gives the pinned commit for `report.json`.

## The MCP server

`mcp.json` starts the server as `/usr/local/bin/python3.12 -m vulnagent.server`. Started with no
staged files, the server copies the code directories of `/target` into `VULNAGENT_WORKDIR` and
serves that copy. It answers `initialize` at once and builds the CLDK analysis in the background,
which takes about two minutes on OWASP. When the agent starts the server, it passes its input copy
in `VULNAGENT_SOURCE` and the `[scan]` paths in `VULNAGENT_ANALYSIS_SCOPE`, and on a project above
5 MB of Python such as SGLang the server analyses only those paths.

To start the server the way the staff driver does, in a sandbox created as above:

```bash
openshell sandbox exec -n vulnagent-mcp --no-login-shell --no-tty --env SYSTEM_PYTHON=/usr/local/bin/python3.12 --env VULNAGENT_TARGET_ROOT=/target --env VULNAGENT_TARGET_ENTRIES=testcode:helpers:app.py:radicale:python:scripts --env VULNAGENT_WORKDIR=/sandbox/work/mcp-server -- /usr/local/bin/python3.12 -m vulnagent.server
```

### Tool contracts

Paths are relative to the workspace root. Every input schema sets `additionalProperties: false`,
and the server validates the arguments before the tool runs. A refusal is a tool result with
`isError: true` whose text starts with `refused:`. When the operating system denied an access that
the server allowed, the text starts with `refused (kernel):` instead.

The analysis tools are built on CLDK.

| Tool | Arguments | Result |
|---|---|---|
| `locate` | `path`, `line` of at least 1 | `{path, line, signature, name, start_line, end_line}` of the callable around the line, with nulls at module scope |
| `source` | a `signature` returned by `locate` | `{signature, path, start_line, end_line, text}` with the numbered body |
| `dataflow` | `path`, `line` | `{signature, edges: [{from_line, to_line, var}]}` with the data-dependence edges of the callable around the line, where `from_line: null` means that the value enters at the callable's entry |
| `callers` | `name`, optional dotted `module` | `{sites: [{path, line, signature, external}], hidden}` |
| `callees` | `name`, optional `module` | the same shape, with `external: true` on library calls |
| `entry_points` | none | `{entry_points: [{path, line, signature}], total, hidden, frameworks, unresolved, errors}` |

The source tools are the HW1 tools. `read_file(path, start_line=1, end_line)` returns `{text}`
with at most 200 numbered lines per call, `search(pattern, path=".")` returns `{text}` with
`path:line: text` matches, and `list_dir(path=".")` returns `{path, entries}`.

`edit(path, old, new)` replaces the one exact occurrence of `old` in the open alert's file and
returns `{path, diff}`, where `diff` is the diff against the pinned commit. `rescan(path)` runs
Bandit 1.9.4 at MEDIUM and above on one workspace file and returns
`{path, alerts: [{test_id, line, severity, confidence, issue_text}]}`.

`submit(label, rationale, evidence)` records the label for the open alert. `label` is 0 or 1,
`rationale` has at most 2,000 characters, and `evidence` has 1 to 5 ranges
`{path, start_line, end_line}` that must exist in files the model may read.

Two tools are only for the host and are never offered to the model. `tools/list` marks them with
`_meta.host_only: true`, and the host drops them. `set_alert(alert_id)` opens an alert and returns
`{alert_id, path, case}`. It accepts an alert id from `report.json` and, on OWASP, also a bare case
name such as `BenchmarkTest00011`. `review_patch()` returns `{path, status, diff, checks}` for the
open alert's file.

The server refuses the following requests.

- Reads through `read_file`, `search`, `list_dir`, `locate`, `dataflow`, `source` or `rescan` of
  an absolute path, a path with `..`, a symlink that leaves the workspace, anything in `.git`, the
  answer key `expectedresults*.csv`, the `.codeanalyzer` cache or a top-level `results/`. On OWASP
  the server also refuses every `BenchmarkTest*` file other than the open case, and every case
  when no alert is open. `callers`, `callees` and `entry_points` leave out sites in files that the
  model may not read and count them in `hidden`.
- Writes through `edit` to any file other than the open alert's file or to any path outside the
  workspace, and edits whose `old` text is missing or occurs more than once.
- Calls to unknown tools and calls with unknown arguments, missing arguments or wrong types.
- A `submit` when no alert is open, and a `submit` whose evidence lies outside the readable files
  or past the end of a file.

## The CodeAct agent

The CodeAct agent has the tools `run_python(code)` and `submit`. `run_python` runs the code with
`exec` in a persistent namespace in my execution kernel, a separate Python process inside the
sandbox, so a CLDK analysis object stays available across actions. The kernel's working directory
is a copy of the input named `WORKSPACE`, and the open alert is bound as `ALERT`. The model gets
back the output, the value of a final expression and any traceback.

I wrote the prompt file with Claude Code in these steps.

1. Clone the CLDK Python SDK and check out the version the agent uses.

   ```bash
   git clone https://github.com/codellm-devkit/python-sdk.git
   ```

   ```bash
   git -C python-sdk checkout v2.0.0
   ```

2. Start Claude Code and give it the prompt in `prompts/codeact_generation_prompt.md`, which is
   the exact prompt I used with the paths on my machine. Claude Code reads the SDK source and
   writes `prompts/codeact_agent.md`, which I then reviewed.

The harness reads the file named by `[codeact] prompt` and appends it to the system prompt after
my rules for labels, evidence and access. The file tells the agent to create the CLDK analysis on
`WORKSPACE` once, choose the analysis methods it needs and compose them into helper functions.

## What is in the repository

| Path | Contents |
|---|---|
| `src/vulnagent/` | the agent with its CLI, loop, model client, budget, tracer and report, the MCP server and host, and the CodeAct toolbox with its execution kernel |
| `mcp.json`, `policy.yaml` | the server entry and the sandbox policy |
| `Dockerfile`, `providers/openai.yaml` | the sandbox image and the OpenShell provider profile |
| `prompts/` | the CodeAct prompt file and the prompt that generated it |
| `configs/` | `mcp.toml`, `codeact.toml` and the per-target MCP configs in `configs/runs/` |
| `runs/` | the unedited runs cited in the report, each with its config |
| `REPORT.md` | the design report, the live-run measurement, the comparisons, the limitations and the contribution statement |
| `requirements.lock` | the pinned dependencies |
