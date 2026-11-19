# Sandbox image for vulnagent (HW2): the agent, the MCP server and their pinned
# dependencies under /app, and one target checkout at /target.
#
#   scripts/build_image.sh owasp            # or radicale, sglang, owasp-injected
#
# Stage 1 clones the target at its pinned commit (with git). Stage 2 is the image.
FROM python:3.12-slim AS target
ARG TARGET_REPO
ARG TARGET_COMMIT
ARG INJECT=0
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY fixtures/injection.patch /tmp/injection.patch
RUN git clone --quiet "$TARGET_REPO" /target \
 && git -C /target checkout --quiet "$TARGET_COMMIT" \
 && if [ "$INJECT" = 1 ]; then git -C /target apply /tmp/injection.patch; fi \
 && git -C /target rev-parse HEAD > /tmp/target-commit

FROM python:3.12-slim
# Everything is installed while building: inside the sandbox there is no package index.
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r /app/requirements.lock
COPY pyproject.toml mcp.json policy.yaml config.schema.json report.schema.json trace.schema.json /app/
COPY src /app/src
COPY configs /app/configs
COPY scripts /app/scripts
COPY prompts /app/prompts
RUN pip install --no-cache-dir --no-deps -e /app
# The CodeAct kernel runs model-written code under its own copy of the interpreter.
# The network policy names binaries by path and lets only /usr/local/bin/python3.12
# (the harness and the MCP server) reach the model provider.
RUN cp /usr/local/bin/python3.12 /usr/local/bin/python3.12-kernel
# The target is owned by root and readable by everyone, so every denial comes from the sandbox policy.
COPY --from=target /target /target
COPY --from=target /tmp/target-commit /etc/vulnagent-target-commit
RUN chmod -R a+rX /target \
 && useradd -m -u 1000 sandbox \
 && mkdir -p /sandbox && chown 1000:1000 /sandbox
