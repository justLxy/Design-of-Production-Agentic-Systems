#!/bin/sh
# Run one agent inside a fresh OpenShell sandbox and download its outputs to out/<run>.
#   scripts/sandbox_run.sh <target> <config> <run>
#   scripts/sandbox_run.sh owasp configs/mcp.toml mcp-owasp
# <target> picks the image (vulnagent-<target>:hw2) and which entries of /target are copied
# into the workspace; <config> is a path inside the repository (the image has it under /app).
set -eu
TARGET=$1 CONFIG=$2 RUN=$3
case "$TARGET" in
  owasp|owasp-injected) ENTRIES="testcode helpers app.py" ;;
  radicale) ENTRIES="radicale" ;;
  sglang) ENTRIES="python scripts" ;;
  *) echo "unknown target $TARGET" >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."
NAME="va-$RUN"  # OpenShell allows at most 19 characters in a sandbox name
[ ${#NAME} -le 19 ] || { echo "run name $RUN is too long for a sandbox name" >&2; exit 2; }
openshell sandbox delete "$NAME" >/dev/null 2>&1 || true
openshell sandbox create --name "$NAME" --from "vulnagent-$TARGET:hw2" --policy policy.yaml \
  --provider openai --detach -- sleep infinity
COPY=""
for entry in $ENTRIES; do COPY="$COPY /target/$entry"; done
openshell sandbox exec -n "$NAME" --no-login-shell --no-tty --env HOME=/sandbox -- sh -c "
  mkdir -p /sandbox/work/target && cp -R $COPY /sandbox/work/target/ &&
  vulnagent --input /sandbox/work/target --output /sandbox/work/$RUN --config /app/$CONFIG" || echo "agent exited with $?"
mkdir -p out
openshell sandbox download "$NAME" "/sandbox/work/$RUN" "out/$RUN"
echo "outputs in out/$RUN"
