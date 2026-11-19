#!/bin/sh
# Build the sandbox image for one target, with its pinned checkout at /target.
#   scripts/build_image.sh owasp|owasp-injected|radicale|sglang
# owasp-injected is OWASP with fixtures/injection.patch applied (for the live runs).
set -eu
case "${1:-}" in
  owasp|owasp-injected)
    REPO=https://github.com/OWASP-Benchmark/BenchmarkPython
    COMMIT=f1291485808b66e20ddb6b01b10dc71b3df8c8ba ;;
  radicale)
    REPO=https://github.com/Kozea/Radicale
    COMMIT=eff8027f3dc4910be1659ee71f4b4a454ade5a8c ;;
  sglang)
    REPO=https://github.com/sgl-project/sglang
    COMMIT=bbe9c7eeb520b0a67e92d133dfc137a3688dc7f2 ;;
  *) echo "usage: $0 owasp|owasp-injected|radicale|sglang" >&2; exit 2 ;;
esac
INJECT=0
[ "$1" = owasp-injected ] && INJECT=1
cd "$(dirname "$0")/.."
docker build -t "vulnagent-$1:hw2" \
  --build-arg TARGET_REPO="$REPO" --build-arg TARGET_COMMIT="$COMMIT" --build-arg INJECT="$INJECT" .
