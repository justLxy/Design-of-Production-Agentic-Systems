"""The CodeAct execution kernel: runs model-written Python in one persistent namespace.

The harness starts it with `python -m vulnagent.kernel --workspace DIR --detach`
inside the sandbox. Variables, imports and the CLDK analysis object the model
creates stay in the namespace across calls and alerts, like cells of a notebook.

--detach: OpenShell lets a process reach a network endpoint if its binary, or the
binary of any ancestor, is listed in the policy. The harness runs as the listed
python3.12, so a kernel started as its child could reach the model provider too.
With --detach the kernel forks and the parent exits, so the kernel is re-parented
to the sandbox supervisor and the harness is no longer among its ancestors. Run
under an interpreter path the policy does not list, it then has no network at all.

Protocol: one JSON object per line. Requests come on stdin, replies go to stdout.
Before any model code runs, the kernel moves both pipes to private descriptors,
points fd 0 at /dev/null and fds 1 and 2 at a capture file. So print(), tracebacks
and subprocesses (bandit, CLDK's analyzer) all write to the capture file, which is
returned with the reply, and nothing the model runs can write into the protocol.

The first line the kernel writes is {"ready": true, "pid": N}. Then, per request:
  {"op": "exec", "code": "..."}            run code; reply {ok, output, value, error}
  {"op": "set", "name": "ALERT", "value": {...}}   bind a name; reply {ok}
"""

import argparse
import ast
import builtins
import errno
import json
import linecache
import os
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any

MAX_OUTPUT_CHARS = 12_000  # output beyond this is cut in the middle
MAX_VALUE_CHARS = 4_000


def is_permission_error(e: BaseException) -> bool:
    """True if e, or an exception it was raised from, is the OS refusing access."""
    seen: set[int] = set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        if isinstance(e, PermissionError) or (
                isinstance(e, OSError) and e.errno in (errno.EACCES, errno.EPERM)):
            return True
        e = e.__cause__ or e.__context__
    return False


def cut_middle(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]}\n... [{len(text) - limit} characters cut] ...\n{text[-half:]}"


class Kernel:
    def __init__(self, workspace: Path, capture_fd: int, capture_path: str):
        self.capture_fd = capture_fd
        self.capture_path = capture_path
        self.cells = 0
        self.namespace: dict[str, Any] = {
            "__name__": "__main__",
            "__builtins__": builtins,
            "WORKSPACE": str(workspace),
            "ALERT": None,
        }

    def handle(self, request: dict) -> dict:
        op = request.get("op")
        if op == "set":
            self.namespace[request["name"]] = request["value"]
            return {"ok": True}
        if op == "exec":
            return self.run(request["code"])
        return {"ok": False, "output": "", "value": None,
                "error": {"type": "ProtocolError", "message": f"unknown op {op!r}", "permission": False,
                          "traceback": ""}}

    def run(self, code: str) -> dict:
        os.ftruncate(self.capture_fd, 0)
        self.cells += 1
        filename = f"<run_python #{self.cells}>"
        # Register the source so tracebacks show the model's own lines.
        linecache.cache[filename] = (len(code), None, code.splitlines(keepends=True), filename)
        value = error = None
        try:
            tree = ast.parse(code, filename, "exec")
            last = None
            if tree.body and isinstance(tree.body[-1], ast.Expr):
                last = ast.Expression(tree.body.pop().value)
            exec(compile(tree, filename, "exec"), self.namespace)
            if last is not None:
                result = eval(compile(last, filename, "eval"), self.namespace)
                if result is not None:
                    value = cut_middle(repr(result), MAX_VALUE_CHARS)
        except SystemExit:
            pass  # sys.exit() in a cell ends the cell, not the kernel
        except BaseException as e:
            # Drop this frame (the exec call) so the traceback starts in the model's code.
            tb = traceback.format_exception(type(e), e, e.__traceback__.tb_next if e.__traceback__ else None)
            error = {"type": type(e).__name__, "message": str(e), "permission": is_permission_error(e),
                     "traceback": cut_middle("".join(tb), MAX_OUTPUT_CHARS // 2)}
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
        return {"ok": error is None, "output": self.read_output(), "value": value, "error": error}

    def read_output(self) -> str:
        with open(self.capture_path, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            if size <= MAX_OUTPUT_CHARS:
                f.seek(0)
                return f.read().decode("utf-8", errors="replace")
            half = MAX_OUTPUT_CHARS // 2
            f.seek(0)
            head = f.read(half).decode("utf-8", errors="replace")
            f.seek(size - half)
            tail = f.read(half).decode("utf-8", errors="replace")
        return f"{head}\n... [{size - 2 * half} bytes cut] ...\n{tail}"


def main() -> None:
    parser = argparse.ArgumentParser(prog="vulnagent.kernel")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--detach", action="store_true", help="leave the parent's process tree first")
    args = parser.parse_args()

    if args.detach:
        parent = os.getpid()
        if os.fork() > 0:
            os._exit(0)  # the harness reaps this one; the child below keeps the pipes
        while os.getppid() == parent:  # wait until the re-parenting has happened
            time.sleep(0.01)

    # Keep the pipes for the protocol, out of reach of the model's code and its children
    # (os.dup returns descriptors that are not inherited by subprocesses).
    proto_in = os.fdopen(os.dup(0), "r", encoding="utf-8")
    proto_out = os.fdopen(os.dup(1), "w", encoding="utf-8", buffering=1)
    fd, capture_path = tempfile.mkstemp(prefix="vulnagent-kernel-", suffix=".out")
    os.close(fd)
    capture_fd = os.open(capture_path, os.O_WRONLY | os.O_APPEND)
    null_fd = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null_fd, 0)
    os.dup2(capture_fd, 1)
    os.dup2(capture_fd, 2)
    sys.stdin = open(0, "r", closefd=False)
    sys.stdout = open(1, "w", buffering=1, encoding="utf-8", errors="replace", closefd=False)
    sys.stderr = open(2, "w", buffering=1, encoding="utf-8", errors="replace", closefd=False)

    os.chdir(args.workspace)
    kernel = Kernel(args.workspace.resolve(), capture_fd, capture_path)
    proto_out.write(json.dumps({"ready": True, "pid": os.getpid()}) + "\n")
    for line in proto_in:
        try:
            reply = kernel.handle(json.loads(line))
        except Exception as e:  # a malformed request; the harness never sends one
            reply = {"ok": False, "output": "", "value": None,
                     "error": {"type": type(e).__name__, "message": str(e), "permission": False, "traceback": ""}}
        proto_out.write(json.dumps(reply) + "\n")
    os.unlink(capture_path)
    os._exit(0)  # skip tearing down whatever the model built (a CLDK graph takes seconds)


if __name__ == "__main__":
    main()
