import os, subprocess
from pathlib import Path
from typing import TypedDict
import networkx as nx
from mcp.server import MCPServer                                # the SDK's main server class
from mcp.server.mcpserver.exceptions import ToolError           # raised when a tool refuses
from cldk import CLDK

HERE = Path(__file__).resolve().parent
TARGET = HERE / "owasp"
os.environ.setdefault("SYSTEM_PYTHON", subprocess.run(["uv", "python", "find", "3.12"], capture_output=True, text=True).stdout.strip())
AN = CLDK.python(project_path=str(TARGET), analysis_level="program_dependency_graph")
mcp = MCPServer("cldk")

def checked(path: str) -> str:
    p = (TARGET / path).resolve()
    if not p.is_relative_to(TARGET) or not p.is_file():
        raise ToolError(f"refused: {path} is not a file of the target")
    return p.relative_to(TARGET).as_posix()

class Located(TypedDict):
    signature: str | None
    name: str | None
    module: str

@mcp.tool(description="The callable that holds a line, or module scope.")
def locate(path: str, line: int) -> Located:
    hit = AN.locate(checked(path), line)
    return {"signature": hit.callable.signature if hit.callable else None,
            "name": hit.callable.name if hit.callable else None, "module": hit.module.module_name}

@mcp.tool(description="The source text of a callable, by signature.")
def source(signature: str) -> str:
    bodies = AN.get_method_bodies([signature])
    if signature not in bodies:
        raise ToolError(f"refused: no body for {signature}")
    return bodies[signature]

@mcp.tool(description="Callers of a callable by name, with file and line.")
def callers(name: str) -> list[dict]:
    return [{"file": c.file, "line": c.line, "callable": c.callable} for c in AN.callers_of(name)]

class Edge(TypedDict):
    from_line: int
    to_line: int
    var: str

@mcp.tool(description="Data-dependence edges of the callable that holds a line: from-line, to-line, variable.")
def dataflow(path: str, line: int) -> list[Edge]:
    hit = AN.locate(checked(path), line)
    if not hit.callable:
        raise ToolError(f"refused: line {line} of {path} is in no callable")
    page = AN.get_ddg(hit.callable.signature, page_size=2000)  # full signature: a bare name like init matches 1,230 callables
    out = []
    for e in page.edges:
        try:
            out.append({"from_line": int(e.src.split("@")[-1].split(":")[0]), "to_line": int(e.dst.split("@")[-1].split(":")[0]), "var": e.var})
        except ValueError:
            continue
    return out

if __name__ == "__main__":
    mcp.run()
