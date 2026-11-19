"""Write configs/runs/<target>-mcp.toml: configs/mcp.toml with the staff [scan] block of
Radicale or SGLang swapped in and that target's pinned commit, everything else kept.

configs/mcp.toml and configs/codeact.toml themselves are the OWASP configs.

Usage: python scripts/make_configs.py
"""

import re
from pathlib import Path

from vulnagent.config import load_config

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {  # target: (staff scan block, pinned commit, as in scripts/build_image.sh)
    "radicale": ("radicale.toml", "eff8027f3dc4910be1659ee71f4b4a454ade5a8c"),
    "sglang": ("sglang.toml", "bbe9c7eeb520b0a67e92d133dfc137a3688dc7f2"),
}


def swap_scan(config_text: str, scan_text: str) -> str:
    """Replace everything before [model] (the [scan] block) with the staff block."""
    return scan_text.rstrip() + "\n\n" + config_text[config_text.index("[model]"):]


def main() -> None:
    out_dir = ROOT / "configs" / "runs"
    out_dir.mkdir(exist_ok=True)
    base = (ROOT / "configs" / "mcp.toml").read_text()
    for target, (scan_file, commit) in TARGETS.items():
        scan = (ROOT / "briefs" / "scan" / scan_file).read_text()
        text = re.sub(r'(?m)^commit = ".*"$', f'commit = "{commit}"', swap_scan(base, scan))
        path = out_dir / f"{target}-mcp.toml"
        path.write_text(text)
        load_config(path)  # every generated config must validate against config.schema.json
        print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
