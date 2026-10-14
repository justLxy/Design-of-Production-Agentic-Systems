"""Write configs/runs/<target>-<budget>.toml: configs/full.toml and configs/low.toml
with each staff [scan] block swapped in and everything else kept.

Usage: python scripts/make_configs.py
"""

from pathlib import Path

from vulnagent.config import load_config

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "radicale": "radicale.toml",
    "sglang": "sglang.toml",
    "owasp": "owasp-benchmark-python.toml",
}


def swap_scan(config_text: str, scan_text: str) -> str:
    """Replace everything before [model] (the [scan] block) with the staff block."""
    return scan_text.rstrip() + "\n\n" + config_text[config_text.index("[model]"):]


def main() -> None:
    out_dir = ROOT / "configs" / "runs"
    out_dir.mkdir(exist_ok=True)
    for budget in ("full", "low"):
        base = (ROOT / "configs" / f"{budget}.toml").read_text()
        for target, scan_file in TARGETS.items():
            scan = (ROOT / "briefs" / "scan" / scan_file).read_text()
            path = out_dir / f"{target}-{budget}.toml"
            path.write_text(swap_scan(base, scan))
            load_config(path)  # every generated config must validate against config.schema.json
            print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()