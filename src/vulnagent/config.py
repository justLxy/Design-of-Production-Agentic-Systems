import json
import tomllib
from pathlib import Path

import jsonschema

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "config.schema.json"


def load_config(path: Path) -> dict:
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.validate(cfg, schema)
    return cfg