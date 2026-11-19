"""Compare runs from their traces and reports: model turns, context tokens, tool calls by
group, labels against the OWASP answer key, accepted patches, and the per-alert labels.

Only for writing the report by hand. Usage:
  python scripts/compare_runs.py <run dir> [<run dir> ...]
"""

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import DEFAULT_KEY, load_key  # noqa: E402

GROUPS = {
    "analysis": {"locate", "dataflow", "source", "callers", "callees", "entry_points"},
    "source": {"read_file", "search", "list_dir"},
    "edit": {"edit"},
    "rescan": {"rescan"},
    "submit": {"submit"},
    "run_python": {"run_python"},
}


def summarize(run: Path, key: dict) -> dict:
    events = [json.loads(line) for line in (run / "trace.jsonl").read_text().splitlines()]
    report = json.loads((run / "report.json").read_text())
    calls = [e for e in events if e["kind"] == "model_call"]
    stage_of: dict[str, str] = {}
    by_group: collections.Counter = collections.Counter()
    by_stage: collections.Counter = collections.Counter()
    stage = {}  # alert -> current stage, from the routing events
    for e in events:
        aid = e.get("alert_id")
        if e["kind"] == "routing" and e.get("decision") == "remediate":
            stage[aid] = "remediation"
        if e["kind"] == "tool_request":
            group = next((g for g, names in GROUPS.items() if e["tool"] in names), "other")
            by_group[group] += 1
            by_stage[(group, stage.get(aid, "classification"))] += 1
    refusals = collections.Counter(e.get("refused_by") or "none" for e in events
                                   if e["kind"] == "tool_result" and not e["ok"])
    rows = report["alerts"]
    labelled = [r for r in rows if r["label"] is not None]
    correct = sum((r["label"] == 1) == key[Path(r["path"]).stem][1] for r in labelled) if key else None
    usage = {k: sum(c["usage"].get(k, 0) for c in calls) for k in ("input", "output", "cache_read")}
    return {
        "run": run.name,
        "model_calls": len(calls),
        "classifier_calls": sum(c["role"] == "classifier" for c in calls),
        "remediator_calls": sum(c["role"] == "remediator" for c in calls),
        "input_tokens": usage["input"],
        "cached_input_tokens": usage["cache_read"],
        "output_tokens": usage["output"],
        "used_tokens": report["budget"]["used_tokens"],
        "tool_calls": dict(by_group),
        "tool_calls_by_stage": {f"{g}/{s}": n for (g, s), n in sorted(by_stage.items())},
        "failed_results": dict(refusals),
        "label_1": sum(r["label"] == 1 for r in rows),
        "agree_with_key": correct,
        "remediation": dict(collections.Counter(r["remediation"]["status"] for r in rows)),
        "labels": {Path(r["path"]).stem + "/" + r["test_id"]: r["label"] for r in rows},
        "wall_s": round(events[-1]["ts"] - events[0]["ts"]),
    }


def main() -> None:
    runs = [Path(p) for p in sys.argv[1:]]
    key = load_key(DEFAULT_KEY) if DEFAULT_KEY.is_file() else {}
    summaries = [summarize(run, key) for run in runs]
    for s in summaries:
        print(json.dumps({k: v for k, v in s.items() if k != "labels"}, indent=1))
    if len(summaries) == 2:
        a, b = summaries
        differ = [k for k in a["labels"] if a["labels"][k] != b["labels"].get(k)]
        print(f"labels that differ between {a['run']} and {b['run']}: {differ}")


if __name__ == "__main__":
    main()
