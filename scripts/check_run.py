"""Check a run's trace.jsonl against the invariants.

Usage: python scripts/check_run.py <trace.jsonl> [<report.json>]
"""

import json
import sys
from pathlib import Path

import jsonschema

REPO_ROOT = Path(__file__).resolve().parents[1]
TRACE_SCHEMA = json.loads((REPO_ROOT / "trace.schema.json").read_text())
REPORT_SCHEMA = json.loads((REPO_ROOT / "report.schema.json").read_text())


def load_events(path: Path) -> tuple[list[dict], list[str]]:
    """Invariant 1 (part): the file parses line by line."""
    events, errors = [], []
    for i, line in enumerate(path.read_text().splitlines(), 1):
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            errors.append(f"line {i}: not valid JSON: {e}")
    return events, errors


def check_trace(events: list[dict]) -> list[str]:
    errors = []

    # Invariant 1: every line validates against trace.schema.json.
    for i, event in enumerate(events, 1):
        try:
            jsonschema.validate(event, TRACE_SCHEMA)
        except jsonschema.ValidationError as e:
            errors.append(f"line {i}: schema: {e.message}")

    # Invariant 2: step starts at 1 and increases by exactly 1.
    for i, event in enumerate(events, 1):
        if event.get("step") != i:
            errors.append(f"line {i}: step is {event.get('step')}, expected {i}")
            break

    # Invariant 3: exactly one terminal event, and it is the last line.
    terminals = [i for i, e in enumerate(events, 1) if e.get("kind") == "terminal"]
    if len(terminals) != 1:
        errors.append(f"expected exactly 1 terminal event, found {len(terminals)}")
    elif terminals[0] != len(events):
        errors.append(f"terminal event is on line {terminals[0]}, not the last line")

    # Invariant 4 (trace side): usage_total equals the per-counter sum over model_call events.
    sums: dict[str, int] = {}
    for event in events:
        if event.get("kind") == "model_call":
            for key, value in event.get("usage", {}).items():
                sums[key] = sums.get(key, 0) + value
    if terminals:
        total = events[terminals[0] - 1].get("usage_total", {})
        for key in sorted(set(sums) | set(total)):
            if total.get(key, 0) != sums.get(key, 0):
                errors.append(f"usage_total.{key} is {total.get(key, 0)}, "
                              f"sum over model_call is {sums.get(key, 0)}")

    # Invariant 6: every tool_request is immediately followed by its tool_result.
    for i, event in enumerate(events, 1):
        if event.get("kind") == "tool_request":
            nxt = events[i] if i < len(events) else {}
            if nxt.get("kind") != "tool_result" or nxt.get("tool") != event.get("tool"):
                errors.append(f"line {i}: tool_request is not immediately followed by its tool_result")

    return errors


def check_report(report: dict, events: list[dict]) -> list[str]:
    errors = []

    try:
        jsonschema.validate(report, REPORT_SCHEMA)
    except jsonschema.ValidationError as e:
        errors.append(f"report schema: {e.message}")

    alerts = report.get("alerts", [])
    alert_count = report.get("scan", {}).get("alert_count")
    if len(alerts) != alert_count:
        errors.append(f"report has {len(alerts)} rows, scan.alert_count is {alert_count}")

    keys = [(a.get("path", ""), a.get("line", 0), a.get("test_id", "")) for a in alerts]
    if keys != sorted(keys):
        errors.append("rows are not ordered by path, then line, then test_id")

    # Invariant 4 (report side): used_tokens is exactly the sum of input + output.
    charged = sum(e["usage"]["input"] + e["usage"]["output"]
                  for e in events if e.get("kind") == "model_call")
    used = report.get("budget", {}).get("used_tokens")
    if used != charged:
        errors.append(f"budget.used_tokens is {used}, sum of input + output is {charged}")

    # Invariant 5: each row has exactly one settling state_change that matches it.
    settles: dict[str, list[dict]] = {}
    for event in events:
        if event.get("kind") == "state_change" and "alert_status" in event:
            settles.setdefault(event["alert_id"], []).append(event)
    for alert in alerts:
        found = settles.get(alert.get("alert_id"), [])
        if len(found) != 1:
            errors.append(f"{alert.get('alert_id')}: {len(found)} settling state_change events, expected 1")
        elif (found[0]["alert_status"], found[0]["label"]) != (alert.get("status"), alert.get("label")):
            errors.append(f"{alert.get('alert_id')}: state_change says "
                          f"({found[0]['alert_status']}, {found[0]['label']}), "
                          f"row says ({alert.get('status')}, {alert.get('label')})")

    return errors


def main() -> None:
    if len(sys.argv) not in (2, 3):
        print(__doc__)
        sys.exit(2)

    events, errors = load_events(Path(sys.argv[1]))
    errors += check_trace(events)
    summary = f"{len(events)} events"

    if len(sys.argv) == 3:
        report = json.loads(Path(sys.argv[2]).read_text())
        errors += check_report(report, events)
        summary += f", {len(report.get('alerts', []))} rows"

    if errors:
        print(f"FAIL ({summary})")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)
    print(f"OK ({summary})")


if __name__ == "__main__":
    main()