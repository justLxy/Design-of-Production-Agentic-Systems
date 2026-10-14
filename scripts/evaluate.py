"""Score an OWASP report.json against the benchmark's answer key.

For the developers only: the agent never reads the key (it is withheld from its workspace).
Usage: python scripts/evaluate.py <report.json> [<expectedresults.csv>]
"""

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KEY = ROOT / "targets" / "owasp-benchmark-python" / "expectedresults-0.1.csv"


def load_key(path: Path) -> dict[str, tuple[str, bool]]:
    """test name -> (category, real vulnerability)."""
    key = {}
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if row and not row[0].startswith("#"):
                key[row[0].strip()] = (row[1].strip(), row[2].strip() == "true")
    return key


def main() -> None:
    if len(sys.argv) not in (2, 3):
        print(__doc__)
        sys.exit(2)
    report = json.loads(Path(sys.argv[1]).read_text())
    key = load_key(Path(sys.argv[2]) if len(sys.argv) == 3 else DEFAULT_KEY)

    tp = fp = tn = fn = unlabelled = 0
    mistakes = []
    for row in report["alerts"]:
        category, actual = key[Path(row["path"]).stem]
        if row["label"] is None:
            unlabelled += 1
            continue
        predicted = row["label"] == 1
        tp += predicted and actual
        fp += predicted and not actual
        tn += not predicted and not actual
        fn += not predicted and actual
        if predicted != actual:
            mistakes.append((row, category, actual))

    precision = tp / (tp + fp) if tp + fp else float("nan")
    recall = tp / (tp + fn) if tp + fn else float("nan")
    print(f"TP={tp} FP={fp} TN={tn} FN={fn} unlabelled={unlabelled}")
    print(f"precision={precision:.2f} recall={recall:.2f} accuracy={(tp + tn) / max(1, tp + fp + tn + fn):.2f}")
    for row, category, actual in mistakes:
        print(f"\n{row['alert_id']} ({row['test_id']}, case category {category}): "
              f"predicted {row['label']}, key says {int(actual)}")
        print(f"  {row['rationale']}")


if __name__ == "__main__":
    main()