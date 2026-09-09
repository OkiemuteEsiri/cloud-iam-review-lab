from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import analyze
from .io import load_inventory
from .reporting import to_markdown


def main() -> None:
    parser = argparse.ArgumentParser(description="Review synthetic cloud IAM inventory for risky privilege patterns.")
    parser.add_argument("inventory", help="Path to JSON inventory")
    parser.add_argument("--output", default="iam-review.md", help="Markdown report path")
    args = parser.parse_args()

    principals, grants = load_inventory(args.inventory)
    findings = analyze(principals, grants)
    report = to_markdown(findings)
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"Wrote {len(findings)} findings to {args.output}")


if __name__ == "__main__":
    main()
