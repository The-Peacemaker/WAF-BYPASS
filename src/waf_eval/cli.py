from __future__ import annotations

import argparse
import logging
from pathlib import Path

import requests

from .generator import SafePatternGenerator
from .reporting import AnalysisEngine, ReportWriter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Defensive WAF/XSS filter validation framework")
    parser.add_argument("--mode", choices=["exhaustive", "fuzz"], default="fuzz")
    parser.add_argument("--count", type=int, default=250, help="Number of safe patterns to generate")
    parser.add_argument("--target", default="http://127.0.0.1:5000/submit", help="Target lab endpoint")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--output", default="reports/results.json")
    parser.add_argument("--csv", default="reports/results.csv")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def evaluate_target(target: str, payloads: list[str], timeout: float) -> tuple[list[bool], list[str]]:
    blocked: list[bool] = []
    reasons: list[str] = []

    for payload in payloads:
        try:
            response = requests.post(target, json={"input": payload}, timeout=timeout)
            data = response.json()
            blocked.append(bool(data.get("blocked", False)))
            reasons.append(str(data.get("reason", "none")))
        except Exception as exc:  # noqa: BLE001
            blocked.append(False)
            reasons.append(f"error:{exc}")
    return blocked, reasons


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    generator = SafePatternGenerator(seed=args.seed)
    if args.mode == "exhaustive":
        generated = generator.generate_exhaustive(limit=args.count)
    else:
        generated = generator.generate_fuzzed(count=args.count)

    payloads = [item.encoded for item in generated]
    logging.info("Generated %s safe patterns", len(payloads))

    blocked_flags, reasons = evaluate_target(args.target, payloads, args.timeout)

    rows = ReportWriter.as_rows(generated, blocked_flags, reasons)
    analysis = AnalysisEngine()
    summary = analysis.score_run(rows)
    recommendations = analysis.recommendations(rows)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ReportWriter.write_json(output_path, summary, rows, recommendations)

    csv_path = Path(args.csv)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    ReportWriter.write_csv(csv_path, rows)

    logging.info("Summary: %s", summary)
    for recommendation in recommendations:
        logging.info("Recommendation: %s", recommendation)
    logging.info("Wrote JSON report to %s", output_path)
    logging.info("Wrote CSV report to %s", csv_path)


if __name__ == "__main__":
    main()
