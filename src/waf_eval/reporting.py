from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from .generator import GeneratedPattern
from .patterns import CATEGORY_RULES, PATTERN_CATEGORIES


class AnalysisEngine:
    def __init__(self) -> None:
        self.category_rules = CATEGORY_RULES
        self.weights = PATTERN_CATEGORIES

    def categorize(self, value: str) -> str:
        upper = value.upper()
        for category, markers in self.category_rules.items():
            if any(marker.upper() in upper for marker in markers):
                return category
        return "marker"

    def score_run(self, evaluations: list[dict]) -> dict:
        if not evaluations:
            return {
                "total": 0,
                "blocked": 0,
                "allowed": 0,
                "block_rate": 0.0,
                "weighted_exposure": 0.0,
                "strength_score": 0.0,
            }

        total = len(evaluations)
        blocked = sum(1 for row in evaluations if row["blocked"])
        allowed = total - blocked
        block_rate = blocked / total

        weighted_exposure = 0.0
        total_weight = 0.0
        for row in evaluations:
            category = self.categorize(row["encoded"])
            weight = self.weights.get(category, 1)
            total_weight += weight
            if not row["blocked"]:
                weighted_exposure += weight

        normalized_exposure = weighted_exposure / total_weight if total_weight else 0.0
        strength_score = max(0.0, min(100.0, (1.0 - normalized_exposure) * 100.0))

        return {
            "total": total,
            "blocked": blocked,
            "allowed": allowed,
            "block_rate": round(block_rate, 4),
            "weighted_exposure": round(normalized_exposure, 4),
            "strength_score": round(strength_score, 2),
        }

    def recommendations(self, evaluations: list[dict]) -> list[str]:
        recs: list[str] = []
        allowed_count = 0
        category_failures: dict[str, int] = {}
        for row in evaluations:
            if row["blocked"]:
                continue
            allowed_count += 1
            category = self.categorize(row["encoded"])
            category_failures[category] = category_failures.get(category, 0) + 1

        if category_failures.get("dom_context", 0) > 0:
            recs.append("Add contextual output encoding for JavaScript and DOM sinks.")
        if category_failures.get("attribute_context", 0) > 0:
            recs.append("Enforce strict allowlists for HTML attributes and quote handling.")
        if category_failures.get("tag_context", 0) > 0:
            recs.append("Normalize inputs before inspection and block suspicious tag-like markers.")
        if category_failures.get("polyglot_like", 0) > 0:
            recs.append("Apply multi-stage decoding before WAF signatures and add anomaly scoring.")
        if allowed_count > 0:
            recs.append("Some safe test probes were allowed; add canonicalization depth, stronger context-aware rules, and output encoding checks.")
        if not recs:
            recs.append("Current regex layer blocked all generated safe probes; validate against broader context-specific test corpus.")
        return recs


class ReportWriter:
    @staticmethod
    def as_rows(patterns: list[GeneratedPattern], blocked_flags: list[bool], reasons: list[str]) -> list[dict]:
        rows: list[dict] = []
        for pattern, blocked, reason in zip(patterns, blocked_flags, reasons):
            row = asdict(pattern)
            row["blocked"] = blocked
            row["reason"] = reason
            rows.append(row)
        return rows

    @staticmethod
    def write_json(path: Path, summary: dict, rows: list[dict], recommendations: list[str]) -> None:
        payload = {
            "summary": summary,
            "recommendations": recommendations,
            "results": rows,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @staticmethod
    def write_csv(path: Path, rows: list[dict]) -> None:
        if not rows:
            path.write_text("", encoding="utf-8")
            return
        with path.open("w", newline="", encoding="utf-8") as fp:
            writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
