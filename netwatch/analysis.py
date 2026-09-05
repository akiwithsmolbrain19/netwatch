"""Severity scoring + correlation."""
from __future__ import annotations
from collections import defaultdict

from .models import Finding

WEIGHTS = {"low": 1.0, "medium": 2.5, "high": 5.0, "critical": 10.0}


def score(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        f.score = round(WEIGHTS.get(f.severity, 1.0) * (1.0 + min(f.count, 100) / 50.0), 2)
    return sorted(findings, key=lambda x: (-x.score, x.rule_id))


def correlate(findings: list[Finding]) -> list[dict]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.src or "unknown"].append(f)
    out = []
    for src, fs in groups.items():
        rules = sorted({x.rule_id for x in fs})
        out.append({"src": src, "finding_count": len(fs), "rules": rules,
                    "max_severity": max((x.severity for x in fs),
                                        key=lambda s: WEIGHTS.get(s, 0)),
                    "total_score": round(sum(x.score for x in fs), 2),
                    "note": "Multiple independent rules fired for one source; prioritize this host."
                            if len(rules) > 1 else "Single rule fired."})
    return sorted(out, key=lambda g: -g["total_score"])
