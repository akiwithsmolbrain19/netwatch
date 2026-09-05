"""JSON + HTML + console reporting (stdlib only)."""
from __future__ import annotations
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding

SEV_COLOR = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#15803d"}


def to_dict(findings: list[Finding], groups: list[dict], meta: dict) -> dict:
    return {"meta": meta, "summary": {"total": len(findings),
            "by_severity": {s: sum(1 for f in findings if f.severity == s)
                            for s in ("critical", "high", "medium", "low")},
            "by_rule": {r: sum(1 for f in findings if f.rule_id == r) for r in sorted({f.rule_id for f in findings})}},
            "groups": groups,
            "findings": [f.__dict__ for f in findings]}


def write_json(findings: list[Finding], groups: list[dict], meta: dict, path: str) -> None:
    Path(path).write_text(json.dumps(to_dict(findings, groups, meta), indent=2))


def _ts(v: float) -> str:
    if not v:
        return "n/a"
    return datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def write_html(findings: list[Finding], groups: list[dict], meta: dict, path: str) -> None:
    e = html.escape
    rows = []
    for f in findings:
        c = SEV_COLOR.get(f.severity, "#333")
        rows.append(f"<tr><td><span style='background:{c};color:#fff;padding:2px 8px;border-radius:8px'>{e(f.severity)}</span></td>"
                    f"<td><b>{e(f.rule_id)}</b><br>{e(f.name)}</td><td>{e(f.src)} &rarr; {e(f.dst or '-')}</td>"
                    f"<td>{e(f.proto or '-')}</td><td>{e(str(f.ports))}</td><td>{e(f.evidence)}</td>"
                    f"<td>{_ts(f.first_seen)}<br>{_ts(f.last_seen)}</td><td>{e(f.rationale)}<br><i>Validate: {e(f.validation)}</i><br>MITRE: {e(', '.join(f.mitre))}</td></tr>")
    header = ("<h1>NetWatch investigation report</h1>"
            f"<p>Source: {e(str(meta.get('pcap','')))} &middot; packets: {e(str(meta.get('packets',0)))} &middot; generated: {e(str(meta.get('generated','')))}</p>"
            f"<p><b>Heuristic findings are investigative leads, not proof of compromise.</b></p>"
            "<h2>Correlated hosts</h2><ul>" +
            "".join(f"<li><b>{e(g['src'])}</b> — {g['finding_count']} findings, rules {e(str(g['rules']))}, max {e(g['max_severity'])}, score {g['total_score']}. {e(g['note'])}</li>" for g in groups) +
            "</ul>")
    if rows:
        body = (header + "<h2>Findings</h2><table border='1' cellpadding='6' cellspacing='0'>"
                "<tr><th>Severity</th><th>Rule</th><th>Src&rarr;Dst</th><th>Proto</th><th>Ports</th><th>Evidence</th><th>Range (UTC)</th><th>Explanation</th></tr>"
                + "".join(rows) + "</table>")
    else:
        body = header + "<p>No findings. Traffic did not cross any detection thresholds.</p>"
    Path(path).write_text(f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>NetWatch report</title>"
                          f"<style>body{{font-family:sans-serif;margin:2em}}table{{border-collapse:collapse;font-size:13px}}td,th{{vertical-align:top}}</style></head>"
                          f"<body>{body}</body></html>")


def console(findings: list[Finding], groups: list[dict], verbose: bool = False) -> str:
    if not findings:
        return "No findings. Traffic did not cross any detection thresholds."
    lines = [f"{len(findings)} finding(s):"]
    for f in findings:
        lines.append(f"[{f.severity.upper():8}] {f.rule_id} {f.name} | {f.src} -> {f.dst or '-'} | {f.evidence}")
        if verbose:
            lines.append(f"           rationale: {f.rationale}")
            lines.append(f"           validate : {f.validation}")
    lines.append("")
    lines.append("Correlated hosts (priority order):")
    for g in groups:
        lines.append(f"  {g['src']}: {g['finding_count']} findings {g['rules']} max={g['max_severity']} score={g['total_score']}")
    return "\n".join(lines)
