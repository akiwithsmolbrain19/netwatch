"""Modular detection rules. Each rule: id, name, severity, MITRE mapping, FP notes."""
from __future__ import annotations
import math
from collections import Counter

from .features import SrcFeatures, cv_of_intervals, window_counts
from .models import Finding

VALIDATION_COMMON = "Pivot to full packet timeline, check asset role, compare to baseline, confirm with endpoint/proxy logs before escalating."

REGISTRY: dict[str, dict] = {}


def rule(rule_id: str, name: str, desc: str, severity: str, mitre: list[str], fp: str, validation: str):
    def deco(fn):
        REGISTRY[rule_id] = {"id": rule_id, "name": name, "desc": desc,
                             "severity": severity, "mitre": mitre, "fp": fp,
                             "validation": validation, "fn": fn}
        fn.meta = REGISTRY[rule_id]
        return fn
    return deco


def _span(ts: list[float]) -> tuple[float, float]:
    return (min(ts), max(ts)) if ts else (0.0, 0.0)


@rule("NW-101", "Possible port scan", "One source touches many distinct destination ports in a short window.",
      "high", ["T1046"], "Vulnerability scanners, asset inventory, and monitoring can look identical.",
      "Confirm SYN-without-full-handshake ratio in Wireshark; check whether source is an approved scanner.")
def detect_port_scan(src: str, f: SrcFeatures, cfg: dict) -> Finding | None:
    w, need = cfg["port_scan_window_s"], cfg["port_scan_min_ports"]
    times = sorted(f.port_times)
    best: set[int] = set()
    best_ts: list[float] = []
    j = 0
    for i in range(len(times)):
        while times[i][0] - times[j][0] > w:
            j += 1
        ports = {p for _, p in times[j:i + 1]}
        if len(ports) > len(best):
            best = ports
            best_ts = [t for t, _ in times[j:i + 1]]
    if len(best) >= need:
        a, b = _span(best_ts)
        return Finding("NW-101", "Possible port scan",
                       f"{src} probed {len(best)} distinct ports within {w:g}s",
                       "high", src=src, ports=sorted(best)[:50],
                       evidence=f"{len(best)} unique dports in {w:g}s window",
                       rationale="High distinct-port fan-out from a single source is the classic scan heuristic.",
                       mitre=["T1046"], count=len(best), first_seen=a, last_seen=b,
                       validation=REGISTRY["NW-101"]["validation"])
    return None


@rule("NW-102", "Possible host discovery sweep", "One source contacts many distinct hosts quickly.",
      "medium", ["T1046"], "Monitoring systems, DHCP churn, and CDN fan-out cause false positives.",
      "Check ARP/ICMP ratio and whether destinations belong to the local subnet.")
def detect_host_discovery(src: str, f: SrcFeatures, cfg: dict) -> Finding | None:
    w, need = cfg["host_discovery_window_s"], cfg["host_discovery_min_hosts"]
    times = sorted(f.dst_times)
    best: set[str] = set()
    best_ts: list[float] = []
    j = 0
    for i in range(len(times)):
        while times[i][0] - times[j][0] > w:
            j += 1
        hosts = {h for _, h in times[j:i + 1]}
        if len(hosts) > len(best):
            best = hosts
            best_ts = [t for t, _ in times[j:i + 1]]
    if len(best) >= need:
        a, b = _span(best_ts)
        return Finding("NW-102", "Possible host discovery sweep",
                       f"{src} contacted {len(best)} distinct hosts within {w:g}s",
                       "medium", src=src, evidence=f"{len(best)} unique dsts in {w:g}s",
                       rationale="Fast fan-out across hosts suggests ping/ARP sweep.",
                       mitre=["T1046"], count=len(best), first_seen=a, last_seen=b,
                       validation=REGISTRY["NW-102"]["validation"])
    return None


@rule("NW-103", "Suspicious repeated connections", "Many repeated connections from one source to one dst:port.",
      "medium", ["T1110"], "Retries, misconfigured clients, and polling APIs repeat connections legitimately.",
      "Check TCP handshake completion and application errors; look for auth failures.")
def detect_repeated(src: str, f: SrcFeatures, cfg: dict) -> Finding | None:
    w, need = cfg["repeat_window_s"], cfg["repeat_min_attempts"]
    hits = []
    for (dst, dport), ts in f.pair_times.items():
        n = window_counts(ts, w)
        if n >= need:
            hits.append(((dst, dport), n, ts))
    if not hits:
        return None
    hits.sort(key=lambda h: -h[1])
    (dst, dport), n, ts = hits[0]
    a, b = _span(ts)
    extra = f" (+{len(hits) - 1} more targeted service(s))" if len(hits) > 1 else ""
    return Finding("NW-103", "Suspicious repeated connections",
                   f"{src} -> {dst}:{dport} {n} attempts in {w:g}s window{extra}",
                   "medium", src=src, dst=dst or "", ports=[dport] if dport else [],
                   evidence=f"{n} connections to {dst}:{dport} within {w:g}s{extra}",
                   rationale="Sustained repetition against one service resembles brute-force or aggressive retry; without application-log auth failures this alone is not evidence of brute force.",
                   mitre=["T1110"], count=n, first_seen=a, last_seen=b,
                   validation=REGISTRY["NW-103"]["validation"])


def _entropy(s: str) -> float:
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values()) if n else 0.0


@rule("NW-104", "Suspicious DNS behavior", "Excessive NXDOMAINs, many unique queries, or high-entropy (tunnel-like) names.",
      "medium", ["T1071.004", "T1048"], "Security products, DNS prefetch, and captive portals are noisy.",
      "Inspect query names, response codes, query volume per endpoint host, and resolver logs.")
def detect_dns(src: str, f: SrcFeatures, cfg: dict) -> Finding | None:
    if not f.dns_queries:
        return None
    w = cfg["dns_window_s"]
    # Sliding window: counts must co-occur inside dns_window_s, not across the whole capture.
    ordered = sorted(f.dns_queries)
    best: list[tuple[float, str, int]] = []
    j = 0
    for i in range(len(ordered)):
        while ordered[i][0] - ordered[j][0] > w:
            j += 1
        if (i - j + 1) > len(best):
            best = ordered[j:i + 1]
    nx = sum(1 for _, _, rc in best if rc == 3)
    uniq = len({q for _, q, _ in best})
    long_hi = [q for _, q, _ in best if len(q) > 40 and _entropy(q) > 3.8]
    trig = nx >= cfg["dns_nxdomain_min"] or uniq >= cfg["dns_query_min_unique"] or len(long_hi) >= 3
    if trig:
        a, b = _span([t for t, _, _ in best])
        rcode_note = (" NOTE: rcode is only present on DNS responses; "
                      "query-only captures cannot show NXDOMAIN." if nx == 0 else "")
        return Finding("NW-104", "Suspicious DNS behavior",
                       f"{src}: {nx} NXDOMAIN, {uniq} unique queries, {len(long_hi)} long high-entropy names (in {w:g}s window)",
                       "medium", src=src, proto="DNS",
                       evidence=f"nxdomain={nx} unique={uniq} tunnel_like={len(long_hi)} e.g. {long_hi[:3]}.{rcode_note}",
                       rationale="DGA/tunneling heuristics: NXDOMAIN bursts and high-entropy long names.",
                       mitre=["T1071.004", "T1048"], count=len(best),
                       first_seen=a, last_seen=b, validation=REGISTRY["NW-104"]["validation"])
    return None


@rule("NW-105", "Possible HTTP reconnaissance", "HTTP requests to suspicious/admin/scanner paths.",
      "medium", ["T1595.002"], "CMS admin traffic, security scanners you own, and WAF probes trigger this.",
      "Replay the URIs, check response codes, and confirm scanner authorization.")
def detect_http_recon(src: str, f: SrcFeatures, cfg: dict) -> Finding | None:
    pats = [p.lower() for p in cfg["http_recon_suspicious_paths"]]
    hits = [p for p in f.http if any(pat in (p.http_uri or "").lower() or pat in (p.http_ua or "").lower() for pat in pats)]
    if len(hits) >= cfg["http_recon_min_hits"]:
        ts = [p.ts for p in hits]
        a, b = _span(ts)
        uris = sorted({p.http_uri for p in hits})[:10]
        dst = Counter(p.dst for p in hits).most_common(1)[0][0] if hits else ""
        return Finding("NW-105", "Possible HTTP reconnaissance",
                       f"{src} made {len(hits)} suspicious HTTP requests",
                       "medium", src=src, dst=dst, proto="HTTP",
                       evidence=f"URIs: {uris}",
                       rationale="Requests match known scanner/admin brute-force path patterns.",
                       mitre=["T1595.002"], count=len(hits), first_seen=a, last_seen=b,
                       validation=REGISTRY["NW-105"]["validation"])
    return None


@rule("NW-106", "Possible beaconing", "Unusually periodic connections from a source to one destination.",
      "medium", ["T1071"], "Scheduled updaters, mail checks, NTP, and keepalives beacon legitimately; periodicity alone never confirms C2.",
      "Compare interval jitter to known-good agents; check payload sizes, DNS/HTTP context, and the endpoint process before any escalation.")
def detect_beacon(src: str, f: SrcFeatures, cfg: dict) -> Finding | None:
    for (dst, dport), ts in f.pair_times.items():
        if len(ts) >= cfg["beacon_min_events"]:
            cv = cv_of_intervals(ts)
            span = ts[-1] - ts[0]
            if cv is not None and cv <= cfg["beacon_cv_max"] and span >= 60:
                mean_iv = (span / (len(ts) - 1)) if len(ts) > 1 else 0.0
                return Finding("NW-106", "Possible beaconing",
                               f"{src} -> {dst}:{dport} {len(ts)} evenly spaced connections (CV={cv:.2f}, mean interval ~{mean_iv:.0f}s)",
                               "medium", src=src, dst=dst or "", ports=[dport] if dport else [],
                               evidence=f"n={len(ts)} interval_cv={cv:.3f} mean_interval_s={mean_iv:.1f} span={span:.0f}s",
                               rationale=("Low jitter over many intervals resembles automated beaconing, but benign schedulers "
                                          "(updaters, mail checks, keepalives) look identical; this is a triage lead, not evidence of C2."),
                               mitre=["T1071"], count=len(ts), first_seen=ts[0], last_seen=ts[-1],
                               validation=REGISTRY["NW-106"]["validation"])
    return None


@rule("NW-107", "Connection to suspicious port", "Contact with commonly abused destination ports.",
      "low", [], "Admins legitimately use SSH/RDP; context matters.",
      "Verify the asset, service banner, and whether the connection was expected.")
def detect_suspicious_ports(src: str, f: SrcFeatures, cfg: dict) -> Finding | None:
    sus = set(cfg["suspicious_ports"])
    hits = {p: c for p, c in f.ports.items() if p in sus}
    total = sum(hits.values())
    if total >= cfg["suspicious_min_hits"]:
        a, b = _span(f.times)
        return Finding("NW-107", "Connection to suspicious port",
                       f"{src} contacted sensitive ports {sorted(hits)} ({total} conns)",
                       "low", src=src, ports=sorted(hits),
                       evidence=f"sensitive-port hits={total}: {sorted(hits)}",
                       rationale="Ports like 22/23/445/3389 are frequently targeted or abused. Deliberately left without a MITRE mapping: contacting a port is not, by itself, a technique.",
                       mitre=[], count=total, first_seen=a, last_seen=b,
                       validation=REGISTRY["NW-107"]["validation"])
    return None


@rule("NW-108", "Unusual connection frequency", "Burst rate far above background (possible flood/scan burst).",
      "medium", ["T1499"], "Backups, speed tests, and streaming burst legitimately.",
      "Check bytes/packets per flow, direction, and whether a single pair dominates.")
def detect_flood(src: str, f: SrcFeatures, cfg: dict) -> Finding | None:
    w = cfg["flood_window_s"]
    n = window_counts(sorted(f.times), w)
    pps = n / w
    if pps >= cfg["flood_min_pps"] and n >= 10:
        a, b = _span(f.times)
        return Finding("NW-108", "Unusual connection frequency",
                       f"{src} peaked at ~{pps:.1f} pkts/s ({n} in {w:g}s)",
                       "medium", src=src, evidence=f"peak {n} packets in {w:g}s window",
                       rationale="Short-window packet bursts indicate floods or aggressive scanning.",
                       mitre=["T1499"], count=n, first_seen=a, last_seen=b,
                       validation=REGISTRY["NW-108"]["validation"])
    return None


RULE_ORDER = ["NW-101", "NW-102", "NW-103", "NW-104", "NW-105", "NW-106", "NW-107", "NW-108"]


def run_all(feats: dict[str, SrcFeatures], cfg: dict) -> list[Finding]:
    findings: list[Finding] = []
    overrides = cfg.get("severity_overrides", {})
    for src, f in feats.items():
        for rid in RULE_ORDER:
            meta = REGISTRY[rid]
            hit = meta["fn"](src, f, cfg)
            if hit:
                if rid in overrides:
                    hit.severity = overrides[rid]
                findings.append(hit)
    return findings
