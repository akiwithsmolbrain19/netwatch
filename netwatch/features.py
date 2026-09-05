"""Normalization + feature extraction."""
from __future__ import annotations
from collections import defaultdict
from statistics import mean, stdev

from .models import Packet


def normalize(packets: list[Packet]) -> list[Packet]:
    for p in packets:
        p.dns_query = p.dns_query.strip().lower().rstrip(".")
        p.http_uri = p.http_uri.strip()
        p.proto = p.proto.upper()
    return packets


class SrcFeatures:
    def __init__(self) -> None:
        self.ports: dict[int, int] = defaultdict(int)
        self.port_times: list[tuple[float, int]] = []
        self.dsts: dict[str, int] = defaultdict(int)
        self.dst_times: list[tuple[float, str]] = []
        self.pair_times: dict[tuple[str, int | None], list[float]] = defaultdict(list)
        self.dns_queries: list[tuple[float, str, int]] = []
        self.http: list[Packet] = []
        self.times: list[float] = []


def extract(packets: list[Packet]) -> dict[str, SrcFeatures]:
    feats: dict[str, SrcFeatures] = defaultdict(SrcFeatures)
    for p in packets:
        if not p.src:
            continue
        f = feats[p.src]
        f.times.append(p.ts)
        if p.dport is not None and p.proto in ("TCP", "UDP"):
            f.ports[p.dport] += 1
            f.port_times.append((p.ts, p.dport))
        if p.dst:
            f.dsts[p.dst] += 1
            f.dst_times.append((p.ts, p.dst))
            f.pair_times[(p.dst, p.dport)].append(p.ts)
        if p.proto == "DNS" and p.dns_query:
            f.dns_queries.append((p.ts, p.dns_query, p.dns_rcode))
        if p.proto == "HTTP":
            f.http.append(p)
    for f in feats.values():
        f.times.sort()
        for v in f.pair_times.values():
            v.sort()
    return feats


def cv_of_intervals(times: list[float]) -> float | None:
    if len(times) < 3:
        return None
    iv = [b - a for a, b in zip(times, times[1:]) if b - a >= 0]
    if len(iv) < 2 or mean(iv) == 0:
        return None
    try:
        return stdev(iv) / mean(iv)
    except Exception:
        return None


def window_counts(times: list[float], window: float) -> int:
    """Max events in any sliding window of `window` seconds."""
    best = 0
    j = 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        best = max(best, i - j + 1)
    return best
