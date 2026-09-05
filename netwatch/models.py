"""Shared data models."""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Packet:
    ts: float
    src: str
    dst: str
    proto: str  # TCP, UDP, ARP, ICMP, DNS, HTTP, ...
    sport: int | None = None
    dport: int | None = None
    flags: str = ""
    length: int = 0
    dns_query: str = ""
    dns_rcode: int = 0
    http_method: str = ""
    http_uri: str = ""
    http_ua: str = ""
    http_status: int | None = None
    info: str = ""


@dataclass
class Finding:
    rule_id: str
    name: str
    description: str
    severity: str  # low, medium, high, critical
    src: str = ""
    dst: str = ""
    proto: str = ""
    ports: list[int] = field(default_factory=list)
    evidence: str = ""
    rationale: str = ""
    mitre: list[str] = field(default_factory=list)
    count: int = 1
    first_seen: float = 0.0
    last_seen: float = 0.0
    validation: str = ""
    status: str = "open"
    score: float = 0.0
