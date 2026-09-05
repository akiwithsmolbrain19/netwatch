"""Parse packets via tshark JSON backend (stdlib only)."""
from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path

from .models import Packet

FIELDS = ["frame.time_epoch", "frame.len", "frame.protocols",
          "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
          "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
          "tcp.srcport", "tcp.dstport", "tcp.flags.str",
          "udp.srcport", "udp.dstport",
          "dns.qry.name", "dns.flags.rcode",
          "http.request.method", "http.request.uri",
          "http.user_agent", "http.response.code"]


def _get(layers: dict, key: str) -> str:
    v = layers.get(key, "")
    if isinstance(v, list):
        v = v[0] if v else ""
    return str(v or "")


def tshark_to_packets(tshark_json: list[dict]) -> list[Packet]:
    packets: list[Packet] = []
    for frame in tshark_json:
        layers = frame.get("_source", {}).get("layers", frame.get("layers", {}))
        ts = float(_get(layers, "frame.time_epoch") or 0)
        src = _get(layers, "ip.src") or _get(layers, "ipv6.src") or _get(layers, "arp.src.proto_ipv4")
        dst = _get(layers, "ip.dst") or _get(layers, "ipv6.dst") or _get(layers, "arp.dst.proto_ipv4")
        proto = "OTHER"
        sport = dport = None
        tsrc, tdst = _get(layers, "tcp.srcport"), _get(layers, "tcp.dstport")
        usrc, udst = _get(layers, "udp.srcport"), _get(layers, "udp.dstport")
        flags = _get(layers, "tcp.flags.str")
        dns_q = _get(layers, "dns.qry.name")
        http_method = _get(layers, "http.request.method")
        http_uri = _get(layers, "http.request.uri")
        http_ua = _get(layers, "http.user_agent")
        if tsrc or tdst:
            proto = "TCP"
            sport = int(float(tsrc)) if tsrc else None
            dport = int(float(tdst)) if tdst else None
        elif usrc or udst:
            proto = "UDP"
            sport = int(float(usrc)) if usrc else None
            dport = int(float(udst)) if udst else None
        elif _get(layers, "arp.src.proto_ipv4"):
            proto = "ARP"
        if dns_q:
            proto = "DNS"
        if http_method or http_uri:
            proto = "HTTP"
        if proto == "OTHER":
            protos = _get(layers, "frame.protocols")
            if "icmp" in protos:
                proto = "ICMP"
            elif "arp" in protos:
                proto = "ARP"
        try:
            http_status = int(_get(layers, "http.response.code")) or None
        except ValueError:
            http_status = None
        try:
            dns_rcode = int(_get(layers, "dns.flags.rcode") or 0)
        except ValueError:
            dns_rcode = 0
        try:
            length = int(float(_get(layers, "frame.len") or 0))
        except ValueError:
            length = 0
        packets.append(Packet(ts=ts, src=src, dst=dst, proto=proto, sport=sport,
                              dport=dport, flags=flags, length=length, dns_query=dns_q,
                              dns_rcode=dns_rcode, http_method=http_method, http_uri=http_uri,
                              http_ua=http_ua, http_status=http_status,
                              info=_get(layers, "frame.protocols")))
    packets.sort(key=lambda p: p.ts)
    return packets


def parse_pcap(path: str, timeout_s: int = 120) -> list[Packet]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"PCAP not found: {path}")
    if p.stat().st_size == 0:
        raise ValueError(f"Empty capture: {path}")
    tshark = shutil.which("tshark")
    if not tshark:
        raise RuntimeError("tshark is required but was not found in PATH")
    cmd = [tshark, "-r", str(p), "-T", "json"]
    for f in FIELDS:
        cmd += ["-e", f]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"tshark timed out on {path}") from e
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed on {path}: {proc.stderr.strip()[:500]}")
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Could not parse tshark output for {path}: {e}") from e
    if not data:
        raise ValueError(f"No packets decoded in {path} (empty or unsupported format)")
    pkts = tshark_to_packets(data)
    if not any(x.src or x.dst for x in pkts):
        raise ValueError(f"No packets decoded in {path} (empty or unsupported format)")
    return pkts
