"""NetWatch test suite: parser, rules +/-, thresholds, correlation, reports, CLI, config."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netwatch.analysis import correlate, score
from netwatch.config import DEFAULTS, load_config
from netwatch.features import extract, normalize
from netwatch.models import Packet
from netwatch.parser import parse_pcap, tshark_to_packets
from netwatch.report import console, to_dict, write_html, write_json
from netwatch.rules import REGISTRY, run_all
from netwatch import store

T = 1700000000.0


def P(src, dst="192.0.2.10", proto="TCP", dport=None, ts=0.0, **kw):
    return Packet(ts=T + ts, src=src, dst=dst, proto=proto, dport=dport, **kw)


def cfg(**over):
    c = dict(DEFAULTS)
    c.update(over)
    return c


def feats(pkts):
    return extract(normalize(pkts))


# ---- parser ----
def test_parse_scan_pcap():
    pkts = parse_pcap("sample_data/scan.pcap")
    assert len(pkts) == 25 and pkts[0].src == "198.51.100.7"


def test_parse_missing_file():
    try:
        parse_pcap("nope.pcap")
        assert False
    except FileNotFoundError:
        pass


def test_parse_empty_file(tmp_path):
    f = tmp_path / "e.pcap"
    f.write_bytes(b"")
    try:
        parse_pcap(str(f))
        assert False
    except ValueError:
        pass


def test_tshark_json_shape():
    data = [{"_source": {"layers": {"frame.time_epoch": ["1"], "ip.src": ["1.1.1.1"],
                                    "ip.dst": ["2.2.2.2"], "tcp.srcport": ["5"],
                                    "tcp.dstport": ["80"], "frame.protocols": ["eth:ip:tcp"]}}}]
    out = tshark_to_packets(data)
    assert out[0].src == "1.1.1.1" and out[0].proto == "TCP" and out[0].dport == 80


def test_normalize_lowercases_dns():
    p = Packet(ts=T, src="a", dst="b", proto="DNS", dns_query="EVIL.Example.COM.")
    normalize([p])
    assert p.dns_query == "evil.example.com"


# ---- NW-101 ----
def test_port_scan_positive():
    pkts = [P("10.0.0.5", dport=1000 + i, ts=i * 0.5) for i in range(15)]
    f = run_all(feats(pkts), cfg())
    assert any(x.rule_id == "NW-101" for x in f)


def test_port_scan_negative_benign():
    pkts = [P("10.0.0.6", dport=80, ts=i * 5) for i in range(3)]
    f = run_all(feats(pkts), cfg())
    assert not any(x.rule_id == "NW-101" for x in f)


def test_port_scan_threshold_boundary():
    just_below = [P("10.0.0.7", dport=1000 + i, ts=i) for i in range(9)]
    at = [P("10.0.0.8", dport=1000 + i, ts=i) for i in range(10)]
    assert not any(x.rule_id == "NW-101" for x in run_all(feats(just_below), cfg()))
    assert any(x.rule_id == "NW-101" for x in run_all(feats(at), cfg()))


# ---- NW-102 / NW-103 ----
def test_host_discovery_positive():
    pkts = [P("10.0.0.9", dst=f"192.0.2.{i}", dport=80, ts=i) for i in range(1, 12)]
    assert any(x.rule_id == "NW-102" for x in run_all(feats(pkts), cfg()))


def test_repeated_positive_and_negative():
    many = [P("10.0.0.11", dport=22, ts=i * 2) for i in range(16)]
    few = [P("10.0.0.12", dport=22, ts=i * 30) for i in range(3)]
    assert any(x.rule_id == "NW-103" for x in run_all(feats(many), cfg()))
    assert not any(x.rule_id == "NW-103" for x in run_all(feats(few), cfg()))


# ---- NW-104 ----
def test_dns_positive_unique_volume():
    pkts = [P("10.0.0.13", dst="192.0.2.53", proto="DNS", dport=53, ts=i * 3,
              dns_query=f"host{i}.example.com") for i in range(25)]
    assert any(x.rule_id == "NW-104" for x in run_all(feats(pkts), cfg()))


def test_dns_negative_benign():
    pkts = [P("10.0.0.14", dst="192.0.2.53", proto="DNS", dport=53, ts=i * 10,
              dns_query="example.com") for i in range(2)]
    assert not any(x.rule_id == "NW-104" for x in run_all(feats(pkts), cfg()))


# ---- NW-105 ----
def test_http_recon_positive():
    pkts = [P("10.0.0.15", proto="HTTP", dport=80, ts=i * 2, http_uri=u,
              http_ua="x") for i, u in
            enumerate(["/admin", "/wp-login.php", "/.git/config", "/phpmyadmin"])]
    assert any(x.rule_id == "NW-105" for x in run_all(feats(pkts), cfg()))


def test_http_recon_negative():
    pkts = [P("10.0.0.16", proto="HTTP", dport=80, ts=i * 5, http_uri="/index.html",
              http_ua="Mozilla/5.0") for i in range(4)]
    assert not any(x.rule_id == "NW-105" for x in run_all(feats(pkts), cfg()))


# ---- NW-106 / NW-107 / NW-108 ----
def test_beacon_positive_and_jitter_negative():
    even = [P("10.0.0.17", dport=443, ts=i * 30) for i in range(8)]
    jitter = [P("10.0.0.18", dport=443, ts=t) for t in [0, 5, 60, 63, 200, 205, 400, 409]]
    assert any(x.rule_id == "NW-106" for x in run_all(feats(even), cfg()))
    assert not any(x.rule_id == "NW-106" for x in run_all(feats(jitter), cfg()))


def test_suspicious_port_positive_and_negative():
    bad = [P("10.0.0.19", dport=445, ts=i * 5) for i in range(5)]
    good = [P("10.0.0.20", dport=443, ts=i * 5) for i in range(5)]
    assert any(x.rule_id == "NW-107" for x in run_all(feats(bad), cfg()))
    assert not any(x.rule_id == "NW-107" for x in run_all(feats(good), cfg()))


def test_flood_positive():
    pkts = [P("10.0.0.21", dport=80, ts=i * 0.01) for i in range(250)]
    assert any(x.rule_id == "NW-108" for x in run_all(feats(pkts), cfg()))


def test_all_rules_have_validation():
    for rid, m in REGISTRY.items():
        assert m["validation"], rid
    # NW-107 deliberately carries no MITRE mapping: contacting a port is not a technique.
    assert REGISTRY["NW-107"]["mitre"] == []
    for rid, m in REGISTRY.items():
        if rid != "NW-107":
            assert m["mitre"], rid


# ---- scoring / correlation ----
def test_scoring_orders_by_severity():
    f = run_all(feats([P("10.0.0.30", dport=1000 + i, ts=i * 0.2) for i in range(15)]), cfg())
    s = score(f)
    assert s[0].score >= s[-1].score


def test_correlate_multi_rule_host():
    pkts = [P("10.0.0.31", dport=1000 + i, ts=i * 0.2) for i in range(15)]
    pkts += [P("10.0.0.31", dst="192.0.2.53", proto="DNS", dport=53, ts=i,
               dns_query=f"h{i}.x.invalid") for i in range(25)]
    groups = correlate(score(run_all(feats(pkts), cfg())))
    g = [x for x in groups if x["src"] == "10.0.0.31"][0]
    assert len(g["rules"]) > 1 and "prioritize" in g["note"].lower() or "multiple" in g["note"].lower()


# ---- reports / store ----
def test_reports_write(tmp_path):
    f = run_all(feats([P("10.0.0.40", dport=1000 + i, ts=i * 0.2) for i in range(12)]), cfg())
    f = score(f)
    g = correlate(f)
    jp, hp = str(tmp_path / "r.json"), str(tmp_path / "r.html")
    write_json(f, g, {"pcap": "x"}, jp)
    write_html(f, g, {"pcap": "x"}, hp)
    assert json.loads(Path(jp).read_text())["summary"]["total"] == len(f)
    assert "NetWatch" in Path(hp).read_text()
    assert "NW-101" in console(f, g)


def test_store_workflow(tmp_path):
    db = str(tmp_path / "t.db")
    con = store.connect(db)
    f = score(run_all(feats([P("10.0.0.50", dport=1000 + i, ts=i * 0.2) for i in range(12)]), cfg()))
    assert store.save(con, f) == len(f)
    rows = store.list_findings(con)
    assert rows
    fid = rows[0][0]
    store.set_status(con, fid, "false_positive", "lab test")
    assert store.get(con, fid)[15] == "false_positive"
    try:
        store.set_status(con, fid, "bogus")
        assert False
    except ValueError:
        pass
    con.close()


# ---- config / CLI ----
def test_config_defaults_and_bad_key(tmp_path):
    assert load_config(None)["port_scan_min_ports"] == 10
    bad = tmp_path / "c.json"
    bad.write_text('{"nope": 1}')
    try:
        load_config(str(bad))
        assert False
    except ValueError:
        pass


def test_config_missing_file():
    try:
        load_config("missing.json")
        assert False
    except FileNotFoundError:
        pass


def test_cli_error_paths(capsys=None):
    from netwatch.cli import main
    assert main(["analyze", "--pcap", "missing.pcap"]) == 2
    import tempfile, os
    fd, p = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    assert main(["analyze", "--pcap", p]) == 3
    os.unlink(p)


def test_scan_window_timestamps_cover_burst():
    # Burst at start, noise at end: reported span must cover the burst, not trailing noise.
    pkts = [P("10.0.0.60", dport=1000 + i, ts=i * 0.2) for i in range(12)]
    pkts += [P("10.0.0.60", dport=80, ts=500 + i * 100) for i in range(3)]
    f = [x for x in run_all(feats(pkts), cfg()) if x.rule_id == "NW-101"][0]
    assert f.first_seen <= T + 2.5 and f.last_seen <= T + 60


def test_repeated_reports_one_finding_naming_others():
    pkts = [P("10.0.0.61", dst="192.0.2.11", dport=22, ts=i * 2) for i in range(16)]
    pkts += [P("10.0.0.61", dst="192.0.2.12", dport=3389, ts=i * 2) for i in range(16)]
    f = [x for x in run_all(feats(pkts), cfg()) if x.rule_id == "NW-103"]
    assert len(f) == 1 and "more targeted service" in f[0].evidence


def test_dns_window_config_respected():
    # 25 unique queries spread over 240s: fire with the default 300s window, not with a 60s one.
    pkts = [P("10.0.0.62", dst="192.0.2.53", proto="DNS", dport=53, ts=i * 10,
              dns_query=f"host{i}.example.com") for i in range(25)]
    assert not any(x.rule_id == "NW-104" for x in run_all(feats(pkts), cfg(dns_window_s=60.0)))
    assert any(x.rule_id == "NW-104" for x in run_all(feats(pkts), cfg()))


def test_yaml_fallback_multiline_list(tmp_path, monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake(name, *a, **k):
        if name == "yaml":
            raise ImportError("blocked for test")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    p = tmp_path / "c.yaml"
    p.write_text('port_scan_min_ports: 5\nsuspicious_ports: [22,\n  80,\n  443]\n')
    c = load_config(str(p))
    assert c["port_scan_min_ports"] == 5 and c["suspicious_ports"] == [22, 80, 443]


def test_invalid_severity_override_rejected(tmp_path):
    p = tmp_path / "c.json"
    p.write_text('{"severity_overrides": {"NW-101": "extreme"}}')
    try:
        load_config(str(p))
        assert False
    except ValueError:
        pass


def test_empty_html_keeps_header(tmp_path):
    hp = str(tmp_path / "empty.html")
    write_html([], [], {"pcap": "x", "packets": 3}, hp)
    text = Path(hp).read_text()
    assert "NetWatch" in text and "No findings" in text


def test_cli_db_bad_path():
    from netwatch.cli import main
    assert main(["analyze", "--pcap", "sample_data/benign.pcap",
                 "--db", "/nonexistent-dir-xyz/c.db"]) == 3
