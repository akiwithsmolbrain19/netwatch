"""Professional CLI for NetWatch."""
from __future__ import annotations
import argparse
import sys
from datetime import datetime, timezone

from . import __version__
from .analysis import correlate, score
from .config import load_config
from .features import extract, normalize
from .parser import parse_pcap
from .report import console, write_html, write_json
from .rules import run_all
from . import store


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="netwatch", description="Defensive network threat detection and PCAP analysis (lab/synthetic traffic only).")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="Analyze a PCAP file")
    a.add_argument("--pcap", required=True, help="Path to .pcap/.pcapng file")
    a.add_argument("--config", default=None, help="JSON or YAML config file")
    a.add_argument("--json-out", default=None)
    a.add_argument("--html-out", default=None)
    a.add_argument("--db", default=None, help="SQLite DB path for case management")
    a.add_argument("--verbose", action="store_true")

    l = sub.add_parser("list", help="List stored findings")
    l.add_argument("--db", required=True)
    l.add_argument("--status", default=None)

    s = sub.add_parser("show", help="Inspect one finding")
    s.add_argument("--db", required=True)
    s.add_argument("--id", required=True, type=int)

    st = sub.add_parser("status", help="Change finding status")
    st.add_argument("--db", required=True)
    st.add_argument("--id", required=True, type=int)
    st.add_argument("--to", required=True, choices=sorted(store.STATUSES))
    st.add_argument("--note", default="")
    return ap


def cmd_analyze(ns: argparse.Namespace) -> int:
    try:
        cfg = load_config(ns.config)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    try:
        packets = parse_pcap(ns.pcap)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 4
    except Exception as e:  # unexpected parser failure
        print(f"Error: unexpected parser failure: {e}", file=sys.stderr)
        return 4
    packets = normalize(packets)
    feats = extract(packets)
    findings = score(run_all(feats, cfg))
    groups = correlate(findings)
    meta = {"pcap": ns.pcap, "packets": len(packets),
            "generated": datetime.now(timezone.utc).isoformat(), "version": __version__}
    print(console(findings, groups, verbose=ns.verbose))
    if ns.json_out:
        try:
            write_json(findings, groups, meta, ns.json_out)
        except OSError as e:
            print(f"Error: cannot write JSON report: {e}", file=sys.stderr)
            return 3
        print(f"Wrote JSON: {ns.json_out}")
    if ns.html_out:
        try:
            write_html(findings, groups, meta, ns.html_out)
        except OSError as e:
            print(f"Error: cannot write HTML report: {e}", file=sys.stderr)
            return 3
        print(f"Wrote HTML: {ns.html_out}")
    if ns.db:
        try:
            con = store.connect(ns.db)
        except Exception as e:
            print(f"Error: cannot open database {ns.db}: {e}", file=sys.stderr)
            return 3
        n = store.save(con, findings)
        con.close()
        print(f"Stored {n} finding(s) in {ns.db}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    ns = ap.parse_args(argv)
    if ns.cmd == "analyze":
        return cmd_analyze(ns)
    con = None
    try:
        try:
            con = store.connect(ns.db)
        except Exception as e:
            print(f"Error: cannot open database {ns.db}: {e}", file=sys.stderr)
            return 3
        if ns.cmd == "list":
            try:
                rows = store.list_findings(con, ns.status)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 2
            for r in rows:
                print(f"#{r[0]} {r[1]} [{r[2]}] {r[3]} -> {r[4]} status={r[5]} score={r[6]}")
            return 0
        if ns.cmd == "show":
            row = store.get(con, ns.id)
            if not row:
                print(f"Error: no finding with id {ns.id}", file=sys.stderr)
                return 3
            cols = ["id", "rule_id", "name", "severity", "src", "dst", "proto",
                    "ports", "evidence", "rationale", "mitre", "count",
                    "first_seen", "last_seen", "score", "status", "note", "updated"]
            for k, v in zip(cols, row):
                print(f"{k:10}: {v}")
            return 0
        if ns.cmd == "status":
            try:
                store.set_status(con, ns.id, ns.to, ns.note)
            except (ValueError, LookupError) as e:
                print(f"Error: {e}", file=sys.stderr)
                return 2 if isinstance(e, ValueError) else 3
            print(f"Finding #{ns.id} -> {ns.to}")
            return 0
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
