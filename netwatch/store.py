"""SQLite case management (stdlib sqlite3)."""
from __future__ import annotations
import sqlite3
import time

from .models import Finding

STATUSES = {"open", "investigating", "closed", "false_positive"}
SCHEMA = """CREATE TABLE IF NOT EXISTS findings(
 id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT, name TEXT, severity TEXT,
 src TEXT, dst TEXT, proto TEXT, ports TEXT, evidence TEXT, rationale TEXT,
 mitre TEXT, cnt INTEGER, first_seen REAL, last_seen REAL, score REAL,
 status TEXT DEFAULT 'open', note TEXT DEFAULT '', updated REAL)"""


def connect(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.execute(SCHEMA)
    con.commit()
    return con


def save(con: sqlite3.Connection, findings: list[Finding]) -> int:
    now = time.time()
    n = 0
    for f in findings:
        con.execute("INSERT INTO findings(rule_id,name,severity,src,dst,proto,ports,evidence,rationale,mitre,cnt,first_seen,last_seen,score,status,updated)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (f.rule_id, f.name, f.severity, f.src, f.dst, f.proto, ",".join(map(str, f.ports)),
                     f.evidence, f.rationale, ",".join(f.mitre), f.count, f.first_seen, f.last_seen,
                     f.score, "open", now))
        n += 1
    con.commit()
    return n


def list_findings(con: sqlite3.Connection, status: str | None = None) -> list[tuple]:
    q = "SELECT id,rule_id,severity,src,dst,status,score FROM findings"
    args: tuple = ()
    if status:
        if status not in STATUSES:
            raise ValueError(f"Invalid status {status!r}; choose from {sorted(STATUSES)}")
        q += " WHERE status=?"
        args = (status,)
    return con.execute(q + " ORDER BY score DESC", args).fetchall()


def get(con: sqlite3.Connection, fid: int) -> tuple | None:
    return con.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()


def set_status(con: sqlite3.Connection, fid: int, status: str, note: str = "") -> None:
    if status not in STATUSES:
        raise ValueError(f"Invalid status {status!r}; choose from {sorted(STATUSES)}")
    cur = con.execute("UPDATE findings SET status=?, note=?, updated=strftime('%s','now') WHERE id=?", (status, note, fid))
    if cur.rowcount == 0:
        raise LookupError(f"No finding with id {fid}")
    con.commit()
