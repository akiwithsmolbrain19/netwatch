"""Default configuration and loader (stdlib only, supports JSON + minimal YAML)."""
from __future__ import annotations
import json
from pathlib import Path

DEFAULTS: dict = {
    "port_scan_min_ports": 10,
    "port_scan_window_s": 60.0,
    "host_discovery_min_hosts": 8,
    "host_discovery_window_s": 60.0,
    "repeat_min_attempts": 15,
    "repeat_window_s": 120.0,
    "dns_nxdomain_min": 5,
    "dns_query_min_unique": 20,
    "dns_window_s": 300.0,
    "http_recon_suspicious_paths": ["/admin", "/wp-login", "/.git/", "/etc/passwd",
                                    "../", "nikto", "sqlmap", "/phpmyadmin", "/actuator"],
    "http_recon_min_hits": 3,
    "beacon_min_events": 6,
    "beacon_cv_max": 0.25,
    "flood_min_pps": 20.0,
    "flood_window_s": 10.0,
    "suspicious_ports": [22, 23, 445, 3389, 5900, 6379, 27017, 4444, 6667],
    "suspicious_min_hits": 3,
    "bruteforce_min_attempts": 10,
    "severity_overrides": {},
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _parse_simple_yaml(text: str) -> dict:
    """Minimal YAML subset for flat key: value files, incl. multi-line [..] lists."""
    # Join continuation lines inside unclosed brackets.
    joined: list[str] = []
    buf = ""
    depth = 0
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        buf += (" " if buf else "") + stripped
        depth += buf.count("[") - buf.count("]")
        if depth <= 0:
            joined.append(buf)
            buf = ""
            depth = 0
    if buf:
        joined.append(buf)
    out: dict = {}
    for line in joined:
        if ":" not in line:
            raise ValueError(f"Invalid config line: {line!r}")
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        try:
            out[k] = json.loads(v)
        except Exception:
            out[k] = v.strip("\"'")
    return out


def load_config(path: str | None) -> dict:
    cfg = dict(DEFAULTS)
    if not path:
        return cfg
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    text = p.read_text()
    try:
        if p.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
                data = yaml.safe_load(text) or {}
            except ImportError:
                data = _parse_simple_yaml(text)
        else:
            data = json.loads(text)
    except FileNotFoundError:
        raise
    except Exception as e:
        raise ValueError(f"Invalid configuration in {path}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"Invalid configuration in {path}: top level must be a mapping")
    unknown = set(data) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"Invalid configuration in {path}: unknown keys {sorted(unknown)}")
    overrides = data.get("severity_overrides", {})
    if not isinstance(overrides, dict) or any(
            s not in VALID_SEVERITIES for s in overrides.values()):
        raise ValueError(f"Invalid configuration in {path}: severity_overrides values must be one of {sorted(VALID_SEVERITIES)}")
    cfg.update(data)
    return cfg
