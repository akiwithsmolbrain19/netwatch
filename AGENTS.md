# AGENTS.md — AI-assisted security-engineering rules (NetWatch)

## SECURITY
- Defensive security only. Lab, CTF, authorized testing, or owned systems only.
- Never introduce malware, persistence, credential theft, destructive behavior, unauthorized exploitation, or evasion.
- Treat all external input (PCAP bytes, tshark JSON, configs, CLI args) as untrusted. Parsers must handle malformed/empty input without tracebacks.
- Never introduce secrets into source, tests, docs, or commits. Sample PCAPs are synthetic/lab traffic — label them as such.

## DEVELOPMENT
- Inspect existing code (`netwatch/*.py`, `config/default.yaml`) before modifying it.
- Prefer small, focused changes. Do not rewrite working components without justification.
- Do not add dependencies: stdlib + `tshark` only by design. New dependencies need explicit human approval.
- Explain significant architectural tradeoffs (threshold choice, scoring weights).
- Preserve CLI interfaces unless the change is intentional and documented.

## TESTING
- Every new detection rule (NW-1xx) requires positive tests; add negative/benign tests where practical.
- Test threshold boundaries, malformed and empty input, and error paths.
- Run: `python3 -m pytest tests/ -q` (32 tests; requires pytest — not installed in this offline env, see Makefile).
- Do not weaken or delete tests merely to make the implementation pass.
- Do not claim functionality that is not tested.

## SECURITY DETECTION QUALITY
- Detection heuristics are investigative leads, not proof of compromise. Say so in code, docs, and reports.
- Document false-positive / false-negative considerations and detection assumptions.
- Challenge detection logic with adversarial examples (fragmentation, encryption, jitter, low-and-slow, NAT, legitimate scanners).
- MITRE ATT&CK mappings must be defensible; record rationale in `docs/DECISIONS.md`.

## DOCUMENTATION
- Documentation must reflect actual implementation. No stale test counts, no unsupported capability claims.
- Limitations must be explicit (e.g. tshark dependency, encrypted-traffic blindness).

## GIT
- Never commit automatically. Never rewrite history. Never create fake historical commits.
- Keep commits focused. Inspect `git diff` before committing.
- Do not commit generated artifacts (`reports/`, `*.db`, `*.json` output) or secrets. See `.gitignore`.

## QUALITY
- Avoid resource leaks (subprocess handles, file descriptors, SQLite connections).
- Handle expected errors cleanly (missing tshark, bad PCAP path); validate user-controlled input.
- Avoid unnecessary complexity. Keep code understandable to a human reviewer.
