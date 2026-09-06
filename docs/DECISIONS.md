# Architecture decision records — NetWatch

## 1. Stdlib + tshark only, no runtime Python dependencies
- Context: must run on stock lab installs against real PCAPs.
- Alternatives: scapy/dpkt/pyshark, pandas.
- Decision: shell out to tshark for parsing; stdlib for everything else.
- Rationale: no heavy deps; tshark is the lab-standard parser.
- Tradeoffs: hard dependency on external tshark binary; subprocess handling needed.
- Consequences: CLI must fail cleanly when tshark is missing; tests use synthetic Packet objects.

## 2. Per-source aggregation before rules
- Context: rules need per-actor view.
- Alternatives: per-packet rules; full flow tracking.
- Decision: `features.py` aggregates per-source stats, rules consume features.
- Rationale: simple, testable, explainable thresholds.
- Tradeoffs: NAT conflates sources (documented); no full TCP reassembly.
- Consequences: flood/scan counts inflate behind NAT — noted in DETECTION-REVIEW.md.

## 3. Independent modular rules (NW-101..NW-108) + score/correlate layer
- Context: want explainable, individually testable detections.
- Alternatives: monolithic classifier; ML model.
- Decision: 8 independent rules in `rules.py`, scoring/correlation in `analysis.py`.
- Rationale: each rule has +/− tests and threshold reasoning; correlation reduces alert fatigue.
- Tradeoffs: no cross-packet statefulness beyond features; scoring weights are judgment calls.
- Consequences: every new rule ships with positive, negative, and boundary tests.

## 4. Heuristics framed as leads, with MITRE hints
- Context: heuristic detections risk overclaim.
- Alternatives: no MITRE mapping; hard verdicts.
- Decision: MITRE IDs as defensible hints; reports state "investigative lead".
- Rationale: analyst-compatible language without false certainty.
- Tradeoffs: mappings are approximate.
- Consequences: challenge mappings in review; record disputes here.
