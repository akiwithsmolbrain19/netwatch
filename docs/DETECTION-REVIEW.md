# Detection review — NetWatch

Heuristics are investigative leads, not proof of compromise. Per rule (NW-101..NW-108):
trigger, evidence, legitimate triggers, evasion, thresholds, FP/FN risks, validation.

## NW-101 port scan / NW-102 discovery / NW-103 repeated
- Triggers: distinct ports/hosts/attempt counts above `port_scan_min_ports`, discovery and `repeat_min_attempts` thresholds.
- Legitimate: asset inventory, monitoring, admin scripts.
- Evasion: low-and-slow, distributed sources, common-port-only probing.
- Validate: is the source an approved scanner? correlate with NW-105/106.

## NW-104 DNS anomaly
- Triggers: NXDOMAIN volume above `dns_nxdomain_min`, suspicious query shapes.
- Legitimate: captive portals, misconfigured clients, AV/telemetry domains.
- Evasion: encrypted DNS (DoH/Do53 over TLS — invisible here), low-volume tunneling.
- Validate: query names, endpoint reputation, volume baseline.

## NW-105 HTTP recon / NW-108 flood
- Triggers: path diversity / packet rate above thresholds (`flood_min_pps`).
- Legitimate: crawlers, load tests, high-volume legitimate services, scheduled jobs.
- Evasion: pacing below thresholds, jitter, rotating sources behind NAT.
- Validate: UA/paths for recon; rate baseline per service for flood (NAT hides source counts).

## NW-106 beaconing
- Triggers: low interval variance (CV below `beacon_cv_max`).
- Legitimate: polling clients, keepalives, scheduled jobs.
- Evasion: jitter, irregular callbacks, low-and-slow.
- Validate: interval histogram, destination reputation, payload context (unavailable if encrypted).

## NW-107 suspicious ports
- Triggers: contact on watchlist ports.
- Legitimate: custom apps on odd ports, remote admin tools in labs.
- Evasion: tunneling over 443/80.
- Validate: what service actually answered; lab inventory.

## Network-wide limits (acknowledged, not solved)
Fragmented traffic, encrypted traffic (blind to payloads), jitter, low-and-slow,
NAT (source conflation), legitimate scanners/monitoring, scheduled jobs,
high-volume legitimate services. Encrypted traffic especially: rules see metadata
only. Do not claim otherwise.

## Adversarial testing examples
- Benign high-rate traffic (sample `benign.pcap`) — expect no critical findings.
- Jittered/low-rate beacon vs strict beacon — document the miss honestly.
- Fragmented or encrypted captures — parsers must not crash; findings degrade.
- NAT scenario: many hosts behind one IP — flood/scan counts inflate; note it.
