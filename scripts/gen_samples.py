"""Generate clearly-synthetic lab PCAPs (RFC5737 TEST-NET addresses only)."""
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

OUT = "sample_data"
ATT = "198.51.100.7"      # simulated attacker (TEST-NET-2)
VIC = "192.0.2.10"        # simulated victim (TEST-NET-1)
BEN = "192.0.2.20"        # benign client
SRV = "192.0.2.53"
t = 1700000000.0

def syn(src, dst, dport, ts):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=12345, dport=dport, flags="S")
    p.time = ts
    return p

# 1. port scan: 25 ports
pkts = [syn(ATT, VIC, 1000 + i, t + i * 0.2) for i in range(25)]
wrpcap(f"{OUT}/scan.pcap", pkts)

# 2. benign: a few normal HTTP-ish SYNs + DNS
pkts = []
pkts += [syn(BEN, VIC, 80, t + i * 5) for i in range(3)]
for i in range(2):
    p = Ether() / IP(src=BEN, dst=SRV) / UDP(sport=53000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    p.time = t + 30 + i
    pkts.append(p)
wrpcap(f"{OUT}/benign.pcap", pkts)

# 3. repeated connections to 445
pkts = [syn(ATT, VIC, 445, t + i * 2) for i in range(20)]
wrpcap(f"{OUT}/repeated.pcap", pkts)

# 4. DNS anomaly: high volume of unique queries (query-only capture, so no
# response rcodes are present; samples exercise the unique-query branch).
pkts = []
for i in range(25):
    p = Ether() / IP(src=ATT, dst=SRV) / UDP(sport=40000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=f"zzq{i}xjkqwvaz{i}.evil-test.invalid"))
    p.time = t + i * 3
    pkts.append(p)
wrpcap(f"{OUT}/dns_anomaly.pcap", pkts)

# 5. HTTP recon
pkts = []
for i, uri in enumerate(["/admin", "/wp-login.php", "/.git/config", "/phpmyadmin", "/etc/passwd", "/actuator/health"]):
    p = Ether() / IP(src=ATT, dst=VIC) / TCP(sport=20000 + i, dport=80, flags="PA") / Raw(load=f"GET {uri} HTTP/1.1\r\nHost: x\r\nUser-Agent: nikto-test\r\n\r\n".encode())
    p.time = t + i * 2
    pkts.append(p)
wrpcap(f"{OUT}/http_recon.pcap", pkts)

# 6. beaconing: periodic every 30s x8 to same port
pkts = [syn(ATT, VIC, 4444, t + i * 30) for i in range(8)]
wrpcap(f"{OUT}/beacon.pcap", pkts)

# 7. host discovery: 12 hosts
pkts = [syn(ATT, f"192.0.2.{i}", 80, t + i * 0.5) for i in range(1, 13)]
wrpcap(f"{OUT}/discovery.pcap", pkts)
print("wrote sample pcaps")
