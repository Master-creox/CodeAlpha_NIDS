#!/usr/bin/env python3
"""
Generate sample_traffic.pcap for the CodeAlpha NIDS (Task 4).

Creates one pcap file containing BOTH normal traffic and attack traffic,
so the NIDS can be tested offline without root:

  Normal traffic (should NOT raise alerts)
    - 3 HTTP GET requests, 2 DNS queries, 2 pings, 1 SSH login
  Attack traffic (SHOULD raise alerts)
    - 10.0.0.50 : port scan       (SYN to 15 distinct ports)
    - 10.0.0.60 : SYN flood       (30 SYNs to port 80, no ACKs)
    - 10.0.0.70 : SSH brute force (8 SYNs to port 22)
    - 10.0.0.80 : HTTP brute force (12 POST /login requests)
    - 10.0.0.100: SQL injection   (GET ... ' OR '1'='1 --)
    - 10.0.0.101: SQL injection   (UNION SELECT in POST body)
    - 10.0.0.90 : ICMP flood      (25 ping requests, incl. a small sweep)

Run:
    python3 generate_sample_traffic.py
    python3 nids.py --pcap sample_traffic.pcap
"""

import time

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap

OUT = "sample_traffic.pcap"
TARGET = "192.168.1.100"   # the "server" being attacked
NORMAL_HOST = "192.168.1.10"


def main():
    packets = []
    t = time.time()  # base timestamp; packets are ~0.2s apart

    def add(pkt):
        nonlocal t
        pkt.time = t
        t += 0.2
        packets.append(pkt)

    # ------------------------------------------------------------------
    # NORMAL traffic (below every rule threshold)
    # ------------------------------------------------------------------
    for i in range(3):  # 3 ordinary HTTP GETs
        add(IP(src=NORMAL_HOST, dst=TARGET) /
            TCP(sport=40000 + i, dport=80, flags="PA") /
            Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
    for i in range(2):  # 2 DNS queries
        add(IP(src=NORMAL_HOST, dst="8.8.8.8") /
            UDP(sport=53000 + i, dport=53) /
            DNS(rd=1, qd=DNSQR(qname="example.com")))
    for i in range(2):  # 2 ordinary pings
        add(IP(src=NORMAL_HOST, dst=TARGET) /
            ICMP(type=8) / Raw(load=b"ping"))
    add(IP(src=NORMAL_HOST, dst=TARGET) /  # 1 normal SSH login
        TCP(sport=41000, dport=22, flags="S"))

    # ------------------------------------------------------------------
    # ATTACK 1 — port scan (10.0.0.50 -> 15 distinct ports)
    # ------------------------------------------------------------------
    for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
                 445, 993, 1723, 3306, 8080]:
        add(IP(src="10.0.0.50", dst=TARGET) /
            TCP(sport=50000 + port, dport=port, flags="S"))

    # ------------------------------------------------------------------
    # ATTACK 2 — SYN flood (10.0.0.60 -> 30 SYNs, port 80, no ACKs)
    # ------------------------------------------------------------------
    for i in range(30):
        add(IP(src="10.0.0.60", dst=TARGET) /
            TCP(sport=51000 + i, dport=80, flags="S"))

    # ------------------------------------------------------------------
    # ATTACK 3 — SSH brute force (10.0.0.70 -> 8 SYNs, port 22)
    # ------------------------------------------------------------------
    for i in range(8):
        add(IP(src="10.0.0.70", dst=TARGET) /
            TCP(sport=52000 + i, dport=22, flags="S"))

    # ------------------------------------------------------------------
    # ATTACK 4 — HTTP brute force (10.0.0.80 -> 12 POST /login)
    # ------------------------------------------------------------------
    for i in range(12):
        body = "username=admin&password=guess{}&submit=Login".format(i).encode()
        payload = (b"POST /login HTTP/1.1\r\nHost: example.com\r\n"
                   b"Content-Length: " + str(len(body)).encode() +
                   b"\r\n\r\n" + body)
        add(IP(src="10.0.0.80", dst=TARGET) /
            TCP(sport=53000 + i, dport=80, flags="PA") /
            Raw(load=payload))

    # ------------------------------------------------------------------
    # ATTACK 5 — SQL injection (two sources, two signatures)
    # ------------------------------------------------------------------
    add(IP(src="10.0.0.100", dst=TARGET) /
        TCP(sport=54000, dport=80, flags="PA") /
        Raw(load=b"GET /search?q=' OR '1'='1 -- HTTP/1.1\r\n"
                 b"Host: example.com\r\n\r\n"))
    add(IP(src="10.0.0.101", dst=TARGET) /
        TCP(sport=54001, dport=80, flags="PA") /
        Raw(load=b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\n"
                 b"username=admin' UNION SELECT password FROM users--&password=x"))

    # ------------------------------------------------------------------
    # ATTACK 6 — ICMP flood / ping sweep (10.0.0.90 -> 25 echo requests)
    # ------------------------------------------------------------------
    for i in range(20):
        add(IP(src="10.0.0.90", dst=TARGET) /
            ICMP(type=8) / Raw(load=b"ping-flood"))
    for i in range(5):  # sweep: same source, different hosts
        add(IP(src="10.0.0.90", dst="192.168.1.{}".format(101 + i)) /
            ICMP(type=8) / Raw(load=b"ping-sweep"))

    wrpcap(OUT, packets)
    print("Wrote {} packets to {} ({} normal + {} attack)".format(
        len(packets), OUT, 8, len(packets) - 8))


if __name__ == "__main__":
    main()
