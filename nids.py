#!/usr/bin/env python3
"""
CodeAlpha — Task 4: Network Intrusion Detection System (NIDS)
=============================================================
A small, educational network-based IDS written in pure Python + scapy.

What it does
------------
1. MONITORS traffic — live capture (needs root) or offline from a .pcap file.
2. DETECTS attacks with a rules engine (rules.json): port scans, SYN floods,
   SSH / HTTP brute force, SQL injection signatures and ICMP floods.
3. ALERTS — every match is printed, appended to alerts.log (JSON lines) and
   stored in a SQLite database (alerts.db).
4. RESPONDS — High/Critical alerts add the offending IP to blocked_ips.txt.
   With --enforce it also tries a real firewall block (iptables); by default
   it only LOGS the block (safe to run anywhere).

Run it
-------
    # Offline (no root needed) — the verified path:
    python3 nids.py --pcap sample_traffic.pcap

    # Live capture (needs root):
    sudo python3 nids.py --iface eth0 --count 200

    # Enforce blocks for real (needs root + iptables):
    sudo python3 nids.py --pcap sample_traffic.pcap --enforce

Ethics: run this only on YOUR OWN network or on traffic you are allowed
to inspect. Never point it at someone else's network without permission.
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, rdpcap, sniff
    HAVE_SCAPY = True
except ImportError:  # scapy is optional until a capture is attempted
    HAVE_SCAPY = False

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_RULES = "rules.json"
DEFAULT_DB = "alerts.db"
DEFAULT_LOG = "alerts.log"
DEFAULT_BLOCKLIST = "blocked_ips.txt"
ALERT_COOLDOWN = 60          # seconds: don't repeat the same (rule, src) alert
HTTP_PORTS = (80, 8080, 8000, 443)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def now_iso():
    """Current time as an ISO-8601 string."""
    return datetime.now().isoformat(timespec="seconds")


def pkt_time(pkt):
    """Packet capture time as a float (seconds since epoch)."""
    try:
        return float(pkt.time)
    except Exception:
        return time.time()


def payload_bytes(pkt):
    """Return the raw application payload of a packet as bytes (b'' if none)."""
    if pkt.haslayer(Raw):
        try:
            return bytes(pkt[Raw].load)
        except Exception:
            return b""
    return b""


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
def load_rules(path):
    """Load detection rules from a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    rules = data.get("rules", data) if isinstance(data, dict) else data
    return rules


def rule_by_type(rules, rtype):
    for r in rules:
        if r.get("detection", {}).get("type") == rtype:
            return r
    return None


# ---------------------------------------------------------------------------
# Alert store (console + log file + SQLite)
# ---------------------------------------------------------------------------
class AlertStore:
    """Sends every alert to the console, a JSON-lines log and SQLite."""

    def __init__(self, db_path, log_path):
        self.db_path = db_path
        self.log_path = log_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   timestamp TEXT,
                   rule_id TEXT,
                   rule_name TEXT,
                   severity TEXT,
                   src_ip TEXT,
                   dst_ip TEXT,
                   details TEXT
               )"""
        )
        self.conn.commit()
        self.count = 0

    def add(self, rule, src_ip, dst_ip, details):
        alert = {
            "timestamp": now_iso(),
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "details": details,
        }
        self.count += 1
        # 1. Console
        print(
            "[ALERT] {severity} | {rule_id} ({rule_name}) | "
            "{src_ip} -> {dst_ip} | {details}".format(**alert)
        )
        # 2. JSON-lines log
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")
        # 3. SQLite
        self.conn.execute(
            "INSERT INTO alerts "
            "(timestamp, rule_id, rule_name, severity, src_ip, dst_ip, details)"
            " VALUES (?,?,?,?,?,?,?)",
            (alert["timestamp"], alert["rule_id"], alert["rule_name"],
             alert["severity"], alert["src_ip"], alert["dst_ip"],
             alert["details"]),
        )
        self.conn.commit()
        return alert

    def close(self):
        self.conn.close()


# ---------------------------------------------------------------------------
# Response (blocklist + optional firewall enforcement)
# ---------------------------------------------------------------------------
class Responder:
    """Blocks offending IPs. By default it only LOGS the block (safe mode).
    With --enforce it also runs a real iptables DROP rule (needs root)."""

    BLOCK_SEVERITIES = {"High", "Critical"}

    def __init__(self, blocklist_path, enforce=False):
        self.blocklist_path = blocklist_path
        self.enforce = enforce
        self.blocked = set()
        if os.path.exists(blocklist_path):
            with open(blocklist_path, "r", encoding="utf-8") as f:
                self.blocked = {line.strip() for line in f if line.strip()}

    def respond(self, alert):
        if alert["severity"] not in self.BLOCK_SEVERITIES:
            return False
        src = alert["src_ip"]
        if src in self.blocked:
            return False  # already blocked, don't repeat
        self.blocked.add(src)
        with open(self.blocklist_path, "a", encoding="utf-8") as f:
            f.write(src + "\n")
        if self.enforce:
            try:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", src, "-j", "DROP"],
                    check=True, capture_output=True, text=True,
                )
                action = "iptables DROP rule added"
            except Exception as exc:  # no root / no iptables -> say so
                action = "iptables failed ({}); block kept in file only".format(exc)
        else:
            action = "simulated only (run with --enforce to block for real)"
        print("[RESPONSE] Blocked {} ({}): {}".format(src, alert["rule_id"], action))
        return True


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------
class NidsEngine:
    """Keeps per-source state and checks every packet against the rules."""

    def __init__(self, rules, store, responder):
        self.rules = {r["id"]: r for r in rules}
        self.store = store
        self.responder = responder
        # Sliding-window state, per source IP (lists of timestamps, oldest first).
        self.syn_times = defaultdict(list)        # src -> [ts of SYN]
        self.ack_times = defaultdict(list)        # src -> [ts of ACK]
        self.dst_port_attempts = defaultdict(list)  # (src, dport) -> [ts]
        self.http_times = defaultdict(list)       # src -> [ts of HTTP req]
        self.icmp_times = defaultdict(list)       # src -> [ts of echo req]
        self.icmp_hosts = defaultdict(set)        # src -> {dst hosts pinged}
        self.last_alert = {}                      # (rule_id, src) -> last ts
        self.packets_seen = 0

    # -- window helpers ------------------------------------------------------
    @staticmethod
    def _prune(times, now, window):
        """Drop timestamps older than `window` seconds (list, oldest first)."""
        while times and times[0] < now - window:
            times.pop(0)
        return times

    def _should_alert(self, rule_id, src, now):
        """Rate-limit: one alert per (rule, src) per ALERT_COOLDOWN seconds."""
        key = (rule_id, src)
        if now - self.last_alert.get(key, 0) < ALERT_COOLDOWN:
            return False
        self.last_alert[key] = now
        return True

    def _fire(self, rule, src, dst, details, now):
        if rule is None or not self._should_alert(rule["id"], src, now):
            return
        alert = self.store.add(rule, src, dst, details)
        self.responder.respond(alert)

    # -- main packet handler --------------------------------------------------
    def process(self, pkt):
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        now = pkt_time(pkt)
        self.packets_seen += 1

        # --- TCP ------------------------------------------------------------
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)
            dport = tcp.dport

            # Track (src, dport) attempts for port counting + SSH/HTTP rules.
            self.dst_port_attempts[(src, dport)].append(now)

            # Port scan: distinct destination ports from one source.
            rule = self.rules.get("PORT_SCAN")
            if rule:
                det = rule["detection"]
                window = det.get("window_seconds", 60)
                ports = set()
                for (s, p), times in list(self.dst_port_attempts.items()):
                    if s == src:
                        self._prune(times, now, window)
                        if times:
                            ports.add(p)
                if len(ports) >= det.get("threshold", 10):
                    self._fire(rule, src, dst,
                               "probed {} distinct ports in {}s "
                               "(possible reconnaissance)".format(len(ports), window),
                               now)

            # SYN flood: many SYNs, few ACKs.
            if is_syn:
                self.syn_times[src].append(now)
            if is_ack:
                self.ack_times[src].append(now)
            rule = self.rules.get("SYN_FLOOD")
            if rule and is_syn:
                det = rule["detection"]
                window = det.get("window_seconds", 10)
                syns = self._prune(self.syn_times[src], now, window)
                acks = self._prune(self.ack_times[src], now, window)
                if len(syns) >= det.get("threshold", 20) and len(acks) < len(syns) // 4:
                    self._fire(rule, src, dst,
                               "{} SYNs vs {} ACKs in {}s (half-open flood)".format(
                                   len(syns), len(acks), window), now)

            # SSH brute force: repeated attempts to port 22.
            rule = self.rules.get("SSH_BRUTEFORCE")
            if rule and is_syn and dport == rule["detection"].get("dst_port", 22):
                det = rule["detection"]
                window = det.get("window_seconds", 60)
                attempts = self._prune(
                    self.dst_port_attempts[(src, 22)], now, window)
                if len(attempts) >= det.get("threshold", 5):
                    self._fire(rule, src, dst,
                               "{} SSH connection attempts in {}s".format(
                                   len(attempts), window), now)

            # HTTP brute force: many HTTP requests to a web server.
            rule = self.rules.get("HTTP_BRUTEFORCE")
            if rule and dport in HTTP_PORTS:
                payload = payload_bytes(pkt)
                is_http = payload.startswith((b"GET ", b"POST ", b"HEAD ",
                                              b"PUT ", b"DELETE "))
                if is_http or (is_syn and dport in HTTP_PORTS):
                    # Count real requests; SYNs only count if no payload yet.
                    if is_http:
                        self.http_times[src].append(now)
                    det = rule["detection"]
                    window = det.get("window_seconds", 60)
                    reqs = self._prune(self.http_times[src], now, window)
                    if len(reqs) >= det.get("threshold", 10):
                        self._fire(rule, src, dst,
                                   "{} HTTP requests in {}s (possible "
                                   "credential stuffing)".format(len(reqs), window),
                                   now)

            # SQL injection: signature in the payload (any TCP payload).
            rule = self.rules.get("SQLI")
            if rule:
                payload = payload_bytes(pkt).decode("utf-8", errors="ignore")
                lowered = payload.lower()
                for sig in rule["detection"].get("signatures", []):
                    if sig.lower() in lowered:
                        self._fire(rule, src, dst,
                                   "payload matched SQLi signature {!r}".format(sig),
                                   now)
                        break

        # --- ICMP -------------------------------------------------------------
        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            if int(icmp.type) == 8:  # echo request (ping)
                self.icmp_times[src].append(now)
                self.icmp_hosts[src].add(dst)
                rule = self.rules.get("ICMP_FLOOD")
                if rule:
                    det = rule["detection"]
                    window = det.get("window_seconds", 10)
                    reqs = self._prune(self.icmp_times[src], now, window)
                    hosts = len(self.icmp_hosts[src])
                    if len(reqs) >= det.get("threshold", 20):
                        self._fire(rule, src, dst,
                                   "{} ICMP echo requests in {}s ({} distinct "
                                   "hosts pinged)".format(len(reqs), window, hosts),
                                   now)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="CodeAlpha Task 4 — Python Network Intrusion Detection System")
    ap.add_argument("--pcap", help="offline mode: read packets from a .pcap file")
    ap.add_argument("--iface", default="eth0",
                    help="live mode: interface to sniff (needs root)")
    ap.add_argument("--count", type=int, default=0,
                    help="stop after N packets (0 = unlimited)")
    ap.add_argument("--rules", default=DEFAULT_RULES, help="rules JSON file")
    ap.add_argument("--db", default=DEFAULT_DB, help="SQLite alerts database")
    ap.add_argument("--log", default=DEFAULT_LOG, help="alerts log file")
    ap.add_argument("--blocklist", default=DEFAULT_BLOCKLIST,
                    help="blocked IPs file")
    ap.add_argument("--enforce", action="store_true",
                    help="actually run iptables DROP for blocked IPs "
                         "(needs root; default is simulate-only)")
    args = ap.parse_args()

    if not HAVE_SCAPY:
        print("ERROR: scapy is not installed. Run: pip install -r requirements.txt")
        return 1

    rules = load_rules(args.rules)
    print("Loaded {} detection rules from {}".format(len(rules), args.rules))
    print("Enforce mode: {}".format("ON (real iptables blocks)"
                                    if args.enforce else
                                    "OFF (blocks are simulated/logged only)"))

    store = AlertStore(args.db, args.log)
    responder = Responder(args.blocklist, enforce=args.enforce)
    engine = NidsEngine(rules, store, responder)

    try:
        if args.pcap:
            print("Offline mode: reading {}".format(args.pcap))
            packets = rdpcap(args.pcap)
            total = len(packets)
            for i, pkt in enumerate(packets):
                engine.process(pkt)
                if args.count and i + 1 >= args.count:
                    break
            print("Read {} packets from pcap.".format(min(total, args.count or total)))
        else:
            print("Live mode: sniffing on {} (Ctrl+C to stop)...".format(args.iface))
            sniff(iface=args.iface, prn=engine.process,
                  count=args.count if args.count else 0, store=False)
    except PermissionError:
        print("ERROR: no permission to capture live traffic. "
              "Run with sudo, or use --pcap <file> for offline mode.")
        return 1
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except FileNotFoundError:
        print("ERROR: pcap file not found: {}".format(args.pcap))
        return 1
    finally:
        store.close()

    print("\n===== NIDS SUMMARY =====")
    print("Packets inspected : {}".format(engine.packets_seen))
    print("Alerts raised     : {}".format(store.count))
    print("IPs blocked       : {} (see {})".format(
        len(responder.blocked), args.blocklist))
    print("Alerts log        : {}".format(args.log))
    print("Alerts database   : {}".format(args.db))
    print("Run  python3 dashboard.py  to build the HTML dashboard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
