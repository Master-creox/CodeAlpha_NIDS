# Snort Setup Guide — CodeAlpha Task 4 (NIDS)

Snort is the classic open-source network intrusion detection system. Our
Python NIDS (`nids.py`) demonstrates the same ideas in code; this guide
shows how the **same detections** are done with real Snort, so the
"using Snort or Suricata" part of the task is covered too.

> Run Snort only on your own network / lab traffic. Never sniff a network
> you do not own or have permission to monitor.

## 1. Install Snort (Ubuntu / Kali)

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install snort -y

# Kali Linux (Snort is usually pre-installed; if not:)
sudo apt install snort -y
```

During the Ubuntu install it asks for your home network range — enter
something like `192.168.1.0/24`. Check the install:

```bash
snort -V
```

## 2. Test the configuration

```bash
sudo snort -T -c /etc/snort/snort.conf
# you should see "Snort successfully validated the configuration!"
```

Run Snort in IDS mode on an interface (needs root):

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

## 3. Where the rules live

- System rules: `/etc/snort/rules/` (e.g. `local.rules` is yours to edit)
- Community rules: download from snort.org (free registration) or use the
  built-in rules that ship with the package.
- After editing a rule file, restart Snort or send it a reload signal.

## 4. Equivalent Snort rules for our 6 detections

Add these to `/etc/snort/rules/local.rules`. `$HOME_NET` is your network,
`$EXTERNAL_NET` is everything else (both are defined in `snort.conf`).

### Rule 1 — Port scan
Snort has a dedicated preprocessor for this; enable it in `snort.conf`:

```
preprocessor sfportscan: proto { all } \
    memcap { 10000000 } sense_level { medium } \
    logfile { portscan.log }
```

(Equivalent to our `PORT_SCAN` rule: many distinct ports from one source.)

### Rule 2 — SYN flood
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 \
  (msg:"SYN flood — many SYNs, few ACKs"; flags:S; \
   detection_filter: track by_src, count 20, seconds 10; \
   sid:1000002; rev:1;)
```

### Rule 3 — SSH brute force
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 \
  (msg:"SSH brute force — repeated login attempts"; flags:S; \
   detection_filter: track by_src, count 5, seconds 60; \
   sid:1000003; rev:1;)
```

### Rule 4 — HTTP brute force (repeated POST /login)
```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS \
  (msg:"HTTP brute force — repeated POST /login"; flow:to_server,established; \
   content:"POST"; http_method; content:"/login"; http_uri; \
   detection_filter: track by_src, count 10, seconds 60; \
   sid:1000004; rev:1;)
```

### Rule 5 — SQL injection in HTTP traffic
```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS \
  (msg:"SQL injection attempt in HTTP request"; flow:to_server,established; \
   content:"or"; nocase; pcre:"/(\%27|\')\s*or\s+(\%27|\')?\s*1\s*=\s*1/i"; \
   sid:1000005; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS \
  (msg:"SQL injection — UNION SELECT"; flow:to_server,established; \
   content:"union select"; nocase; sid:1000006; rev:1;)
```

### Rule 6 — ICMP flood / ping sweep
```
alert icmp $EXTERNAL_NET any -> $HOME_NET any \
  (msg:"ICMP flood — high ping rate"; itype:8; \
   detection_filter: track by_src, count 20, seconds 10; \
   sid:1000007; rev:1;)
```

## 5. Test with our sample traffic

Replay the bundled pcap through Snort (no root capture needed):

```bash
# Read a pcap file instead of a live interface:
sudo snort -r sample_traffic.pcap -c /etc/snort/snort.conf -A console -q
```

You should see alerts for the port scan, SYN flood, SSH brute force,
HTTP brute force, SQL injection and ICMP flood — the same six detections
our Python NIDS raises.

## 6. Snort vs our Python NIDS

| Feature | Snort | Our `nids.py` |
|---|---|---|
| Packet capture | libpcap (fast, C) | scapy (slower, Python) |
| Rules | Snort rule language + preprocessors | `rules.json` (JSON) |
| Alerts | console / unified2 / syslog | console + `alerts.log` + SQLite |
| Response | flexresp / external scripts | blocklist file (+ optional iptables) |
| Dashboard | separate tools (Snorby, Squert) | built-in `dashboard.py` |
| Best for | production monitoring | learning how a NIDS works |

## 7. Suricata (alternative)

Suricata works the same way and understands Snort rules. Install and run:

```bash
sudo apt install suricata -y
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
# alerts appear in /var/log/suricata/fast.log and eve.json
```

Suricata's `eve.json` is JSON — the same idea as our `alerts.log`.
