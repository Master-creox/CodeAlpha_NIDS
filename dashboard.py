#!/usr/bin/env python3
"""
CodeAlpha — Task 4: NIDS Dashboard Generator
============================================
Reads the alerts database (alerts.db) produced by nids.py and builds a
single standalone HTML dashboard — no server, no internet, no external
libraries. Just open the file in a browser.

What it shows
-------------
- Summary cards: total alerts, Critical / High / Medium, unique attackers,
  IPs currently blocked.
- Alerts over time (hourly bar chart, pure CSS).
- Top offending source IPs.
- Rule hit counts.
- Severity breakdown.
- Full alert table (newest first) and the current blocklist.

Run:
    python3 dashboard.py                 # reads alerts.db, writes dashboard.html
    python3 dashboard.py --db alerts.db --output dashboard.html
"""

import argparse
import html
import json
import os
import sqlite3
import sys
from collections import Counter

SEVERITY_COLORS = {
    "Critical": "#e5484d",
    "High": "#f76b15",
    "Medium": "#ffb224",
    "Low": "#46a758",
}

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NIDS Dashboard — CodeAlpha Task 4</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; font-family: Arial, Helvetica, sans-serif;
         background: #0f1115; color: #e6e6e6; }
  header { background: #171a21; border-bottom: 3px solid #e5484d;
           padding: 18px 24px; }
  header h1 { margin: 0; font-size: 24px; }
  header p { margin: 4px 0 0; color: #9aa0aa; }
  main { max-width: 1100px; margin: 0 auto; padding: 20px 16px 40px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
           gap: 12px; margin-bottom: 24px; }
  .card { background: #171a21; border: 1px solid #262a33; border-radius: 10px;
          padding: 14px 16px; }
  .card .num { font-size: 30px; font-weight: bold; }
  .card .lbl { color: #9aa0aa; font-size: 13px; margin-top: 4px; }
  section { background: #171a21; border: 1px solid #262a33; border-radius: 10px;
            padding: 16px 18px; margin-bottom: 20px; }
  h2 { margin: 0 0 12px; font-size: 18px; }
  .bar-row { display: flex; align-items: center; gap: 10px; margin: 6px 0; }
  .bar-lbl { width: 170px; text-align: right; color: #c8cdd5; font-size: 13px;
             overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { flex: 1; background: #262a33; border-radius: 4px; height: 18px; }
  .bar-fill { height: 100%; border-radius: 4px; background: #e5484d; }
  .bar-val { width: 40px; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid #262a33;
           vertical-align: top; }
  th { color: #9aa0aa; }
  .sev { display: inline-block; padding: 2px 8px; border-radius: 20px;
         color: #fff; font-size: 12px; font-weight: bold; }
  .mono { font-family: monospace; }
  .muted { color: #9aa0aa; }
  .blocked { display: inline-block; background: #3a1214; border: 1px solid #e5484d;
             color: #ffb3b3; border-radius: 6px; padding: 4px 10px; margin: 3px;
             font-family: monospace; }
  .empty { color: #9aa0aa; }
</style>
</head>
<body>
<header>
  <h1>&#128737; NIDS Dashboard</h1>
  <p>CodeAlpha Cyber Security — Task 4: Network Intrusion Detection System &nbsp;|&nbsp; Generated from <span class="mono">__DB__</span></p>
</header>
<main>
  <div class="cards">
    __CARDS__
  </div>
  <section>
    <h2>Alerts over time (per hour)</h2>
    __TIME_BARS__
  </section>
  <section>
    <h2>Top offending source IPs</h2>
    __TOP_IPS__
  </section>
  <section>
    <h2>Rule hit counts</h2>
    __RULE_BARS__
  </section>
  <section>
    <h2>Severity breakdown</h2>
    __SEV_BARS__
  </section>
  <section>
    <h2>Blocked IPs (response actions)</h2>
    __BLOCKED__
  </section>
  <section>
    <h2>All alerts (newest first)</h2>
    __ALERT_TABLE__
  </section>
  <p class="muted">Educational project — alerts come only from traffic you captured
  yourself or from the bundled sample pcap. Never monitor a network you do not
  own or have permission to inspect.</p>
</main>
</body>
</html>
"""


def bar_row(label, value, max_value, color="#e5484d"):
    """One horizontal bar row; width is relative to the largest value."""
    width = (value / max_value * 100) if max_value else 0
    return (
        '<div class="bar-row"><span class="bar-lbl">{}</span>'
        '<span class="bar-track"><span class="bar-fill" style="display:block;'
        'width:{:.1f}%;background:{}"></span></span>'
        '<span class="bar-val">{}</span></div>'
    ).format(html.escape(str(label)), width, color, value)


def build(db_path, blocklist_path):
    """Read alerts.db (+ blocklist) and return the dashboard HTML string."""
    if not os.path.exists(db_path):
        print("ERROR: database not found: {} (run nids.py first)".format(db_path))
        return None
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()
    conn.close()

    total = len(rows)
    sev_counts = Counter(r["severity"] for r in rows)
    rule_counts = Counter(r["rule_id"] for r in rows)
    ip_counts = Counter(r["src_ip"] for r in rows)
    hour_counts = Counter((r["timestamp"] or "")[:13] for r in rows)

    blocked = []
    if os.path.exists(blocklist_path):
        with open(blocklist_path, "r", encoding="utf-8") as f:
            blocked = [line.strip() for line in f if line.strip()]

    # --- summary cards -----------------------------------------------------
    cards = [
        (total, "Total alerts"),
        (sev_counts.get("Critical", 0), "Critical"),
        (sev_counts.get("High", 0), "High"),
        (sev_counts.get("Medium", 0), "Medium"),
        (len(ip_counts), "Unique attackers"),
        (len(blocked), "IPs blocked"),
    ]
    cards_html = "".join(
        '<div class="card"><div class="num">{}</div>'
        '<div class="lbl">{}</div></div>'.format(n, lbl) for n, lbl in cards)

    # --- alerts over time ---------------------------------------------------
    if hour_counts:
        top_hour = max(hour_counts.values())
        time_html = "".join(
            bar_row(h, c, top_hour, "#4c8dff")
            for h, c in sorted(hour_counts.items()))
    else:
        time_html = '<p class="empty">No alerts yet.</p>'

    # --- top IPs -------------------------------------------------------------
    if ip_counts:
        top_ip = max(ip_counts.values())
        ips_html = "".join(
            bar_row(ip, c, top_ip, "#f76b15")
            for ip, c in ip_counts.most_common(10))
    else:
        ips_html = '<p class="empty">No alerts yet.</p>'

    # --- rule hits ------------------------------------------------------------
    if rule_counts:
        top_rule = max(rule_counts.values())
        rule_html = "".join(
            bar_row(rule, c, top_rule, "#e5484d")
            for rule, c in rule_counts.most_common())
    else:
        rule_html = '<p class="empty">No alerts yet.</p>'

    # --- severity -------------------------------------------------------------
    if sev_counts:
        top_sev = max(sev_counts.values())
        sev_html = "".join(
            bar_row(sev, c, top_sev, SEVERITY_COLORS.get(sev, "#888"))
            for sev, c in sev_counts.most_common())
    else:
        sev_html = '<p class="empty">No alerts yet.</p>'

    # --- blocked IPs ------------------------------------------------------------
    blocked_html = ("".join('<span class="blocked">{}</span>'.format(html.escape(ip))
                           for ip in blocked)
                      or '<p class="empty">No IPs blocked yet.</p>')

    # --- alert table -------------------------------------------------------------
    if rows:
        trs = []
        for r in rows:
            color = SEVERITY_COLORS.get(r["severity"], "#888")
            trs.append(
                "<tr><td class=\"mono\">{}</td>"
                "<td><span class=\"sev\" style=\"background:{}\">{}</span></td>"
                "<td class=\"mono\">{}</td><td>{}</td>"
                "<td class=\"mono\">{}</td><td class=\"mono\">{}</td>"
                "<td>{}</td></tr>".format(
                    html.escape(r["timestamp"] or ""),
                    color, html.escape(r["severity"] or ""),
                    html.escape(r["rule_id"] or ""),
                    html.escape(r["rule_name"] or ""),
                    html.escape(r["src_ip"] or ""),
                    html.escape(r["dst_ip"] or ""),
                    html.escape(r["details"] or "")))
        table_html = (
            "<table><tr><th>Time</th><th>Severity</th><th>Rule</th>"
            "<th>Name</th><th>Source IP</th><th>Dest IP</th><th>Details</th></tr>"
            + "".join(trs) + "</table>")
    else:
        table_html = '<p class="empty">No alerts yet — run nids.py first.</p>'

    return (PAGE.replace("__DB__", html.escape(db_path))
                .replace("__CARDS__", cards_html)
                .replace("__TIME_BARS__", time_html)
                .replace("__TOP_IPS__", ips_html)
                .replace("__RULE_BARS__", rule_html)
                .replace("__SEV_BARS__", sev_html)
                .replace("__BLOCKED__", blocked_html)
                .replace("__ALERT_TABLE__", table_html))


def main():
    ap = argparse.ArgumentParser(description="Build the NIDS HTML dashboard")
    ap.add_argument("--db", default="alerts.db", help="SQLite alerts database")
    ap.add_argument("--blocklist", default="blocked_ips.txt",
                    help="blocked IPs file")
    ap.add_argument("--output", default="dashboard.html",
                    help="output HTML file")
    args = ap.parse_args()

    html_doc = build(args.db, args.blocklist)
    if html_doc is None:
        return 1
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html_doc)
    print("Dashboard written to {} ({} bytes). Open it in any browser.".format(
        args.output, os.path.getsize(args.output)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
