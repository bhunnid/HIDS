import os, re, sys, json, time, threading, signal, sqlite3
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request, redirect, url_for, Response

import hids_engine as eng

# Populate configuration up-front so the dashboard bind address/port and file
# paths come from config.json (env vars still take precedence if set).
eng.load_config()

ALERT_LOG = eng.CFG.get("alert_log", "alerts.log")
PORT = int(os.environ.get("PORT", eng.CFG.get("dashboard_port", 5000)))
HOST_BIND = os.environ.get("HOST", eng.CFG.get("dashboard_host", "0.0.0.0"))

app = Flask(__name__)
threading.Thread(target=eng.start_engine, daemon=True).start()


def _on_exit(*_):
    eng.stop_engine(); os._exit(0)


signal.signal(signal.SIGTERM, _on_exit)
signal.signal(signal.SIGINT, _on_exit)


_RULE_META = {
    "brute_force":     ("Brute-force Login",      "H1"),
    "priv_escalation": ("Privilege Escalation",   "H2"),
    "proc_anomaly":    ("Process Anomaly",         "H3"),
    "file_integrity":  ("File Tampered",           "H4"),
    "susp_process":    ("Suspicious Process",      "H5"),
    "syn_flood":       ("SYN Flood",               "N1"),
    "udp_flood":       ("UDP Flood",               "N2"),
    "icmp_flood":      ("ICMP Flood",              "N3"),
    "dns_tunnel":      ("DNS Tunneling",           "N5"),
    "arp_spoof":       ("ARP Spoofing",            "N6"),
    "engine":          ("System",                  "SYS"),
}

_LEVEL_COLOR = {
    "CRITICAL": "#C0392B", "HIGH": "#CB5A1F",
    "MEDIUM": "#B07A12", "LOW": "#2F6DB3", "INFO": "#7A766E",
}


def _enrich(row: dict) -> dict:
    rule = row.get("rule", "")
    level = row.get("level", "INFO")
    disp = rule[5:] if rule.startswith("scan_") else rule
    label, code = _RULE_META.get(disp, ("Alert", "--"))
    if rule.startswith("scan_"):
        label = f"Port Scan ({rule[5:]})"
        code = "N4"
    row["label"] = label
    row["code"] = code
    row["color"] = _LEVEL_COLOR.get(level, "#7A766E")
    row["score"] = row.get("score", 0)
    return row


def _uptime() -> str:
    st = eng.hids_state.get("uptime_start")
    if st and eng.is_running():
        s = int((datetime.now() - st).total_seconds())
        h, r = divmod(s, 3600); m, sec = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{sec:02d}"
    return ""


DASH_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ulinzi — Host Intrusion Detection</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700&family=Fraunces:opsz,wght@9..144,400;9..144,500;9..144,600;9..144,700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root{
    --paper:#F4F3EE; --surface:#FBFAF6; --surface-2:#FFFFFF;
    --ink:#1A1916; --ink-soft:#57544B; --ink-faint:#8E8A7E;
    --rule:#E3E0D7; --rule-2:#CFCBBE; --rule-ink:#1A1916;
    --crit:#B23A2E; --high:#C25A1E; --med:#9C7510; --low:#2C63A6; --info:#7A766E;
    --serif:'Fraunces',Georgia,'Times New Roman',serif;
    --sans:'Archivo','Helvetica Neue',Arial,sans-serif;
    --mono:'JetBrains Mono',ui-monospace,Menlo,monospace;
    --r:3px;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{background:var(--paper);color:var(--ink);font-family:var(--sans);
    -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
  body{line-height:1.45;font-size:14px}
  ::selection{background:var(--ink);color:var(--paper)}
  a{color:inherit;text-decoration:none;cursor:pointer}
  .wrap{max-width:1240px;margin:0 auto;padding:0 28px 64px}

  /* ---------- masthead ---------- */
  .mast{padding-top:30px}
  .mast-rule-top{height:3px;background:var(--ink);margin-bottom:18px}
  .mast-head{display:flex;justify-content:space-between;align-items:flex-end;gap:24px}
  .brand h1{font-family:var(--serif);font-weight:600;font-size:62px;line-height:.9;
    letter-spacing:-.02em;font-optical-sizing:auto}
  .brand .tag{font-size:10.5px;letter-spacing:.34em;text-transform:uppercase;
    color:var(--ink-soft);margin-top:10px;font-weight:600}
  .status-cluster{text-align:right;padding-bottom:4px;white-space:nowrap}
  .phase{display:inline-flex;align-items:center;gap:8px;font-size:11px;font-weight:600;
    letter-spacing:.06em;text-transform:uppercase}
  .dot{width:8px;height:8px;border-radius:50%;background:var(--ink-faint);flex:none}
  .dot.on{background:var(--low)}
  .dot.warn{background:var(--med)}
  .dot.off{background:var(--ink-faint)}
  .dot.live{animation:pulse 2s ease-in-out infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
  .uptime{font-family:var(--mono);font-size:22px;font-weight:500;margin-top:6px;letter-spacing:.02em}
  .clock{font-family:var(--mono);font-size:10.5px;color:var(--ink-faint);margin-top:3px;letter-spacing:.08em}

  .mast-rule{margin:16px 0 0;border-top:2px solid var(--ink);border-bottom:1px solid var(--ink)}
  .dateline{display:flex;justify-content:space-between;align-items:center;
    padding:7px 0;font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-soft);font-weight:500}
  .mast-rule-bot{height:1px;background:var(--rule-2)}

  /* ---------- nav ---------- */
  .nav{display:flex;gap:32px;padding:16px 0 0;margin-bottom:26px}
  .nav a{font-size:11px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;
    color:var(--ink-faint);padding-bottom:9px;border-bottom:2px solid transparent;transition:color .15s,border-color .15s}
  .nav a:hover{color:var(--ink-soft)}
  .nav a.on{color:var(--ink);border-color:var(--ink)}

  /* ---------- pages ---------- */
  .page{display:none;animation:rise .45s cubic-bezier(.2,.7,.3,1)}
  .page.on{display:block}
  @keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

  /* ---------- KPI strip ---------- */
  .kpis{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid var(--rule);
    background:var(--surface);border-radius:var(--r);overflow:hidden}
  .kpi{padding:18px 20px 16px;border-left:1px solid var(--rule);position:relative}
  .kpi:first-child{border-left:0}
  .kpi .lbl{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-faint);font-weight:600}
  .kpi .val{font-family:var(--serif);font-size:42px;font-weight:500;line-height:1;margin-top:10px;
    letter-spacing:-.01em;font-variant-numeric:tabular-nums}
  .kpi .sub{font-size:10px;color:var(--ink-faint);margin-top:8px;letter-spacing:.02em}
  .kpi.crit .val{color:var(--crit)}
  .kpi.crit::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--crit)}

  /* ledger row */
  .ledger{display:flex;flex-wrap:wrap;gap:0;align-items:center;margin-top:14px;
    font-family:var(--mono);font-size:11px;color:var(--ink-soft);border:1px solid var(--rule);
    border-radius:var(--r);background:var(--surface);overflow:hidden}
  .ledger .seg{padding:8px 14px;border-left:1px solid var(--rule);display:flex;gap:7px;align-items:baseline}
  .ledger .seg:first-child{border-left:0}
  .ledger .seg b{font-weight:700;color:var(--ink)}
  .ledger .seg .k{font-size:9px;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-faint)}
  .ledger .sp{flex:1}

  /* ---------- layout grid ---------- */
  .grid{display:grid;grid-template-columns:1fr 340px;gap:18px;margin-top:18px}
  @media(max-width:920px){.grid{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}
    .kpi:nth-child(3){border-left:0}.kpi:nth-child(n+3){border-top:1px solid var(--rule)}}

  .card{background:var(--surface);border:1px solid var(--rule);border-radius:var(--r)}
  .card + .card{margin-top:18px}
  .card-hd{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;
    border-bottom:1px solid var(--rule)}
  .card-hd h3{font-family:var(--serif);font-weight:600;font-size:17px;letter-spacing:-.01em}
  .card-hd .meta{font-family:var(--mono);font-size:10.5px;color:var(--ink-faint);letter-spacing:.04em}

  /* filters */
  .filters{display:flex;gap:4px}
  .filters button{font-family:var(--sans);font-size:9.5px;font-weight:600;letter-spacing:.1em;
    text-transform:uppercase;color:var(--ink-faint);background:none;border:1px solid transparent;
    padding:4px 8px;border-radius:2px;cursor:pointer;transition:.15s}
  .filters button:hover{color:var(--ink-soft)}
  .filters button.on{color:var(--ink);border-color:var(--rule-2);background:var(--surface-2)}

  /* feed */
  .feed{max-height:560px;overflow-y:auto}
  .feed-row{display:grid;grid-template-columns:46px 1fr auto;gap:14px;align-items:center;
    padding:13px 18px;border-bottom:1px solid var(--rule)}
  .feed-row:last-child{border-bottom:0}
  .chip{font-family:var(--mono);font-size:12px;font-weight:700;text-align:center;
    padding:5px 0;border:1px solid var(--c,var(--ink-faint));color:var(--c,var(--ink));
    border-radius:2px;letter-spacing:.02em}
  .feed-label{font-weight:600;font-size:13.5px;letter-spacing:-.005em}
  .feed-detail{font-family:var(--mono);font-size:11px;color:var(--ink-faint);margin-top:3px;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
  .feed-meta{text-align:right;white-space:nowrap}
  .tag{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--c,var(--ink))}
  .time{display:block;font-family:var(--mono);font-size:10px;color:var(--ink-faint);margin-top:4px}
  .lv-CRITICAL{--c:var(--crit)} .lv-HIGH{--c:var(--high)} .lv-MEDIUM{--c:var(--med)}
  .lv-LOW{--c:var(--low)} .lv-INFO{--c:var(--info)}
  .empty{padding:48px 20px;text-align:center;color:var(--ink-faint);font-size:12.5px}

  /* system card body */
  .sys{padding:16px 18px}
  .prog-lbl{display:flex;justify-content:space-between;font-size:10px;letter-spacing:.1em;
    text-transform:uppercase;color:var(--ink-faint);font-weight:600;margin-bottom:7px}
  .prog{height:3px;background:var(--rule);border-radius:2px;overflow:hidden}
  .prog>i{display:block;height:100%;width:0;background:var(--ink);transition:width .6s ease}
  .mons{margin-top:16px;border-top:1px solid var(--rule);padding-top:6px}
  .mon{display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--rule)}
  .mon:last-child{border-bottom:0}
  .mon .n{font-size:11.5px;color:var(--ink-soft)}
  .mon .v{display:flex;align-items:center;gap:7px;font-family:var(--mono);font-size:11px;color:var(--ink)}
  .mdot{width:7px;height:7px;border-radius:50%;background:var(--ink-faint)}
  .mdot.ok{background:var(--low)} .mdot.no{background:var(--rule-2)}

  .metatab{margin-top:14px;width:100%;border-collapse:collapse;font-size:11px}
  .metatab td{padding:5px 0;border-bottom:1px solid var(--rule)}
  .metatab td:first-child{color:var(--ink-faint);letter-spacing:.04em}
  .metatab td:last-child{text-align:right;font-family:var(--mono);color:var(--ink)}
  .metatab tr:last-child td{border-bottom:0}

  .controls{display:flex;gap:8px;margin-top:16px}
  .btn{flex:1;font-family:var(--sans);font-size:10.5px;font-weight:600;letter-spacing:.08em;
    text-transform:uppercase;padding:10px 0;border:1px solid var(--ink);background:var(--ink);
    color:var(--paper);border-radius:2px;cursor:pointer;transition:.15s}
  .btn:hover{opacity:.85}
  .btn.ghost{background:none;color:var(--ink)}
  .btn.ghost:hover{background:var(--surface-2)}
  .btn:disabled{opacity:.3;cursor:not-allowed}
  .btn-wide{width:100%;margin-top:8px;font-family:var(--sans);font-size:10px;font-weight:600;
    letter-spacing:.1em;text-transform:uppercase;padding:9px 0;border:1px solid var(--rule-2);
    background:none;color:var(--ink-soft);border-radius:2px;cursor:pointer;transition:.15s}
  .btn-wide:hover{border-color:var(--ink);color:var(--ink)}

  /* traffic bars */
  .traf{padding:16px 18px}
  .traf-row{margin-bottom:13px}
  .traf-row:last-child{margin-bottom:0}
  .traf-top{display:flex;justify-content:space-between;font-size:10.5px;margin-bottom:5px}
  .traf-top .n{letter-spacing:.08em;text-transform:uppercase;color:var(--ink-faint);font-weight:600}
  .traf-top .v{font-family:var(--mono);color:var(--ink)}
  .bar{height:4px;background:var(--rule);border-radius:2px;overflow:hidden}
  .bar>i{display:block;height:100%;width:0;background:var(--ink-soft);transition:width .5s ease}
  .bar.syn>i{background:var(--low)} .bar.udp>i{background:var(--med)}
  .bar.icmp>i{background:var(--high)} .bar.tot>i{background:var(--ink)}

  /* sparkline */
  .spark-wrap{padding:14px 18px 16px}
  .spark-hd{font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-faint);
    font-weight:600;margin-bottom:8px}
  svg.spark{display:block;width:100%;height:40px}

  /* hourly chart */
  .hours{display:flex;align-items:flex-end;gap:3px;height:120px;padding:18px 18px 8px}
  .hcol{flex:1;display:flex;flex-direction:column-reverse;gap:1px;min-width:0;cursor:default}
  .hcol .seg{width:100%;border-radius:1px}
  .hcol .base{height:2px;background:var(--rule);border-radius:1px}
  .hours-x{display:flex;gap:3px;padding:0 18px 14px}
  .hours-x span{flex:1;text-align:center;font-family:var(--mono);font-size:8.5px;color:var(--ink-faint)}

  /* tables (alerts/attackers) */
  .tbl{width:100%;border-collapse:collapse;font-size:12px}
  .tbl thead th{text-align:left;font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;
    color:var(--ink-faint);font-weight:600;padding:12px 18px;border-bottom:1px solid var(--rule-2);background:var(--surface)}
  .tbl tbody td{padding:11px 18px;border-bottom:1px solid var(--rule);vertical-align:middle}
  .tbl tbody tr:last-child td{border-bottom:0}
  .tbl .mono{font-family:var(--mono);font-size:11px}
  .tbl .muted{color:var(--ink-faint)}
  .sev-pill{display:inline-block;font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
    padding:3px 8px;border:1px solid var(--c,var(--ink));color:var(--c,var(--ink));border-radius:2px}

  /* settings */
  .settings{max-width:620px}
  .field{margin-bottom:18px}
  .field label{display:block;font-size:10px;letter-spacing:.12em;text-transform:uppercase;
    color:var(--ink-faint);font-weight:600;margin-bottom:6px}
  .field input,.field select{width:100%;font-family:var(--mono);font-size:13px;color:var(--ink);
    background:var(--surface-2);border:1px solid var(--rule-2);border-radius:2px;padding:10px 12px;outline:none;transition:.15s}
  .field input:focus,.field select:focus{border-color:var(--ink)}
  .toggle{display:flex;align-items:center;gap:12px;cursor:pointer}
  .toggle input{width:auto}
  .switch{width:40px;height:22px;background:var(--rule-2);border-radius:11px;position:relative;transition:.2s;flex:none}
  .switch::after{content:'';position:absolute;top:2px;left:2px;width:18px;height:18px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 1px 2px rgba(0,0,0,.2)}
  .toggle input:checked + .switch{background:var(--ink)}
  .toggle input:checked + .switch::after{transform:translateX(18px)}
  .toggle .t-txt{font-size:13px;color:var(--ink)}
  .steps{counter-reset:s;margin:8px 0 0;padding:0;list-style:none}
  .steps li{counter-increment:s;position:relative;padding:8px 0 8px 30px;font-size:12.5px;color:var(--ink-soft);border-bottom:1px solid var(--rule)}
  .steps li:last-child{border-bottom:0}
  .steps li::before{content:counter(s);position:absolute;left:0;top:7px;width:20px;height:20px;
    border:1px solid var(--rule-2);border-radius:50%;font-family:var(--mono);font-size:10px;
    display:flex;align-items:center;justify-content:center;color:var(--ink)}
  .steps code{font-family:var(--mono);font-size:11.5px;background:var(--surface-2);border:1px solid var(--rule);padding:1px 5px;border-radius:2px}
  .flash{font-family:var(--mono);font-size:11.5px;margin-top:12px;min-height:16px;letter-spacing:.02em}
  .flash.ok{color:var(--low)} .flash.err{color:var(--crit)}
  .note{font-size:11.5px;color:var(--ink-faint);margin-top:14px;padding-top:14px;border-top:1px solid var(--rule);line-height:1.6}

  /* footer */
  .foot{margin-top:40px;padding-top:16px;border-top:2px solid var(--ink);
    display:flex;justify-content:space-between;font-size:10px;letter-spacing:.14em;
    text-transform:uppercase;color:var(--ink-faint)}

  .feed::-webkit-scrollbar,.settings::-webkit-scrollbar{width:8px}
  .feed::-webkit-scrollbar-thumb{background:var(--rule-2);border-radius:4px}
</style>
</head>
<body>
<div class="wrap">

  <header class="mast">
    <div class="mast-rule-top"></div>
    <div class="mast-head">
      <div class="brand">
        <h1>Ulinzi</h1>
        <div class="tag">Anomaly-Based Host Intrusion Detection System</div>
      </div>
      <div class="status-cluster">
        <div class="phase"><span class="dot" id="live-dot"></span><span id="phase">Connecting</span></div>
        <div class="uptime" id="uptime">--:--:--</div>
        <div class="clock" id="clock"></div>
      </div>
    </div>
    <div class="mast-rule"></div>
    <div class="dateline">
      <span>Strathmore University &middot; School of Computing &amp; Engineering Sciences</span>
      <span id="dateline-date"></span>
    </div>
    <div class="mast-rule-bot"></div>
  </header>

  <nav class="nav">
    <a class="on" data-page="overview" onclick="nav('overview',this)">Overview</a>
    <a data-page="alerts" onclick="nav('alerts',this)">Alert Log</a>
    <a data-page="attackers" onclick="nav('attackers',this)">Attackers</a>
    <a data-page="settings" onclick="nav('settings',this)">Settings</a>
  </nav>

  <!-- ============ OVERVIEW ============ -->
  <section class="page on" id="p-overview">
    <div class="kpis">
      <div class="kpi"><div class="lbl">Total Alerts</div><div class="val" id="k-total">0</div><div class="sub">since engine start</div></div>
      <div class="kpi crit"><div class="lbl">Critical</div><div class="val" id="k-crit">0</div><div class="sub">highest severity</div></div>
      <div class="kpi"><div class="lbl">Packets Inspected</div><div class="val" id="k-pkt">0</div><div class="sub">raw-socket capture</div></div>
      <div class="kpi"><div class="lbl">Active Rules</div><div class="val" id="k-rule">0 / 11</div><div class="sub">H1&ndash;H5 &middot; N1&ndash;N6</div></div>
    </div>

    <div class="ledger">
      <div class="seg"><span class="k">Crit</span><b id="sv-CRITICAL">0</b></div>
      <div class="seg"><span class="k">High</span><b id="sv-HIGH">0</b></div>
      <div class="seg"><span class="k">Med</span><b id="sv-MEDIUM">0</b></div>
      <div class="seg"><span class="k">Low</span><b id="sv-LOW">0</b></div>
      <div class="seg"><span class="k">Info</span><b id="sv-INFO">0</b></div>
      <div class="sp"></div>
      <div class="seg"><span class="k">Host</span><b id="cat-host">0</b></div>
      <div class="seg"><span class="k">Network</span><b id="cat-net">0</b></div>
    </div>

    <div class="grid">
      <div>
        <div class="card">
          <div class="card-hd">
            <h3>Live Alert Feed</h3>
            <div class="filters" id="filters">
              <button class="on" data-f="ALL" onclick="setFilter('ALL',this)">All</button>
              <button data-f="CRITICAL" onclick="setFilter('CRITICAL',this)">Critical</button>
              <button data-f="HIGH" onclick="setFilter('HIGH',this)">High</button>
              <button data-f="MEDIUM" onclick="setFilter('MEDIUM',this)">Medium</button>
              <button data-f="LOW" onclick="setFilter('LOW',this)">Low</button>
            </div>
          </div>
          <div class="feed" id="feed"><div class="empty">Connecting to engine&hellip;</div></div>
        </div>

        <div class="card">
          <div class="card-hd"><h3>Activity</h3><div class="meta">Alerts per hour &middot; last 24 h</div></div>
          <div class="hours" id="hours"></div>
          <div class="hours-x" id="hours-x"></div>
        </div>
      </div>

      <div>
        <div class="card">
          <div class="card-hd"><h3>System</h3></div>
          <div class="sys">
            <div class="prog-lbl"><span>Baseline learning</span><span id="bl-pct">0%</span></div>
            <div class="prog"><i id="bl-bar"></i></div>
            <div class="mons">
              <div class="mon"><span class="n">Auth log (H1&ndash;H2)</span><span class="v"><span class="mdot" id="d-auth"></span><span id="v-auth">&mdash;</span></span></div>
              <div class="mon"><span class="n">Process table (H3, H5)</span><span class="v"><span class="mdot" id="d-proc"></span><span id="v-proc">&mdash;</span></span></div>
              <div class="mon"><span class="n">File integrity (H4)</span><span class="v"><span class="mdot" id="d-fim"></span><span id="v-fim">&mdash;</span></span></div>
              <div class="mon"><span class="n">Network (N1&ndash;N6)</span><span class="v"><span class="mdot" id="d-net"></span><span id="v-net">&mdash;</span></span></div>
              <div class="mon"><span class="n">Push (ntfy)</span><span class="v"><span class="mdot" id="d-ntfy"></span><span id="v-ntfy">&mdash;</span></span></div>
            </div>
            <table class="metatab">
              <tr><td>Uptime</td><td id="mt-up">&mdash;</td></tr>
              <tr><td>Interface</td><td id="mt-if">&mdash;</td></tr>
              <tr><td>Window</td><td id="mt-win">&mdash;</td></tr>
              <tr><td>Baseline</td><td id="mt-base">&mdash;</td></tr>
            </table>
            <div class="controls">
              <button class="btn" id="btn-start" onclick="ctl('start')">Start</button>
              <button class="btn ghost" id="btn-stop" onclick="ctl('stop')">Stop</button>
            </div>
            <button class="btn-wide" onclick="ctl('clear')">Clear alert log</button>
          </div>
        </div>

        <div class="card">
          <div class="card-hd"><h3>Inbound Traffic</h3><div class="meta" id="traf-meta">per second</div></div>
          <div class="traf">
            <div class="traf-row"><div class="traf-top"><span class="n">SYN</span><span class="v" id="t-syn">0</span></div><div class="bar syn"><i id="b-syn"></i></div></div>
            <div class="traf-row"><div class="traf-top"><span class="n">UDP</span><span class="v" id="t-udp">0</span></div><div class="bar udp"><i id="b-udp"></i></div></div>
            <div class="traf-row"><div class="traf-top"><span class="n">ICMP</span><span class="v" id="t-icmp">0</span></div><div class="bar icmp"><i id="b-icmp"></i></div></div>
            <div class="traf-row"><div class="traf-top"><span class="n">Total</span><span class="v" id="t-tot">0</span></div><div class="bar tot"><i id="b-tot"></i></div></div>
          </div>
        </div>

        <div class="card">
          <div class="spark-wrap">
            <div class="spark-hd">Alert rate &middot; last 30 min</div>
            <svg class="spark" id="spark" viewBox="0 0 300 40" preserveAspectRatio="none"></svg>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- ============ ALERT LOG ============ -->
  <section class="page" id="p-alerts">
    <div class="card">
      <div class="card-hd"><h3>Alert Log</h3><div class="meta" id="alerts-meta">most recent 150</div></div>
      <table class="tbl">
        <thead><tr><th style="width:90px">Time</th><th style="width:54px">Rule</th><th>Detection</th><th style="width:90px">Severity</th><th style="width:130px">Source</th></tr></thead>
        <tbody id="alerts-body"><tr><td colspan="5" class="empty">Connecting&hellip;</td></tr></tbody>
      </table>
    </div>
  </section>

  <!-- ============ ATTACKERS ============ -->
  <section class="page" id="p-attackers">
    <div class="card">
      <div class="card-hd"><h3>Attacker Profile</h3><div class="meta">aggregated by source address</div></div>
      <table class="tbl">
        <thead><tr><th style="width:150px">Source IP</th><th style="width:80px">Events</th><th style="width:110px">Max Severity</th><th>Attack Types</th><th style="width:90px">First Seen</th><th style="width:90px">Last Seen</th></tr></thead>
        <tbody id="att-body"><tr><td colspan="6" class="empty">No attackers recorded yet.</td></tr></tbody>
      </table>
    </div>
  </section>

  <!-- ============ SETTINGS ============ -->
  <section class="page" id="p-settings">
    <div class="card settings">
      <div class="card-hd"><h3>Push Notifications</h3><div class="meta">ntfy.sh</div></div>
      <div class="sys">
        <div class="field">
          <label class="toggle"><input type="checkbox" id="s-enabled"><span class="switch"></span><span class="t-txt">Enable push notifications</span></label>
        </div>
        <div class="field"><label>Topic name</label><input id="s-topic" placeholder="ulinzi-alerts-yourname-9f2a"></div>
        <div class="field"><label>Server</label><input id="s-server" value="https://ntfy.sh"></div>
        <div class="field"><label>Minimum severity to push</label>
          <select id="s-min"><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select>
        </div>
        <div class="field"><label>Access token (optional)</label><input id="s-token" placeholder="leave blank for public topics"></div>
        <div class="controls">
          <button class="btn" onclick="saveCfg()">Save &amp; Apply</button>
          <button class="btn ghost" onclick="testNtfy()">Send Test</button>
        </div>
        <div class="flash" id="cfg-flash"></div>

        <ol class="steps">
          <li>Install the <code>ntfy</code> app on your phone (Play Store or App Store).</li>
          <li>In the app, add a subscription and enter the <b>exact</b> topic name above.</li>
          <li>Enable the toggle, set a topic, then press <code>Save &amp; Apply</code>.</li>
          <li>Press <code>Send Test</code> &mdash; the phone should receive it within ~2 seconds.</li>
        </ol>
        <div class="note">Topic names on the public ntfy.sh server are effectively passwords &mdash; anyone who knows the name can read the alerts. Use a long, random topic, or self-host ntfy for anything beyond a lab.</div>
      </div>
    </div>
  </section>

  <footer class="foot">
    <span>Ulinzi HIDS</span>
    <span>Reg. 193310 &middot; CNS 3104</span>
  </footer>
</div>

<script>
const RULE_CODE={brute_force:'H1',priv_escalation:'H2',proc_anomaly:'H3',file_integrity:'H4',
  susp_process:'H5',syn_flood:'N1',udp_flood:'N2',icmp_flood:'N3',port_scan:'N4',
  dns_tunnel:'N5',arp_spoof:'N6',engine:'SYS'};
const PHASE={stopped:'Stopped',baseline:'Learning baseline',detecting:'Detecting'};
const SEVC={CRITICAL:'var(--crit)',HIGH:'var(--high)',MEDIUM:'var(--med)',LOW:'var(--low)',INFO:'var(--info)'};
let FILTER='ALL', ALERTS=[];

function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function fmt(n){return (Number(n)||0).toLocaleString();}
function codeFor(rule){if(!rule)return '--';if(rule.indexOf('scan_')===0)return 'N4';return RULE_CODE[rule]||'--';}
function $(id){return document.getElementById(id);}
function setTxt(id,v){const e=$(id);if(e)e.textContent=v;}

function nav(p,el){document.querySelectorAll('.page').forEach(x=>x.classList.remove('on'));
  $('p-'+p).classList.add('on');
  document.querySelectorAll('.nav a').forEach(a=>a.classList.remove('on'));el.classList.add('on');}

function setFilter(f,el){FILTER=f;document.querySelectorAll('#filters button').forEach(b=>b.classList.remove('on'));
  el.classList.add('on');renderFeed();}

/* ---- clock ---- */
function tick(){const d=new Date();
  setTxt('clock',d.toLocaleTimeString('en-GB'));
  setTxt('dateline-date',d.toLocaleDateString('en-GB',{weekday:'long',day:'numeric',month:'long',year:'numeric'}).toUpperCase());}
setInterval(tick,1000);tick();

/* ---- controls ---- */
async function ctl(a){try{await fetch('/'+a,{method:'POST'});}catch(e){}setTimeout(poll,400);}

/* ---- renderers ---- */
function renderKPIs(m,s){
  const c=m.counts||{};
  const total=(c.CRITICAL||0)+(c.HIGH||0)+(c.MEDIUM||0)+(c.LOW||0);
  setTxt('k-total',fmt(total));
  setTxt('k-crit',fmt(c.CRITICAL||0));
  setTxt('k-pkt',fmt(s.packets_total||0));
  setTxt('k-rule',(s.active_rules==null?0:s.active_rules)+' / 11');
  ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].forEach(l=>setTxt('sv-'+l,fmt(c[l]||0)));
  const cat=m.cat||{};setTxt('cat-host',fmt(cat.host||0));setTxt('cat-net',fmt(cat.network||0));
}

function renderStatus(s){
  const ph=s.phase||'stopped';
  setTxt('phase',PHASE[ph]||ph);
  const dot=$('live-dot');dot.className='dot '+(ph==='detecting'?'on live':(ph==='baseline'?'warn live':'off'));
  setTxt('uptime',s.uptime||'--:--:--');
  let p=s.baseline_pct||0;if(p<=1)p*=100;p=Math.max(0,Math.min(100,p));
  $('bl-bar').style.width=p+'%';setTxt('bl-pct',Math.round(p)+'%');
  const m=s.monitors||{};
  const setMon=(d,v,on,txt)=>{$(d).className='mdot '+(on?'ok':'no');setTxt(v,txt);};
  setMon('d-auth','v-auth',!!m.auth_log,m.auth_log?'Active':'Off');
  setMon('d-proc','v-proc',!!m.psutil,m.psutil?'Active':'Off');
  setMon('d-fim','v-fim',(m.fim_files||0)>0,(m.fim_files||0)+' files');
  const iface=m.iface||'—';const netOk=!!s.running&&iface!=='—'&&String(iface).indexOf('N/A')<0;
  setMon('d-net','v-net',netOk,netOk?iface:'Disabled');
  setMon('d-ntfy','v-ntfy',!!m.ntfy,m.ntfy?'Active':'Off');
  setTxt('mt-up',s.uptime||'—');setTxt('mt-if',iface);
  setTxt('mt-win',(s.window_seconds==null?1:s.window_seconds)+'s');
  setTxt('mt-base',(s.baseline_seconds==null?60:s.baseline_seconds)+'s');
  $('btn-start').disabled=!!s.running;$('btn-stop').disabled=!s.running;
  // traffic
  const ns=s.last_ns||{};
  const bar=(id,bid,val,max)=>{setTxt(id,(val==null?0:val).toLocaleString());
    $(bid).style.width=Math.max(2,Math.min(100,(val/max)*100||0))+'%';};
  bar('t-syn','b-syn',ns.syn_rate,800);bar('t-udp','b-udp',ns.udp_rate,1500);
  bar('t-icmp','b-icmp',ns.icmp_rate,400);bar('t-tot','b-tot',ns.total_rate,3000);
}

function renderFeed(){
  const feed=$('feed');
  let rows=ALERTS.filter(a=>FILTER==='ALL'?true:a.level===FILTER);
  if(!rows.length){feed.innerHTML='<div class="empty">No alerts'+(FILTER==='ALL'?' yet. The system is monitoring.':' at this severity.')+'</div>';return;}
  feed.innerHTML=rows.slice(0,60).map(a=>{
    const lv=a.level||'INFO';const code=a.code||codeFor(a.rule);
    return '<div class="feed-row lv-'+lv+'">'+
      '<div class="chip">'+esc(code)+'</div>'+
      '<div><div class="feed-label">'+esc(a.label||a.rule)+'</div>'+
      '<div class="feed-detail">'+esc(a.detail||'')+'</div></div>'+
      '<div class="feed-meta"><span class="tag">'+esc(lv)+'</span>'+
      '<span class="time">'+esc((a.ts||'').slice(11))+'</span></div></div>';
  }).join('');
}

function renderAlertsTable(){
  const b=$('alerts-body');
  if(!ALERTS.length){b.innerHTML='<tr><td colspan="5" class="empty">No alerts yet.</td></tr>';return;}
  b.innerHTML=ALERTS.slice(0,150).map(a=>{
    const lv=a.level||'INFO';const code=a.code||codeFor(a.rule);
    return '<tr>'+
      '<td class="mono muted">'+esc((a.ts||'').slice(11))+'</td>'+
      '<td class="mono" style="color:'+(SEVC[lv]||'inherit')+';font-weight:700">'+esc(code)+'</td>'+
      '<td><b>'+esc(a.label||a.rule)+'</b><div class="mono muted" style="margin-top:2px">'+esc(a.detail||'')+'</div></td>'+
      '<td><span class="sev-pill lv-'+lv+'">'+esc(lv)+'</span></td>'+
      '<td class="mono muted">'+esc(a.src_ip||'local')+'</td></tr>';
  }).join('');
  setTxt('alerts-meta','showing '+Math.min(ALERTS.length,150)+' of most recent');
}

function renderAttackers(list){
  const b=$('att-body');
  if(!list||!list.length){b.innerHTML='<tr><td colspan="6" class="empty">No attackers recorded yet. Run an attack from VM2.</td></tr>';return;}
  b.innerHTML=list.map(a=>{
    let types=a.attack_types;try{const p=JSON.parse(types);if(Array.isArray(p))types=p.join(', ');}catch(e){}
    const lv=a.max_level||'INFO';
    return '<tr>'+
      '<td class="mono" style="font-weight:700">'+esc(a.ip)+'</td>'+
      '<td class="mono">'+esc(a.event_count)+'</td>'+
      '<td><span class="sev-pill lv-'+lv+'">'+esc(lv)+'</span></td>'+
      '<td>'+esc(types||'—')+'</td>'+
      '<td class="mono muted">'+esc((a.first_seen||'').slice(11)||'—')+'</td>'+
      '<td class="mono muted">'+esc((a.last_seen||'').slice(11)||'—')+'</td></tr>';
  }).join('');
}

function renderHours(data){
  const wrap=$('hours'),xs=$('hours-x');
  if(!data||!data.length){wrap.innerHTML='';return;}
  const max=Math.max(1,...data.map(d=>(d.CRITICAL||0)+(d.HIGH||0)+(d.MEDIUM||0)+(d.LOW||0)));
  const H=104;
  wrap.innerHTML=data.map(d=>{
    const segs=[['CRITICAL','var(--crit)'],['HIGH','var(--high)'],['MEDIUM','var(--med)'],['LOW','var(--low)']];
    const tot=(d.CRITICAL||0)+(d.HIGH||0)+(d.MEDIUM||0)+(d.LOW||0);
    let inner=segs.map(([k,c])=>{const v=d[k]||0;if(!v)return '';return '<div class="seg" style="height:'+(v/max*H)+'px;background:'+c+'"></div>';}).join('');
    if(!tot)inner='<div class="base"></div>';
    return '<div class="hcol" title="'+esc(d.hour)+' · '+tot+' alerts">'+inner+'</div>';
  }).join('');
  xs.innerHTML=data.map((d,i)=>'<span>'+(i%4===0?esc(d.hour):'')+'</span>').join('');
}

function renderSpark(arr){
  const svg=$('spark');if(!arr||!arr.length){svg.innerHTML='';return;}
  const W=300,H=40,max=Math.max(1,...arr),n=arr.length;
  const pts=arr.map((v,i)=>[i/(n-1)*W,H-2-(v/max)*(H-4)]);
  const line=pts.map((p,i)=>(i?'L':'M')+p[0].toFixed(1)+' '+p[1].toFixed(1)).join(' ');
  const area=line+' L'+W+' '+H+' L0 '+H+' Z';
  svg.innerHTML='<path d="'+area+'" fill="rgba(26,25,22,.06)"/>'+
    '<path d="'+line+'" fill="none" stroke="var(--ink)" stroke-width="1.5" stroke-linejoin="round"/>';
}

/* ---- settings ---- */
async function loadCfg(){try{const c=await(await fetch('/api/config')).json();
  $('s-enabled').checked=!!c.ntfy_enabled;$('s-topic').value=c.ntfy_topic||'';
  $('s-server').value=c.ntfy_server||'https://ntfy.sh';$('s-min').value=c.ntfy_min_level||'MEDIUM';
  $('s-token').value=c.ntfy_token||'';}catch(e){}}
async function saveCfg(){const fl=$('cfg-flash');fl.className='flash';fl.textContent='Saving…';
  const body={ntfy_enabled:$('s-enabled').checked,ntfy_topic:$('s-topic').value.trim(),
    ntfy_server:$('s-server').value.trim(),ntfy_min_level:$('s-min').value,ntfy_token:$('s-token').value.trim()};
  try{const d=await(await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();
    fl.className='flash '+(d.ok?'ok':'err');fl.textContent=d.ok?'Saved and applied.':('Error: '+(d.error||'failed'));}
  catch(e){fl.className='flash err';fl.textContent='Error: '+e;}}
async function testNtfy(){const fl=$('cfg-flash');fl.className='flash';fl.textContent='Sending test…';
  try{const d=await(await fetch('/api/test-notification',{method:'POST'})).json();
    fl.className='flash '+(d.ok?'ok':'err');fl.textContent=d.ok?'Test sent. Check your phone.':('Error: '+(d.error||'failed'));}
  catch(e){fl.className='flash err';fl.textContent='Error: '+e;}}

/* ---- poll loop ---- */
async function poll(){
  try{
    const [s,m,al,at,hr]=await Promise.all([
      fetch('/api/status').then(r=>r.json()),
      fetch('/api/metrics').then(r=>r.json()),
      fetch('/api/alerts?n=150').then(r=>r.json()),
      fetch('/api/attackers?n=25').then(r=>r.json()),
      fetch('/api/hourly').then(r=>r.json()),
    ]);
    renderStatus(s);renderKPIs(m,s);
    ALERTS=al.alerts||[];renderFeed();renderAlertsTable();
    renderAttackers(at.attackers||[]);
    renderHours(hr.data||[]);renderSpark(m.spark||[]);
  }catch(e){/* keep last view */}
}
loadCfg();poll();setInterval(poll,2500);
</script>
</body>
</html>"""



@app.get("/")
def index():
    return DASH_HTML


@app.post("/start")
def start():
    if not eng.is_running():
        eng.start_engine()
    return redirect(url_for("index"))


@app.post("/stop")
def stop():
    if eng.is_running():
        eng.stop_engine()
    return redirect(url_for("index"))


@app.post("/clear")
def clear():
    # The dashboard reads alerts from SQLite, so the database must be cleared --
    # rotating the log files alone leaves the feed and counters unchanged.
    try:
        eng.db_clear_alerts()
    except Exception:
        pass
    try:
        if os.path.exists(ALERT_LOG):
            os.replace(ALERT_LOG, ALERT_LOG + ".bak")
        if os.path.exists(eng.CFG.get("json_log", "alerts.jsonl")):
            os.replace(eng.CFG["json_log"], eng.CFG["json_log"] + ".bak")
    except OSError: pass
    return redirect(url_for("index"))


@app.get("/api/status")
def api_status():
    st = eng.get_state()
    ns = st.get("last_ns")
    ns_d = {}
    if ns:
        ns_d = {"syn_rate": round(ns.syn_rate, 1), "udp_rate": round(ns.udp_rate, 1),
                "icmp_rate": round(ns.icmp_rate, 1), "total_rate": round(ns.total_rate, 1)}
    return jsonify({
        "running": eng.is_running(),
        "phase": st.get("phase", "stopped"),
        "uptime": _uptime(),
        "windows": st.get("windows", 0),
        "packets_total": st.get("packets_total", 0),
        "active_rules": st.get("active_rules", 0),
        "baseline_pct": st.get("baseline_pct", 0.0),
        "window_seconds": eng.CFG.get("window_seconds", 1),
        "baseline_seconds": eng.CFG.get("baseline_seconds", 60),
        "last_ns": ns_d,
        "monitors": st.get("monitors", {}),
    })


@app.get("/api/alerts")
def api_alerts():
    n = min(int(request.args.get("n", 150)), 500)
    level = request.args.get("level")
    since = request.args.get("since_epoch", type=float)
    rows = eng.db_query_alerts(n=n, level_filter=level, since_epoch=since)
    return jsonify({"alerts": [_enrich(r) for r in rows]})


@app.get("/api/metrics")
def api_metrics():
    return jsonify({
        "counts": eng.db_counts(),
        "cat": eng.db_category_counts(),
        "spark": eng.db_spark(),
    })


@app.get("/api/hourly")
def api_hourly():
    return jsonify({"data": eng.db_hourly_activity(24)})


@app.get("/api/attackers")
def api_attackers():
    n = int(request.args.get("n", 20))
    return jsonify({"attackers": eng.db_top_attackers(n)})


@app.get("/api/config")
def api_config_get():
    safe = {k: v for k, v in eng.CFG.items()
            if k in ("ntfy_enabled", "ntfy_topic", "ntfy_server",
                     "ntfy_min_level", "ntfy_token")}
    return jsonify(safe)


@app.post("/api/config")
def api_config_post():
    data = request.get_json(force=True, silent=True) or {}
    allowed = {"ntfy_enabled", "ntfy_topic", "ntfy_server", "ntfy_min_level", "ntfy_token"}
    for k, v in data.items():
        if k in allowed:
            eng.CFG[k] = v
    try:
        if os.path.exists(eng.CONFIG_FILE):
            with open(eng.CONFIG_FILE) as fh: existing = json.load(fh)
        else:
            existing = dict(eng._DEFAULT_CONFIG)
        existing.update({k: v for k, v in data.items() if k in allowed})
        with open(eng.CONFIG_FILE, "w") as fh: json.dump(existing, fh, indent=2)
        eng.db_log_system("config_update", json.dumps({k: v for k, v in data.items() if k in allowed}))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.post("/api/test-notification")
def api_test_notification():
    import socket as _socket
    if not eng.REQUESTS_OK:
        return jsonify({"ok": False, "error": "requests library not installed"}), 400
    topic = eng.CFG.get("ntfy_topic", "")
    if not topic:
        return jsonify({"ok": False, "error": "No topic configured — set a topic first"}), 400
    ok = eng._send_ntfy("HIGH", "engine",
                         f"Ulinzi HIDS test notification — server is live at {_socket.gethostname()}",
                         datetime.now().strftime("%H:%M:%S"))
    if ok:
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "ntfy delivery failed — check topic/server"}), 500


if __name__ == "__main__":
    print(f"""
  --------------------------------------------------
   ULINZI HIDS  -  Strathmore University
  --------------------------------------------------
   Dashboard : http://127.0.0.1:{PORT}
   Phone/LAN : http://<this-VM-IP>:{PORT}
  --------------------------------------------------
""")
    app.run(host=HOST_BIND, port=PORT, debug=False, use_reloader=False, threaded=True)
