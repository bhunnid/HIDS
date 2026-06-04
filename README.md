# Ulinzi HIDS

**Ulinzi** is a lightweight, anomaly-based **Host Intrusion Detection System** written in
Python. It watches a single Linux host in real time and raises alerts when activity deviates
from a baseline of normal behaviour — no machine learning, no signatures, no heavy agent.

It detects **11 attack types** across the host and the network, shows them on a live web
dashboard, persists them to SQLite, writes plain-text + JSON logs, and (optionally) pushes
high-severity alerts to your phone via [ntfy.sh](https://ntfy.sh).

> Built for the final-year project *"Ulinzi: A Lightweight Anomaly-Based Host Intrusion
> Detection System"* (Strathmore University, School of Computing & Engineering Sciences).

---

## What it detects

| | Host rules | | Network rules |
|---|---|---|---|
| **H1** | Brute-force login | **N1** | SYN flood |
| **H2** | Privilege escalation | **N2** | UDP flood |
| **H3** | Process-spawn anomaly | **N3** | ICMP flood |
| **H4** | File-integrity violation (SHA-256) | **N4** | Port scan |
| **H5** | Suspicious / reverse-shell process | **N5** | DNS tunnelling |
| | | **N6** | ARP spoofing |

Host rules (H1–H5) run as a normal user. Network rules (N1–N6) need `sudo` for raw-socket
packet capture.

---

## Quick start

```bash
# 1. install dependencies
pip install -r requirements.txt --break-system-packages

# 2. run (sudo enables the network rules N1–N6)
sudo python3 app.py
```

Then open the dashboard at **http://localhost:5000** (or `http://<this-VM-IP>:5000` from
your phone).

On startup the engine runs a short **learning phase** (60 s by default) during which it
builds its baselines and raises no alerts. Once the dashboard shows **Detecting**, it is live.

---

## Files

| File | Purpose |
|------|---------|
| `app.py` | Flask web dashboard + entry point |
| `hids_engine.py` | Detection engine (all 11 rules, baseline, persistence, ntfy) |
| `config.json` | All detection parameters and monitored targets — edit, no code changes |
| `build_exe.py` | Builds a standalone executable with PyInstaller |
| `requirements.txt` | Python dependencies |
| `DOCUMENTATION.md` | **Full guide: two-Kali-VM lab setup + every attack command** |

Runtime output (created on first run): `alerts.log`, `alerts.jsonl`, `hids.log`, `ulinzi.db`.

---

## Full testing guide

For the complete two-virtual-machine attack lab — VM setup, the exact `hydra` / `nmap` /
`hping3` / `arpspoof` commands for each rule, ntfy phone setup, and troubleshooting — see
**[DOCUMENTATION.md](DOCUMENTATION.md)**.
