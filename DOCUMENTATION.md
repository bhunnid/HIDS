# Ulinzi HIDS — Usage & Two-VM Testing Guide

This guide walks you through running Ulinzi and validating **all 11 detection rules** using a
two–virtual-machine lab: one VM runs the HIDS, the other plays the attacker. Every command you
need is here, copy-paste ready.

---

## 1. Lab topology

```
        ┌──────────────────────────┐         host-only network         ┌──────────────────────────┐
        │   VM1  —  MONITOR         │         192.168.56.0/24           │   VM2  —  ATTACKER        │
        │   Kali Linux              │ <───────────────────────────────>│   Kali Linux              │
        │   runs:  Ulinzi HIDS      │                                   │   runs:  hydra / nmap /   │
        │   dashboard :5000         │                                   │          hping3 / arpspoof│
        │   IP e.g. 192.168.56.108  │                                   │   IP e.g. 192.168.56.109  │
        └──────────────────────────┘                                   └──────────────────────────┘
                   │
                   │  push notifications (ntfy.sh)
                   ▼
            📱  Your phone (ntfy app)
```

Both VMs sit on the **same host-only (or internal) network** so the attacker's traffic
actually reaches the monitor. Replace the example IPs below with your own.

---

## 2. One-time prerequisites

### 2.1 VirtualBox network

For each VM: **Settings → Network**. The simplest reliable setup:

- **Adapter 1** → *NAT* (gives the VM internet to install packages).
- **Adapter 2** → *Host-Only Adapter* (`vboxnet0`) — this is the isolated lab segment the
  two VMs talk over.

After booting, check the interface names and addresses on each VM:

```bash
ip -br addr
```

You'll typically see `eth0` (NAT) and `eth1` (host-only). **Use the host-only IP/interface**
for all testing. In the commands below, `$TARGET` is VM1's host-only IP.

### 2.2 Packages on VM2 (attacker)

```bash
sudo apt update
sudo apt install -y hydra nmap hping3 dnsutils dsniff
# dsniff provides arpspoof; dnsutils provides dig
```

`hydra`, `nmap`, and `hping3` ship with Kali by default, but this guarantees they're present.

---

## 3. Set up VM1 (the monitor)

### 3.1 Copy the project onto VM1

Put the `Ulinzi-HIDS` folder anywhere, e.g. `~/Ulinzi-HIDS`, and `cd` into it.

### 3.2 Install dependencies

```bash
cd ~/Ulinzi-HIDS
pip install -r requirements.txt --break-system-packages
```

(If you prefer a virtual environment: `python3 -m venv venv && source venv/bin/activate &&
pip install -r requirements.txt`, then start the engine with `sudo venv/bin/python app.py`.)

### 3.3 Enable the services the host-rule tests rely on

```bash
# auth.log — needed for H1 (brute-force) and H2 (privilege escalation)
sudo systemctl enable --now rsyslog

# SSH server — the target for the H1 hydra test
sudo systemctl enable --now ssh
```

> If `/var/log/auth.log` does not exist, Ulinzi automatically falls back to reading
> `journalctl`, so H1/H2 still work — but enabling `rsyslog` is the cleaner path.

### 3.4 Start Ulinzi

```bash
sudo python3 app.py
```

`sudo` matters: without it, raw-socket capture is disabled and the network rules **N1–N6**
won't run (the dashboard will warn you and show *Active Rules 5 / 11*).

### 3.5 Open the dashboard

- On VM1 itself: **http://localhost:5000**
- From your phone or laptop on the same network: **http://192.168.56.108:5000**
  (use VM1's host-only IP)

### 3.6 Find VM1's IP (this is your `$TARGET`)

```bash
ip -br addr | grep 192.168.56
```

---

## 4. Phone push notifications (optional but in the proposal)

1. Install the **ntfy** app (Android Play Store / iOS App Store).
2. Pick a unique, hard-to-guess topic name, e.g. `ulinzi-alerts-9f2a-brandon`.
3. On VM1, open `config.json` and set:
   ```json
   "ntfy_enabled": true,
   "ntfy_topic": "ulinzi-alerts-9f2a-brandon",
   "ntfy_min_level": "MEDIUM",
   ```
   Then restart Ulinzi (`Ctrl-C`, then `sudo python3 app.py` again).
   *(Or do it live from the dashboard: **Settings → Push Notifications**, enter the topic,
   enable, **Save & Apply**, then **Test Notification**.)*
4. In the ntfy app, **subscribe to the same topic name**.
5. Alerts at or above `ntfy_min_level` are pushed automatically during the tests.

---

## 5. Understand the two phases before you attack

When Ulinzi starts it shows **Baseline…** while it learns normal traffic/host rates
(`learning_window_seconds`, default 60 s). **Do not launch attacks during this window** — you'd
poison the baseline. Wait until the dashboard badge reads **Detecting**, then begin.

> For a realistic demo you can keep the 60 s baseline. For production the project recommends a
> much longer learning window (e.g. 600 s) so thresholds reflect a full daily cycle — change
> `learning_window_seconds` in `config.json`.

---

## 6. The attack playbook

Two groups:

- **Host attacks (H2–H5)** originate *on the host itself*, so you run them **on VM1**.
- **H1 and all network attacks (N1–N6)** are launched **from VM2** against VM1.

On **VM2**, set the target once per terminal:

```bash
export TARGET=192.168.56.108        # <-- VM1's host-only IP
```

### H1 — Brute-force login  *(run on VM2)*

```bash
# decompress the wordlist once:
sudo gunzip /usr/share/wordlists/rockyou.txt.gz   # skip if already done

hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$TARGET -t 4 -f
```
*Expected:* repeated SSH auth failures push the failure rate over the adaptive threshold →
**Brute-force** alert (LOW→CRITICAL as the rate climbs).

### H2 — Privilege escalation  *(run on VM1)*

```bash
for i in $(seq 1 30); do sudo -k -n true 2>/dev/null; sudo ls /root >/dev/null 2>&1; done
```
*Expected:* a burst of sudo/su events over the threshold → **Privilege Escalation** (HIGH/CRITICAL).

### H3 — Process-spawn anomaly  *(run on VM1)*

```bash
for i in $(seq 1 80); do (sleep 0.2 &) ; done
```
*Expected:* new-process spawn rate exceeds the baseline → **Process Anomaly** (LOW→CRITICAL).

### H4 — File-integrity violation  *(run on VM1)*

```bash
echo "10.0.0.99  evil.example.com" | sudo tee -a /etc/hosts
```
*Expected:* the SHA-256 of `/etc/hosts` changes → **File Tampered** (CRITICAL) within a few seconds.

**Restore afterwards:**
```bash
sudo sed -i '/evil.example.com/d' /etc/hosts
```

### H5 — Suspicious / reverse-shell process  *(run on VM1)*

```bash
nc -lvnp 4444 &        # a netcat listener; 'nc' is on the suspicious-process watchlist
# stop it when done:
kill %1 2>/dev/null
```
*Expected:* a watched process name / reverse-shell pattern → **Suspicious Process** (HIGH).

### N1 — SYN flood  *(run on VM2)*

```bash
sudo hping3 -S --flood -p 80 $TARGET
```

### N2 — UDP flood  *(run on VM2)*

```bash
sudo hping3 --udp --flood -p 9999 $TARGET
```

### N3 — ICMP flood  *(run on VM2)*

```bash
sudo hping3 --icmp --flood $TARGET
```

> The three floods are `--flood` (as fast as possible). Let each run **3–5 seconds**, then stop
> with `Ctrl-C`. Severity scales with the observed rate.

### N4 — Port scan  *(run on VM2)*

```bash
sudo nmap -sS -p 1-1000 --min-rate 500 $TARGET
```
*Expected:* one source hitting ≥ 20 distinct ports in a window → **Port Scan** (MEDIUM/HIGH).

### N5 — DNS tunnelling  *(run on VM2)*

```bash
for i in $(seq 1 300); do
  dig +tries=1 +time=1 @$TARGET "data$i.exfil.example.com" >/dev/null 2>&1 &
done; wait
```
*Expected:* a high rate of DNS queries from a single source → **DNS Tunneling** (MEDIUM/HIGH).
(The short `+tries/+time` keep it fast even though VM1 isn't a real DNS server.)

### N6 — ARP spoofing  *(run on VM2)*

First find VM2's host-only interface and the gateway, then poison VM1's ARP cache:

```bash
IFACE=$(ip -br addr | awk '/192.168.56/{print $1; exit}')
GW=$(ip route | awk '/default/{print $3; exit}')
sudo arpspoof -i "$IFACE" -t $TARGET "$GW"
```
*Expected:* Ulinzi sees the gateway's IP suddenly bound to a new (attacker) MAC, or a sustained
stream of unsolicited ARP replies → **ARP Spoofing** (HIGH). Stop with `Ctrl-C`.

> Ulinzi deliberately **ignores** ordinary/gratuitous ARP and the host's own announcements, so
> N6 only fires on the genuine cache-poisoning signature — no false alarms from normal traffic.

---

## 7. Where the alerts show up

Every detected anomaly appears in **all** of these at once:

1. **Dashboard** (`http://<VM1-IP>:5000`) — live feed, severity counters, the four KPI cards
   (Total Alerts · Critical · Packets Inspected · Active Rules), live traffic bars, and the
   **Attackers** tab.
2. **Phone** — ntfy push, if enabled (severity ≥ `ntfy_min_level`).
3. **`alerts.log`** — human-readable, one line per alert.
4. **`alerts.jsonl`** — structured JSON, one object per line (SIEM-friendly).
5. **`ulinzi.db`** — SQLite, queryable across restarts.

Inspect the logs/DB on VM1:

```bash
tail -f alerts.log
tail -f alerts.jsonl
sqlite3 ulinzi.db "SELECT ts, level, rule, detail FROM alerts ORDER BY id DESC LIMIT 20;"
sqlite3 ulinzi.db "SELECT ip, event_count, max_level, attack_types FROM attackers;"
```

---

## 8. Expected results at a glance

| Rule | Attack tool / action | Typical alert level |
|------|----------------------|---------------------|
| H1 | `hydra` SSH brute-force | HIGH / CRITICAL |
| H2 | sudo loop | HIGH / CRITICAL |
| H3 | process-spawn loop | LOW / MEDIUM |
| H4 | edit `/etc/hosts` | CRITICAL |
| H5 | `nc` listener | HIGH |
| N1 | `hping3 -S --flood` | HIGH / CRITICAL |
| N2 | `hping3 --udp --flood` | MEDIUM / HIGH |
| N3 | `hping3 --icmp --flood` | HIGH / CRITICAL |
| N4 | `nmap -sS` | MEDIUM / HIGH |
| N5 | DNS query flood | MEDIUM / HIGH |
| N6 | `arpspoof` | HIGH |

Exact level depends on the observed rate relative to your machine's learned baseline.

---

## 9. Configuration reference (`config.json`)

All behaviour is controlled here — **no code changes needed**. Edit, then restart Ulinzi.

| Key | Meaning |
|-----|---------|
| `interface` | Capture interface, or `null` to auto-detect the active one. |
| `learning_window_seconds` | Baseline learning duration (default 60). |
| `sampling_interval_seconds` | Detection window length in seconds (default 1). |
| `percentile_threshold` | Percentile of baseline used for adaptive thresholds (default 95). |
| `threshold_multiplier` | Safety multiplier applied to the percentile (default 3). |
| `confirm_windows` | Consecutive anomalous windows required before a volumetric alert. |
| `cooldown_secs` | Minimum gap between repeat alerts for the same rule. |
| `syn_ratio_threshold` | Min fraction of TCP that must be SYN for N1 (default 0.60). |
| `port_scan_distinct_ports` | Distinct ports from one source that trigger N4 (default 20). |
| `*_floor` | Lower bounds so quiet baselines can't make thresholds too sensitive. |
| `auth_fail_floor` / `sudo_event_floor` / `process_spawn_floor` | Host-rule floors. |
| `ntfy_enabled` / `ntfy_topic` / `ntfy_server` / `ntfy_min_level` / `ntfy_token` | Push settings. |
| `dashboard_host` / `dashboard_port` | Where the web dashboard binds (default `0.0.0.0:5000`). |
| `monitored_files` | Files watched for integrity changes (H4). |
| `alert_log` / `json_log` / `info_log` / `db_path` | Output file locations. |

> The config keys above are the proposal's names. The legacy names
> (`baseline_seconds`, `window_seconds`, `syn_ratio_min`, `port_scan_threshold`) are also
> accepted, and an old `ulinzi.conf` is read if no `config.json` is present.

**Security note:** `dashboard_host` defaults to `0.0.0.0` so your phone/laptop can reach the
dashboard during the demo. For anything beyond a trusted lab network, set it to `127.0.0.1`
(and put a reverse proxy with auth + TLS in front), per the project's hardening recommendation.

---

## 10. Build a standalone executable (PyInstaller)

Produces a single binary that runs on a clean Kali host with no Python install:

```bash
python3 build_exe.py
sudo ./dist/ulinzi          # or: sudo ./dist/run.sh
```

The build copies your `config.json` next to the binary in `dist/`.

---

## 11. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Dashboard shows *Active Rules 5 / 11* and a sudo warning | You started without `sudo`. Stop and run `sudo python3 app.py`. |
| No N1–N6 alerts | Confirm both VMs are on the **same host-only network** and `$TARGET` is VM1's host-only IP. Check `interface` in `config.json` (or leave it `null`). |
| No H1/H2 alerts | Ensure `rsyslog` (or `journalctl`) works and SSH is running for H1: `sudo systemctl status ssh rsyslog`. |
| Everything fires immediately on startup | You attacked during the baseline. Restart and wait for **Detecting**. |
| `hydra` can't find the wordlist | `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`. |
| `arpspoof: command not found` | `sudo apt install -y dsniff`. |
| Phone gets no push | Topic must match exactly in `config.json` and the ntfy app; alert severity must be ≥ `ntfy_min_level`; VM1 needs internet (NAT adapter). |
| Want a faster demo | Lower `learning_window_seconds` (e.g. 20) in `config.json`. |

---

## 12. Cleanup after testing

```bash
# on VM1 — restore the file you modified for H4
sudo sed -i '/evil.example.com/d' /etc/hosts

# stop any leftover netcat listener (H5)
pkill -f 'nc -lvnp 4444' 2>/dev/null

# on VM2 — stop any flood/arpspoof still running
sudo pkill hping3 2>/dev/null
sudo pkill arpspoof 2>/dev/null
```

`arpspoof` re-broadcasts the correct mapping automatically when you `Ctrl-C` it, restoring
VM1's ARP cache.

---

That's the full loop: start Ulinzi on VM1, wait for **Detecting**, fire each attack, and watch
the alerts land on the dashboard, your phone, and in the logs and database.
