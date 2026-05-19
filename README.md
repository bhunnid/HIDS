# Ulinzi HIDS

Lightweight anomaly-based Host Intrusion Detection System. Detects 11 attack types across host and network layers. Runs on Kali Linux with a browser-accessible dashboard and optional mobile push notifications via ntfy.sh.

---

## Setup — Monitor VM (VM1)

### 1. Install dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

### 2. Enable auth logging (if not already running)

```bash
sudo systemctl start rsyslog
sudo systemctl enable rsyslog
```

### 3. Run Ulinzi

```bash
sudo python3 app.py
```

Open the dashboard at `http://localhost:5000` or `http://<VM1-IP>:5000` from your phone.

The engine runs a **60-second baseline phase** on startup. Do not launch attacks during this window. Once the dashboard shows **Detecting**, begin testing.

### 4. Get your VM's IP (needed for attack commands)

```bash
ip addr show | grep "inet "
```

---

## Attack Simulation — Attacker VM (VM2)

Set the target IP once, then run any combination of attacks below.

```bash
export TARGET=<VM1-IP>
```

### H1 — Brute-force SSH (requires SSH running on VM1)

```bash
# Start SSH on VM1 first:
sudo systemctl start ssh

# Then from VM2:
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$TARGET -t 8 -f
```

### H2 — Privilege escalation (run ON VM1)

```bash
for i in $(seq 1 30); do sudo ls /root 2>/dev/null; done
```

### H3 — Process spawn anomaly (run ON VM1)

```bash
for i in $(seq 1 60); do (sleep 0.1 &); done
```

### H4 — File integrity violation (run ON VM1)

```bash
echo "10.0.0.99 malicious.local" | sudo tee -a /etc/hosts
# Restore after detection:
sudo sed -i '/malicious.local/d' /etc/hosts
```

### H5 — Suspicious process (run ON VM1)

```bash
which nc && nc -lvp 4444 &
```

### N1 — SYN flood

```bash
sudo hping3 -S --flood -p 80 $TARGET
```

### N2 — UDP flood

```bash
sudo hping3 --udp --flood -p 53 $TARGET
```

### N3 — ICMP flood

```bash
sudo hping3 --icmp --flood $TARGET
```

### N4 — Port scan

```bash
sudo nmap -sS -p 1-1000 --min-rate 500 $TARGET
```

### N5 — DNS tunneling simulation

```bash
for i in $(seq 1 200); do dig @$TARGET google.com & done; wait
```

### N6 — ARP spoofing

```bash
sudo arpspoof -i eth0 -t $TARGET $(ip route | awk '/default/{print $3}')
```

---

## Push Notifications (optional)

1. Install the **ntfy** app on your phone (Android/iOS).
2. Open the dashboard → **Settings** tab.
3. Enter a unique topic name, enable notifications, click **Save & Apply**.
4. In the ntfy app, subscribe to the same topic name.
5. Click **Test Notification** to verify.

---

## Build a standalone executable (optional)

```bash
python3 build_exe.py
sudo ./dist/ulinzi
```

---

## Detection Rules Reference

| Rule | Category | Trigger |
|------|----------|---------|
| H1 | Brute-force Login | Auth failure rate > adaptive threshold |
| H2 | Privilege Escalation | sudo/su event rate > adaptive threshold |
| H3 | Process Anomaly | New process spawn rate > adaptive threshold |
| H4 | File Integrity | SHA-256 change on monitored critical files |
| H5 | Suspicious Process | Known malicious process name or reverse shell |
| N1 | SYN Flood | SYN rate > threshold AND >60% of TCP are SYN |
| N2 | UDP Flood | Inbound UDP rate > threshold |
| N3 | ICMP Flood | Inbound ICMP rate > threshold |
| N4 | Port Scan | Single source hits ≥20 distinct ports in 1 window |
| N5 | DNS Tunneling | High DNS query rate from single source |
| N6 | ARP Spoofing | ARP reply without prior ARP request within 5s |

Rules N1–N6 require root (`sudo`) for raw socket capture. H1–H5 work without root.

---

## Output Files

| File | Contents |
|------|----------|
| `alerts.log` | Plain-text alert log |
| `alerts.jsonl` | Structured JSON alert log (one entry per line) |
| `hids.log` | Engine operational log |
| `ulinzi.db` | SQLite database (alerts, attackers, incidents) |
