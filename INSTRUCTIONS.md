# Ulinzi HIDS — Test Instructions

## VM Setup

| VM | Role | IP |
|----|------|----|
| VM1 | Monitor (runs HIDS) | 192.168.56.108 |
| VM2 | Attacker | 192.168.56.109 |

---

## VM1 — Start the HIDS

### 1. Install rsyslog (if not already done)

```bash
sudo apt update && sudo apt install rsyslog -y
sudo systemctl enable rsyslog && sudo systemctl start rsyslog
```

### 2. Enable SSH (required for H1 brute-force test)

```bash
sudo systemctl enable ssh && sudo systemctl start ssh
```

### 3. Activate virtualenv and start HIDS

```bash
cd ~/ulinzi
source venv/bin/activate
sudo venv/bin/python app.py
```

Open the dashboard in a browser: `http://192.168.56.108:5000`

**Wait for the dashboard to show "Detecting" (60-second baseline). Do NOT run any attacks until then.**

### 4. Push notifications

- Install the **ntfy** app on your phone (Android / iOS).
- Subscribe to topic: `thisisulinzihidsntfytopicsoexpectnotifcations`
- The HIDS will push alerts automatically once attacks are detected.

---

## VM2 — Set Target IP

Run this once before any attack:

```bash
export TARGET=192.168.56.108
```

---

## VM2 — Attack Commands

### H1 — Brute-force SSH

```bash
# Decompress wordlist first (only needed once):
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Run brute-force:
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$TARGET -t 8 -f
```

### N1 — SYN Flood

```bash
sudo hping3 -S --flood -p 80 $TARGET
```

### N2 — UDP Flood

```bash
sudo hping3 --udp --flood -p 53 $TARGET
```

### N3 — ICMP Flood

```bash
sudo hping3 --icmp --flood $TARGET
```

### N4 — Port Scan

```bash
sudo nmap -sS -p 1-1000 --min-rate 500 $TARGET
```

### N5 — DNS Tunneling Simulation

```bash
for i in $(seq 1 200); do dig @$TARGET google.com & done; wait
```

### N6 — ARP Spoofing

```bash
sudo arpspoof -i eth1 -t $TARGET $(ip route | awk '/default/{print $3}')
```

---

## VM1 — Host-Based Attack Commands (run directly on VM1)

### H2 — Privilege Escalation

```bash
for i in $(seq 1 30); do sudo ls /root 2>/dev/null; done
```

### H3 — Process Spawn Anomaly

```bash
for i in $(seq 1 60); do (sleep 0.1 &); done
```

### H4 — File Integrity Violation

```bash
echo "10.0.0.99 malicious.local" | sudo tee -a /etc/hosts
# Restore after detection:
sudo sed -i '/malicious.local/d' /etc/hosts
```

### H5 — Suspicious Process (Reverse Shell Listener)

```bash
which nc && nc -lvp 4444 &
```

---

## What to Expect

| Rule | Attack | Expected Alert Level |
|------|--------|----------------------|
| H1 | Hydra SSH brute-force | HIGH / CRITICAL |
| H2 | sudo loop | HIGH / CRITICAL |
| H3 | Process spawn loop | MEDIUM / HIGH |
| H4 | /etc/hosts modification | CRITICAL |
| H5 | netcat listener | HIGH |
| N1 | SYN flood | HIGH / CRITICAL |
| N2 | UDP flood | MEDIUM / HIGH |
| N3 | ICMP flood | HIGH / CRITICAL |
| N4 | Port scan | MEDIUM |
| N5 | DNS tunneling | MEDIUM / HIGH |
| N6 | ARP spoofing | HIGH / CRITICAL |

Alerts appear in:
- Dashboard at `http://192.168.56.108:5000`
- ntfy app (topic: `thisisulinzihidsntfytopicsoexpectnotifcations`)
- `~/ulinzi/alerts.log`
- `~/ulinzi/alerts.jsonl`
