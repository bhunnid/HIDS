# Ulinzi HIDS

**Ulinzi** is a lightweight, anomaly-based **Host Intrusion Detection System** for Linux.
It learns a baseline of normal host and network behaviour, then raises real-time alerts when
activity deviates from that baseline

It detects **11 attack types**, shows them on a clean real-time web dashboard, persists them to
SQLite, writes plain-text and JSON logs and pushes high-severity alerts to your phone via
[ntfy.sh](https://ntfy.sh).
---

## Detection coverage

| Host rules (H) | detector | Network rules (N) | detector |
|---|---|---|---|
| **H1** Brute-force login | auth log | **N1** SYN flood | raw socket |
| **H2** Privilege escalation | sudo / su rate | **N2** UDP flood | raw socket |
| **H3** Process-spawn anomaly | process table | **N3** ICMP flood | raw socket |
| **H4** File-integrity violation | SHA-256 hashing | **N4** Port scan | raw socket |
| **H5** Suspicious process | reverse-shell match | **N5** DNS tunnelling | raw socket |
| | | **N6** ARP spoofing | raw socket |

Host rules run as any user; network rules need `sudo` for raw-socket packet capture.
