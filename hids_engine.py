from __future__ import annotations

import os, re, sys, time, signal, socket, struct, hashlib, json, sqlite3
import logging, subprocess, threading, collections, ipaddress
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    import requests as _req
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# --- Config ------------------------------------------------------------------

_DEFAULT_CONFIG: Dict[str, Any] = {
    "interface":             None,
    "baseline_seconds":      60,
    "window_seconds":        1,
    "percentile_threshold":  95,
    "threshold_multiplier":  3,
    "confirm_windows":       2,
    "cooldown_secs":         30,
    "file_check_interval":   5,
    "syn_floor":             100,
    "udp_floor":             500,
    "icmp_floor":            50,
    "total_floor":           800,
    "syn_ratio_min":         0.60,
    "port_scan_threshold":   20,
    "dns_query_floor":       50,
    "auth_fail_floor":       3,
    "sudo_event_floor":      5,
    "process_spawn_floor":   20,
    "ntfy_enabled":          False,
    "ntfy_topic":            "ulinzi-hids-alerts",
    "ntfy_server":           "https://ntfy.sh",
    "ntfy_min_level":        "MEDIUM",
    "ntfy_token":            "",
    "alert_log":             "alerts.log",
    "json_log":              "alerts.jsonl",
    "info_log":              "hids.log",
    "db_path":               "ulinzi.db",
    "dashboard_host":        "0.0.0.0",
    "dashboard_port":        5000,
    "monitored_files": [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/hosts", "/etc/ssh/sshd_config", "/etc/crontab",
    ],
}

# The proposal (Appendix D) documents the configuration file as config.json with
# human-readable key names. The engine reads config.json first and falls back to
# the legacy ulinzi.conf if config.json is absent. Either key naming works.
CONFIG_CANDIDATES = ("config.json", "ulinzi.conf")
CONFIG_FILE = "config.json"

# Map the proposal's documented (config.json) key names to the engine's internal
# names, so a config file written in either style is accepted transparently.
_CONFIG_ALIASES = {
    "learning_window_seconds":  "baseline_seconds",
    "sampling_interval_seconds": "window_seconds",
    "syn_ratio_threshold":      "syn_ratio_min",
    "port_scan_distinct_ports": "port_scan_threshold",
}

CFG: Dict[str, Any] = dict(_DEFAULT_CONFIG)


def _normalize_config(cfg: Dict[str, Any]) -> None:
    """Translate proposal-style keys (config.json) into internal keys in place."""
    for alias, internal in _CONFIG_ALIASES.items():
        if alias in cfg:
            cfg[internal] = cfg[alias]


def load_config() -> None:
    global CFG, CONFIG_FILE
    CFG = dict(_DEFAULT_CONFIG)
    for cand in CONFIG_CANDIDATES:
        if os.path.exists(cand):
            CONFIG_FILE = cand
            try:
                with open(cand) as fh:
                    CFG.update(json.load(fh))
            except Exception as e:
                print(f"[config] Warning: {e}")
            break
    _normalize_config(CFG)


def save_default_config() -> None:
    if not any(os.path.exists(c) for c in CONFIG_CANDIDATES):
        with open(CONFIG_FILE, "w") as fh:
            json.dump(_DEFAULT_CONFIG, fh, indent=2)


# --- Severity ----------------------------------------------------------------

_RULE_BASE_SCORE: Dict[str, int] = {
    "brute_force": 55, "priv_escalation": 75, "proc_anomaly": 45,
    "file_integrity": 90, "susp_process": 80, "syn_flood": 60,
    "udp_flood": 50, "icmp_flood": 45, "port_scan": 55,
    "dns_tunnel": 65, "arp_spoof": 70, "engine": 5,
}

_LEVEL_MULTIPLIER = {
    "CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4, "INFO": 0.05,
}

_LEVEL_PUSH_PRIORITY = {
    "CRITICAL": "urgent", "HIGH": "high", "MEDIUM": "default",
    "LOW": "low", "INFO": "min",
}

_PUSH_LEVEL_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_score(rule: str, level: str) -> int:
    base_rule = rule[5:] if rule.startswith("scan_") else rule
    base = _RULE_BASE_SCORE.get(base_rule, 40)
    return min(100, int(base * _LEVEL_MULTIPLIER.get(level, 0.5)))


def rate_to_level(value: float, floor: float) -> str:
    r = value / max(floor, 1)
    if r >= 10: return "CRITICAL"
    if r >= 5:  return "HIGH"
    if r >= 2.5: return "MEDIUM"
    return "LOW"


# --- Logging -----------------------------------------------------------------

def _setup_logging() -> None:
    fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    fh = RotatingFileHandler(CFG["info_log"], maxBytes=5_000_000, backupCount=3)
    fh.setLevel(logging.DEBUG); fh.setFormatter(fmt); root.addHandler(fh)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO); ch.setFormatter(fmt); root.addHandler(ch)


_logging_ready = False
log = logging.getLogger("hids")


def _ensure_logging():
    global _logging_ready
    if not _logging_ready:
        _setup_logging()
        _logging_ready = True


# --- Database ----------------------------------------------------------------

_db_lock = threading.Lock()
_db_conn: Optional[sqlite3.Connection] = None


def _get_db() -> sqlite3.Connection:
    global _db_conn
    if _db_conn is None:
        _db_conn = sqlite3.connect(CFG["db_path"], check_same_thread=False)
        _db_conn.row_factory = sqlite3.Row
        _db_conn.execute("PRAGMA journal_mode=WAL")
        _db_conn.execute("PRAGMA synchronous=NORMAL")
    return _db_conn


def init_db() -> None:
    with _db_lock:
        db = _get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT    NOT NULL,
                ts_epoch    REAL    NOT NULL,
                level       TEXT    NOT NULL,
                rule        TEXT    NOT NULL,
                detail      TEXT    NOT NULL,
                score       INTEGER NOT NULL DEFAULT 0,
                src_ip      TEXT,
                attack_type TEXT,
                notified    INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ts    ON alerts(ts_epoch DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level);
            CREATE INDEX IF NOT EXISTS idx_alerts_rule  ON alerts(rule);
            CREATE INDEX IF NOT EXISTS idx_alerts_ip    ON alerts(src_ip);

            CREATE TABLE IF NOT EXISTS attackers (
                ip           TEXT PRIMARY KEY,
                first_seen   TEXT NOT NULL,
                last_seen    TEXT NOT NULL,
                event_count  INTEGER NOT NULL DEFAULT 0,
                attack_types TEXT NOT NULL DEFAULT '[]',
                max_level    TEXT NOT NULL DEFAULT 'LOW'
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                started      TEXT NOT NULL,
                ended        TEXT,
                src_ip       TEXT,
                attack_types TEXT NOT NULL DEFAULT '[]',
                alert_count  INTEGER NOT NULL DEFAULT 0,
                max_score    INTEGER NOT NULL DEFAULT 0,
                status       TEXT NOT NULL DEFAULT 'open'
            );

            CREATE TABLE IF NOT EXISTS system_log (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      TEXT NOT NULL,
                event   TEXT NOT NULL,
                detail  TEXT
            );
        """)
        db.commit()


def _extract_src_ip(rule: str, detail: str) -> Optional[str]:
    if rule.startswith("scan_"):
        return rule[5:]
    m = re.search(r"src=(\d+\.\d+\.\d+\.\d+)", detail)
    if m: return m.group(1)
    return None


def _attack_type_for_rule(rule: str) -> str:
    mapping = {
        "brute_force": "brute_force", "priv_escalation": "privilege_escalation",
        "proc_anomaly": "process_anomaly", "file_integrity": "file_tampering",
        "susp_process": "suspicious_process", "syn_flood": "syn_flood",
        "udp_flood": "udp_flood", "icmp_flood": "icmp_flood",
        "dns_tunnel": "dns_tunneling", "arp_spoof": "arp_spoofing",
    }
    if rule.startswith("scan_"): return "port_scan"
    return mapping.get(rule, rule)


def db_insert_alert(ts: str, ts_epoch: float, level: str, rule: str,
                    detail: str, score: int, src_ip: Optional[str] = None) -> int:
    attack_type = _attack_type_for_rule(rule)
    with _db_lock:
        db = _get_db()
        cur = db.execute(
            "INSERT INTO alerts (ts,ts_epoch,level,rule,detail,score,src_ip,attack_type,notified)"
            " VALUES (?,?,?,?,?,?,?,?,0)",
            (ts, ts_epoch, level, rule, detail, score, src_ip, attack_type)
        )
        alert_id = cur.lastrowid
        if src_ip:
            row = db.execute("SELECT * FROM attackers WHERE ip=?", (src_ip,)).fetchone()
            if row:
                types = json.loads(row["attack_types"])
                if attack_type not in types: types.append(attack_type)
                levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                max_lv = row["max_level"]
                if level in levels and max_lv in levels:
                    if levels.index(level) > levels.index(max_lv): max_lv = level
                db.execute(
                    "UPDATE attackers SET last_seen=?,event_count=event_count+1,"
                    "attack_types=?,max_level=? WHERE ip=?",
                    (ts, json.dumps(types), max_lv, src_ip)
                )
            else:
                db.execute(
                    "INSERT INTO attackers (ip,first_seen,last_seen,event_count,attack_types,max_level)"
                    " VALUES (?,?,?,1,?,?)",
                    (src_ip, ts, ts, json.dumps([attack_type]), level)
                )
        db.commit()
        return alert_id


def db_query_alerts(n: int = 200, level_filter: Optional[str] = None,
                    rule_filter: Optional[str] = None,
                    since_epoch: Optional[float] = None) -> List[Dict]:
    with _db_lock:
        db = _get_db()
        q = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []
        if level_filter and level_filter != "ALL":
            q += " AND level=?"; params.append(level_filter)
        if rule_filter:
            q += " AND (rule=? OR rule LIKE ?)"; params += [rule_filter, "scan_%"]
        if since_epoch:
            q += " AND ts_epoch>?"; params.append(since_epoch)
        q += " ORDER BY ts_epoch DESC LIMIT ?"
        params.append(n)
        return [dict(r) for r in db.execute(q, params).fetchall()]


def db_counts() -> Dict[str, int]:
    with _db_lock:
        db = _get_db()
        rows = db.execute(
            "SELECT level, COUNT(*) as c FROM alerts GROUP BY level"
        ).fetchall()
        c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": 0}
        for r in rows:
            if r["level"] in c: c[r["level"]] = r["c"]
        c["TOTAL"] = sum(v for k, v in c.items() if k != "TOTAL")
        return c


def db_top_attackers(n: int = 10) -> List[Dict]:
    with _db_lock:
        db = _get_db()
        rows = db.execute(
            "SELECT * FROM attackers ORDER BY event_count DESC LIMIT ?", (n,)
        ).fetchall()
        return [dict(r) for r in rows]


def db_spark(buckets: int = 30, secs_per_bucket: int = 60) -> List[int]:
    now = time.time()
    start = now - buckets * secs_per_bucket
    with _db_lock:
        db = _get_db()
        rows = db.execute(
            "SELECT ts_epoch FROM alerts WHERE ts_epoch>? AND level!='INFO'",
            (start,)
        ).fetchall()
    result = [0] * buckets
    for r in rows:
        idx = int((now - r["ts_epoch"]) / secs_per_bucket)
        if 0 <= idx < buckets: result[idx] += 1
    return list(reversed(result))


def db_category_counts() -> Dict[str, int]:
    host_types = {"brute_force", "privilege_escalation", "process_anomaly",
                  "file_tampering", "suspicious_process"}
    net_types = {"syn_flood", "udp_flood", "icmp_flood", "port_scan",
                 "dns_tunneling", "arp_spoofing"}
    with _db_lock:
        db = _get_db()
        rows = db.execute(
            "SELECT attack_type, COUNT(*) as c FROM alerts "
            "WHERE level!='INFO' GROUP BY attack_type"
        ).fetchall()
    h = n = 0
    for r in rows:
        if r["attack_type"] in host_types: h += r["c"]
        elif r["attack_type"] in net_types: n += r["c"]
    return {"host": h, "network": n}


def db_hourly_activity(hours: int = 24) -> List[Dict]:
    now = time.time()
    with _db_lock:
        db = _get_db()
        rows = db.execute(
            "SELECT ts_epoch, level FROM alerts "
            "WHERE ts_epoch > ? AND level != 'INFO'",
            (now - hours * 3600,)
        ).fetchall()
    buckets: Dict[int, Dict[str, int]] = {}
    for r in rows:
        h = int((now - r["ts_epoch"]) / 3600)
        if h >= hours: continue
        buckets.setdefault(h, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
        lv = r["level"]
        if lv in buckets[h]: buckets[h][lv] += 1
    result = []
    for i in range(hours - 1, -1, -1):
        t = datetime.fromtimestamp(now - i * 3600)
        b = buckets.get(i, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
        result.append({"hour": t.strftime("%H:00"), **b})
    return result


def db_log_system(event: str, detail: str = "") -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _db_lock:
        db = _get_db()
        db.execute("INSERT INTO system_log (ts,event,detail) VALUES (?,?,?)",
                   (ts, event, detail))
        db.commit()


# --- Push Notifications ------------------------------------------------------

_notify_queue: List[Dict] = []
_notify_lock = threading.Lock()

_LEVEL_EMOJI = {
    "CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️",
}

_RULE_EMOJI = {
    "brute_force": "🔑", "priv_escalation": "⬆️", "proc_anomaly": "⚙️",
    "file_integrity": "📄", "susp_process": "👾", "syn_flood": "🌊",
    "udp_flood": "🌊", "icmp_flood": "🏓", "dns_tunnel": "🔮", "arp_spoof": "🎭",
}


def _should_push(level: str) -> bool:
    if not CFG.get("ntfy_enabled"): return False
    if not REQUESTS_OK: return False
    min_level = CFG.get("ntfy_min_level", "MEDIUM")
    return _PUSH_LEVEL_ORDER.index(level) >= _PUSH_LEVEL_ORDER.index(min_level)


def queue_notification(level: str, rule: str, detail: str) -> None:
    if not _should_push(level): return
    with _notify_lock:
        _notify_queue.append({"level": level, "rule": rule, "detail": detail,
                               "ts": datetime.now().strftime("%H:%M:%S")})


def _send_ntfy(level: str, rule: str, detail: str, ts: str) -> bool:
    topic = CFG.get("ntfy_topic", "ulinzi-hids-alerts")
    server = CFG.get("ntfy_server", "https://ntfy.sh").rstrip("/")
    token = CFG.get("ntfy_token", "")
    url = f"{server}/{topic}"

    display_rule = rule[5:] if rule.startswith("scan_") else rule
    rule_emoji = _RULE_EMOJI.get(display_rule, "⚠️")
    lv_emoji = _LEVEL_EMOJI.get(level, "⚠️")
    priority = _LEVEL_PUSH_PRIORITY.get(level, "default")
    title = f"{lv_emoji} {level} — {display_rule.replace('_', ' ').title()}"
    message = f"{rule_emoji} {detail}\n⏱ {ts}"

    headers = {
        "Title": title,
        "Priority": priority,
        "Tags": f"warning,ulinzi,{display_rule}",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = _req.post(url, data=message.encode(), headers=headers, timeout=8)
        return resp.status_code in (200, 201)
    except Exception as e:
        log.debug("ntfy send failed: %s", e)
        return False


class NotificationWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="ntfy_worker")
        self._stop = threading.Event()

    def run(self):
        while not self._stop.wait(2.0):
            with _notify_lock:
                batch = list(_notify_queue); _notify_queue.clear()
            for item in batch:
                ok = _send_ntfy(item["level"], item["rule"], item["detail"], item["ts"])
                log.debug("ntfy %s: %s", "OK" if ok else "FAIL", item["rule"])

    def stop(self): self._stop.set()


# --- Alert Writer ------------------------------------------------------------

def write_alert(level: str, rule: str, detail: str) -> int:
    now = datetime.now()
    ts = now.strftime("%Y-%m-%d %H:%M:%S")
    epoch = now.timestamp()
    score = severity_score(rule, level)
    src_ip = _extract_src_ip(rule, detail)

    line = f"[{ts}] LEVEL:{level} RULE:{rule} | {detail}"
    try:
        with open(CFG["alert_log"], "a") as fh:
            fh.write(line + "\n")
    except OSError: pass

    jline = json.dumps({
        "ts": ts, "epoch": epoch, "level": level, "rule": rule,
        "detail": detail, "score": score, "src_ip": src_ip
    })
    try:
        with open(CFG["json_log"], "a") as fh:
            fh.write(jline + "\n")
    except OSError: pass

    alert_id = 0
    try:
        alert_id = db_insert_alert(ts, epoch, level, rule, detail, score, src_ip)
    except Exception as e:
        log.error("DB insert failed: %s", e)

    if level != "INFO":
        queue_notification(level, rule, detail)

    log.warning(">>> %s | %s | %s", level, rule, detail)
    return alert_id


# --- Network: Local IP & Interface Detection ---------------------------------

def _get_local_ips() -> Set[str]:
    ips: Set[str] = set()
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show"],
                                      stderr=subprocess.DEVNULL, timeout=3).decode()
        for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out):
            ips.add(m.group(1))
    except Exception: pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0); s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0]); s.close()
    except Exception: pass
    try: ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception: pass
    ips.discard("127.0.0.1"); ips.discard("0.0.0.0")
    return ips


_VIRTUAL = ("lo", "virbr", "docker", "br-", "veth", "tun", "tap", "vmnet", "vboxnet", "dummy", "sit")


def _is_virtual(n: str) -> bool:
    return any(n.startswith(p) for p in _VIRTUAL)


def _candidate_interfaces() -> List[str]:
    seen: Set[str] = set(); result: List[str] = []

    def add(n: str) -> None:
        n = n.strip()
        if n and n not in seen and not _is_virtual(n):
            seen.add(n); result.append(n)

    try:
        out = subprocess.check_output(["ip", "route", "show", "default"],
                                      stderr=subprocess.DEVNULL, timeout=3).decode()
        toks = out.split()
        for i, t in enumerate(toks):
            if t == "dev" and i + 1 < len(toks): add(toks[i + 1])
    except Exception: pass
    try:
        for _, n in socket.if_nameindex(): add(n)
    except Exception: pass
    try:
        with open("/proc/net/dev") as fh:
            for line in fh:
                if ":" in line: add(line.split(":")[0].strip())
    except OSError: pass
    for fb in ("eth0", "eth1", "ens33", "ens3", "enp0s3", "ens160", "wlan0"): add(fb)
    return result


def _can_bind(iface: str) -> bool:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((iface, 0)); s.close(); return True
    except OSError: return False


def get_interfaces() -> List[str]:
    explicit = CFG.get("interface")
    if explicit:
        log.info("Network interface (config): %s", explicit)
        return [explicit]
    if os.geteuid() != 0:
        log.warning("Not root — network capture disabled")
        return []
    result = []
    for iface in _candidate_interfaces():
        if _can_bind(iface):
            log.info("Network interface: %s", iface)
            result.append(iface)
    if not result:
        log.warning("No bindable interface — N1-N6 disabled")
    return result


# --- Packet Parsing ----------------------------------------------------------

PROTO_TCP = 6; PROTO_UDP = 17; PROTO_ICMP = 1
ETH_P_IP = 0x0800; ETH_P_ARP = 0x0806; ETH_P_ALL = 0x0003
DNS_PORT = 53


class Packet:
    __slots__ = ("src_ip", "dst_ip", "proto", "sport", "dport", "is_syn", "is_arp",
                 "arp_op", "arp_src_ip", "arp_src_mac", "raw_len")

    def __init__(self, src_ip: str = "", dst_ip: str = "", proto: int = 0,
                 sport: int = 0, dport: int = 0, is_syn: bool = False,
                 is_arp: bool = False, arp_op: int = 0, arp_src_ip: str = "",
                 arp_src_mac: str = "", raw_len: int = 0):
        self.src_ip = src_ip; self.dst_ip = dst_ip; self.proto = proto
        self.sport = sport; self.dport = dport; self.is_syn = is_syn
        self.is_arp = is_arp; self.arp_op = arp_op; self.arp_src_ip = arp_src_ip
        self.arp_src_mac = arp_src_mac; self.raw_len = raw_len


def parse_packet(raw: bytes) -> Optional[Packet]:
    if len(raw) < 14: return None
    eth_type = struct.unpack_from("!H", raw, 12)[0]

    if eth_type == ETH_P_ARP and len(raw) >= 42:
        try:
            arp_op = struct.unpack_from("!H", raw, 20)[0]
            arp_src_mac = ":".join(f"{b:02x}" for b in raw[22:28])
            arp_src_ip = socket.inet_ntoa(raw[28:32])
            return Packet(is_arp=True, arp_op=arp_op, arp_src_ip=arp_src_ip,
                          arp_src_mac=arp_src_mac, raw_len=len(raw))
        except Exception: return None

    if eth_type != ETH_P_IP: return None
    ip = raw[14:]
    if len(ip) < 20: return None
    ihl = (ip[0] & 0x0F) * 4; proto = ip[9]
    try:
        src_ip = socket.inet_ntoa(ip[12:16])
        dst_ip = socket.inet_ntoa(ip[16:20])
    except OSError: return None
    payload = ip[ihl:]; sport = dport = 0; is_syn = False
    if proto == PROTO_TCP and len(payload) >= 14:
        sport = struct.unpack_from("!H", payload, 0)[0]
        dport = struct.unpack_from("!H", payload, 2)[0]
        flags = payload[13]; is_syn = bool(flags & 0x02) and not bool(flags & 0x10)
    elif proto == PROTO_UDP and len(payload) >= 4:
        sport = struct.unpack_from("!H", payload, 0)[0]
        dport = struct.unpack_from("!H", payload, 2)[0]
    return Packet(src_ip=src_ip, dst_ip=dst_ip, proto=proto,
                  sport=sport, dport=dport, is_syn=is_syn, raw_len=len(raw))


# --- Packet Buffer & Sniffer -------------------------------------------------

class PacketBuffer:
    def __init__(self):
        self._lock = threading.Lock(); self._pkts: List[Packet] = []

    def put(self, p: Packet):
        with self._lock: self._pkts.append(p)

    def drain(self) -> List[Packet]:
        with self._lock:
            out, self._pkts = self._pkts, []; return out


class Sniffer(threading.Thread):
    def __init__(self, buf: PacketBuffer, iface: str, local_ips: Set[str]):
        super().__init__(daemon=True, name="sniffer")
        self._buf = buf; self._iface = iface; self._local_ips = local_ips
        self._stop = threading.Event(); self._sock = None
        self.failed = False

    def run(self):
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(ETH_P_ALL))
            self._sock.bind((self._iface, 0))
            self._sock.settimeout(0.3)
            log.info("Sniffer bound to %s", self._iface)
        except PermissionError:
            log.critical("Sniffer: permission denied — run with sudo")
            self.failed = True; return
        except OSError as e:
            log.critical("Sniffer: bind %r failed: %s", self._iface, e)
            self.failed = True; return

        while not self._stop.is_set():
            try:
                raw = self._sock.recv(65535)
                p = parse_packet(raw)
                if not p: continue
                if p.is_arp:
                    self._buf.put(p); continue
                if not self._local_ips or p.dst_ip in self._local_ips:
                    self._buf.put(p)
            except socket.timeout: continue
            except OSError: break
        if self._sock: self._sock.close()

    def stop(self): self._stop.set()


# --- Network Stats -----------------------------------------------------------

class NetStats:
    __slots__ = ("total_rate", "syn_rate", "udp_rate", "icmp_rate",
                 "tcp_count", "syn_count", "udp_count", "icmp_count",
                 "syn_ratio", "src_port_spread", "dns_counts", "arp_replies",
                 "arp_requests", "total_bytes")

    def __init__(self):
        self.total_rate = 0.0; self.syn_rate = 0.0; self.udp_rate = 0.0; self.icmp_rate = 0.0
        self.tcp_count = 0; self.syn_count = 0; self.udp_count = 0; self.icmp_count = 0
        self.syn_ratio = 0.0; self.src_port_spread: Dict[str, int] = {}
        self.dns_counts: Dict[str, int] = {}
        self.arp_replies: List[Tuple[str, str]] = []
        self.arp_requests: List[Tuple[str, str]] = []
        self.total_bytes = 0


def compute_net_stats(packets: List[Packet], w: float) -> NetStats:
    ns = NetStats()
    src_ports: Dict[str, Set[int]] = collections.defaultdict(set)
    dns_src: Dict[str, int] = collections.defaultdict(int)

    for p in packets:
        ns.total_bytes += p.raw_len
        if p.is_arp:
            if p.arp_op == 2:
                ns.arp_replies.append((p.arp_src_ip, p.arp_src_mac))
            elif p.arp_op == 1:
                ns.arp_requests.append((p.arp_src_ip, p.arp_src_mac))
            continue
        if p.proto == PROTO_TCP:
            ns.tcp_count += 1; src_ports[p.src_ip].add(p.dport)
            if p.is_syn: ns.syn_count += 1
        elif p.proto == PROTO_UDP:
            ns.udp_count += 1; src_ports[p.src_ip].add(p.dport)
            if p.dport == DNS_PORT or p.sport == DNS_PORT:
                dns_src[p.src_ip] += 1
        elif p.proto == PROTO_ICMP: ns.icmp_count += 1

    total = len([p for p in packets if not p.is_arp])
    ns.total_rate = total / w; ns.syn_rate = ns.syn_count / w
    ns.udp_rate = ns.udp_count / w; ns.icmp_rate = ns.icmp_count / w
    ns.syn_ratio = (ns.syn_count / ns.tcp_count) if ns.tcp_count else 0.0
    ns.src_port_spread = {ip: len(ports) for ip, ports in src_ports.items()}
    ns.dns_counts = dict(dns_src)
    return ns


# --- Auth Log Monitor (H1, H2) -----------------------------------------------

_AUTH_FAIL_RE = re.compile(
    r"(Failed password|authentication failure|Invalid user|FAILED LOGIN|"
    r"pam_unix.*authentication failure|Connection closed by authenticating user|"
    r"Too many authentication|error: maximum authentication attempts|"
    r"Failed publickey|BREAK-IN ATTEMPT)",
    re.IGNORECASE)

_SUDO_RE = re.compile(
    r"(sudo:.*COMMAND|su:.*session opened|sudo:.*authentication failure|"
    r"sudo:.*incorrect password|FAILED SU|su\[.*\]:.*FAILED)",
    re.IGNORECASE)

_AUTH_IP_RE = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")


class AuthLogMonitor:
    def __init__(self):
        self._path = self._find(); self._pos = 0
        self._fail = 0; self._sudo = 0
        self._fail_ips: collections.Counter = collections.Counter()
        self._lock = threading.Lock()
        self._use_journal = False
        if self._path:
            try: self._pos = os.path.getsize(self._path)
            except OSError: pass
            log.info("Auth log: %s (offset %d)", self._path, self._pos)
        else:
            if self._journalctl_ok():
                self._use_journal = True
                log.info("Auth log: journalctl fallback")
            else:
                log.warning("No auth log — H1/H2 disabled")

    @staticmethod
    def _find() -> Optional[str]:
        for p in ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"]:
            if os.path.exists(p) and os.access(p, os.R_OK): return p
        return None

    @staticmethod
    def _journalctl_ok() -> bool:
        try:
            subprocess.check_output(["journalctl", "--lines=1"],
                                    stderr=subprocess.DEVNULL, timeout=2)
            return True
        except Exception: return False

    def poll(self):
        if self._use_journal or not self._path: return
        try: size = os.path.getsize(self._path)
        except OSError: return
        if size < self._pos: self._pos = 0
        if size == self._pos: return
        try:
            with open(self._path, "r", errors="replace") as fh:
                fh.seek(self._pos); chunk = fh.read(size - self._pos)
                self._pos = fh.tell()
        except OSError: return
        f = d = 0; ips: List[str] = []
        for line in chunk.splitlines():
            if _AUTH_FAIL_RE.search(line):
                f += 1
                m = _AUTH_IP_RE.search(line)
                if m: ips.append(m.group(1))
            if _SUDO_RE.search(line): d += 1
        with self._lock:
            self._fail += f; self._sudo += d
            for ip in ips: self._fail_ips[ip] += 1

    def drain(self) -> Tuple[int, int, Dict[str, int]]:
        if self._use_journal:
            try:
                out = subprocess.check_output(
                    ["journalctl", "--lines=200", "--no-pager", "--output=short"],
                    stderr=subprocess.DEVNULL, timeout=3).decode(errors="replace")
                f = d = 0; ips: List[str] = []
                for line in out.splitlines():
                    if _AUTH_FAIL_RE.search(line):
                        f += 1
                        m = _AUTH_IP_RE.search(line)
                        if m: ips.append(m.group(1))
                    if _SUDO_RE.search(line): d += 1
                return f, d, dict(collections.Counter(ips))
            except Exception: return 0, 0, {}
        with self._lock:
            f, s, ips = self._fail, self._sudo, dict(self._fail_ips)
            self._fail = self._sudo = 0; self._fail_ips.clear()
            return f, s, ips

    def available(self) -> bool: return self._path is not None or self._use_journal


# --- Process Monitor (H3, H5) ------------------------------------------------

_SUSP_NAMES = {
    "nc", "ncat", "netcat", "nmap", "masscan", "hydra", "medusa",
    "xmrig", "minergate", "cpuminer", "ethminer",
    "msfconsole", "msfvenom", "metasploit",
    "mimikatz", "lazagne", "responder",
    "empire", "covenant", "havoc", "sliver",
    "chisel", "ligolo", "rpivot",
}

_SUSP_CMD_RE = re.compile(
    r"(bash\s+-i|/dev/tcp/|/dev/udp/|exec.*sh|nc\s+-e|ncat\s+-e|"
    r"python.*socket|perl.*socket|ruby.*socket|"
    r"curl.*\|\s*bash|wget.*\|\s*sh|chmod.*\+x)",
    re.IGNORECASE)


class ProcessMonitor:
    def __init__(self):
        self._ok = PSUTIL_OK
        self._pids: Set[int] = set()
        self._new_count = 0
        self._susp_pending: List[Dict] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        if self._ok:
            try:
                self._pids = {p.pid for p in psutil.process_iter()}
                log.info("Process monitor: %d PIDs tracked", len(self._pids))
                threading.Thread(target=self._poll_loop, daemon=True,
                                 name="proc_monitor").start()
            except Exception: self._ok = False
        if not self._ok:
            log.warning("psutil unavailable — H3/H5 disabled")

    def _poll_loop(self):
        while not self._stop.wait(0.25):
            try:
                cur_procs = list(psutil.process_iter(["pid", "name", "cmdline", "username"]))
            except Exception: continue
            cur_pids = {p.pid for p in cur_procs}
            with self._lock:
                new_pids = cur_pids - self._pids
                self._pids = cur_pids
                self._new_count += len(new_pids)
                for p in cur_procs:
                    if p.pid not in new_pids: continue
                    try:
                        name = (p.info.get("name") or "").lower()
                        cmd = " ".join(p.info.get("cmdline") or [])
                        user = p.info.get("username", "")
                        if name in _SUSP_NAMES or _SUSP_CMD_RE.search(cmd):
                            self._susp_pending.append(
                                {"pid": p.pid, "name": name, "cmd": cmd[:120], "user": user})
                    except (psutil.NoSuchProcess, psutil.AccessDenied): pass

    def count_new(self) -> Tuple[int, List[Dict]]:
        if not self._ok: return 0, []
        with self._lock:
            count = self._new_count
            susp = list(self._susp_pending)
            self._new_count = 0
            self._susp_pending.clear()
            return count, susp

    def stop(self): self._stop.set()

    def available(self) -> bool: return self._ok


# --- File Integrity Monitor (H4) ---------------------------------------------

class FileIntegrityMonitor:
    def __init__(self):
        self._hashes: Dict[str, str] = {}; self._skip: Set[str] = set()
        self._pending: List[Tuple[str, str]] = []
        self._lock = threading.Lock(); self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="fim")
        self._baseline(); self._thread.start()
        log.info("FIM: watching %d file(s) (skipped %d)",
                 len(self._hashes), len(self._skip))

    @staticmethod
    def _hash(path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""): h.update(chunk)
            return h.hexdigest()
        except OSError: return None

    def _baseline(self):
        for p in CFG["monitored_files"]:
            h = self._hash(p)
            if h is None: self._skip.add(p)
            else: self._hashes[p] = h

    def _run(self):
        while not self._stop.wait(CFG["file_check_interval"]):
            for path, known in list(self._hashes.items()):
                cur = self._hash(path)
                if cur and cur != known:
                    detail = (f"path={path} "
                              f"prev={known[:16]}... new={cur[:16]}...")
                    with self._lock: self._pending.append((path, detail))
                    self._hashes[path] = cur

    def drain(self) -> List[Tuple[str, str]]:
        with self._lock:
            out, self._pending = self._pending, []; return out

    def stop(self): self._stop.set()

    @property
    def file_count(self): return len(self._hashes)


# --- Adaptive Baseline -------------------------------------------------------

class Baseline:
    def __init__(self):
        self._s: Dict[str, List[float]] = {
            "total": [], "syn": [], "udp": [], "icmp": [],
            "auth_fail": [], "sudo": [], "proc": [], "dns": []}
        self.thr_total = float(CFG["total_floor"])
        self.thr_syn = float(CFG["syn_floor"])
        self.thr_udp = float(CFG["udp_floor"])
        self.thr_icmp = float(CFG["icmp_floor"])
        self.thr_auth_fail = float(CFG["auth_fail_floor"])
        self.thr_sudo = float(CFG["sudo_event_floor"])
        self.thr_proc = float(CFG["process_spawn_floor"])
        self.thr_dns = float(CFG["dns_query_floor"])

    def record(self, ns: NetStats, af: int, sd: int, pr: int):
        self._s["total"].append(ns.total_rate)
        self._s["syn"].append(ns.syn_rate)
        self._s["udp"].append(ns.udp_rate)
        self._s["icmp"].append(ns.icmp_rate)
        self._s["auth_fail"].append(float(af))
        self._s["sudo"].append(float(sd))
        self._s["proc"].append(float(pr))
        max_dns = max(ns.dns_counts.values()) if ns.dns_counts else 0
        self._s["dns"].append(float(max_dns))

    @staticmethod
    def _percentile(v: List[float], pct: float = 95.0) -> float:
        if not v:
            return 0.0
        s = sorted(v)
        k = int(round((pct / 100.0) * (len(s) - 1)))
        return s[max(0, min(k, len(s) - 1))]

    def finalise(self):
        m = CFG["threshold_multiplier"]
        pct = float(CFG.get("percentile_threshold", 95))

        def t(key, floor): return max(floor, self._percentile(self._s[key], pct) * m)

        self.thr_total = t("total", CFG["total_floor"])
        self.thr_syn = t("syn", CFG["syn_floor"])
        self.thr_udp = t("udp", CFG["udp_floor"])
        self.thr_icmp = t("icmp", CFG["icmp_floor"])
        self.thr_auth_fail = t("auth_fail", CFG["auth_fail_floor"])
        self.thr_sudo = t("sudo", CFG["sudo_event_floor"])
        self.thr_proc = t("proc", CFG["process_spawn_floor"])
        self.thr_dns = t("dns", CFG["dns_query_floor"])
        log.info(
            "Baseline — syn=%.0f udp=%.0f icmp=%.0f total=%.0f | "
            "auth=%.0f sudo=%.0f proc=%.0f dns=%.0f",
            self.thr_syn, self.thr_udp, self.thr_icmp, self.thr_total,
            self.thr_auth_fail, self.thr_sudo, self.thr_proc, self.thr_dns)
        write_alert("INFO", "engine",
                    f"DETECTION active syn={self.thr_syn:.0f} udp={self.thr_udp:.0f} "
                    f"icmp={self.thr_icmp:.0f} auth={self.thr_auth_fail:.0f} "
                    f"sudo={self.thr_sudo:.0f} proc={self.thr_proc:.0f} "
                    f"dns={self.thr_dns:.0f}")


# --- ARP Spoof Tracker (N6) --------------------------------------------------

class ARPTracker:
    """N6 ARP spoofing detector.

    A single unsolicited ARP reply is normal on real networks (gratuitous ARP,
    the host's own announcements, gateway refreshes), so flagging every one of
    them produces constant false positives. This tracker instead raises an alert
    only on the genuine signatures of ARP cache poisoning:
      * a known IP -> MAC binding suddenly changing (e.g. the gateway's MAC is
        replaced by the attacker's), or
      * a sustained burst of unsolicited replies from one IP (what arpspoof and
        similar tools generate as they continuously re-poison the cache).
    Replies that match the host's own IPs are always ignored.
    """

    def __init__(self, local_ips: Optional[Set[str]] = None):
        self._requests: Dict[str, float] = {}
        self._bindings: Dict[str, str] = {}
        self._unsolicited: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._local_ips: Set[str] = set(local_ips or set())
        self._lock = threading.Lock()

    def note_request(self, ip: str):
        with self._lock:
            self._requests[ip] = time.time()

    def process_replies(self, arp_replies: List[Tuple[str, str]]) -> List[Tuple[str, str, str]]:
        now = time.time()
        suspicious: List[Tuple[str, str, str]] = []
        with self._lock:
            for ip, mac in arp_replies:
                if not ip or ip in ("0.0.0.0",) or ip in self._local_ips:
                    if ip and mac:
                        self._bindings[ip] = mac
                    continue
                req_time = self._requests.get(ip, 0)
                solicited = (now - req_time) <= 5.0
                prev_mac = self._bindings.get(ip)
                if mac:
                    self._bindings[ip] = mac
                binding_changed = bool(prev_mac and mac and prev_mac != mac)

                if solicited and not binding_changed:
                    continue

                dq = self._unsolicited[ip]
                dq.append(now)
                while dq and now - dq[0] > 10.0:
                    dq.popleft()

                if binding_changed:
                    suspicious.append(
                        (ip, mac,
                         f"src={ip} IP->MAC binding changed {prev_mac} => {mac} "
                         f"(ARP cache poisoning)"))
                    dq.clear()
                elif len(dq) >= 3:
                    suspicious.append(
                        (ip, mac,
                         f"src={ip} mac={mac} {len(dq)} unsolicited ARP replies in 10s "
                         f"(no matching request)"))
                    dq.clear()
        return suspicious


# --- Rule Engine -------------------------------------------------------------

class RuleEngine:
    def __init__(self, bl: Baseline):
        self._b = bl
        self._streak: Dict[str, int] = collections.defaultdict(int)
        self._last_alert: Dict[str, float] = collections.defaultdict(float)
        self._attacker_counts: Dict[str, int] = collections.defaultdict(int)

    def _fire(self, rule: str, level: str, detail: str,
              confirm: int = None, src_ip: Optional[str] = None):
        if confirm is None: confirm = CFG["confirm_windows"]
        self._streak[rule] += 1
        if self._streak[rule] < confirm:
            log.debug("[SUSPECT] %s streak=%d/%d", rule, self._streak[rule], confirm)
            return

        base_cooldown = CFG["cooldown_secs"]
        if src_ip:
            cnt = self._attacker_counts[src_ip]
            cooldown = max(5, base_cooldown - min(cnt * 5, base_cooldown - 5))
        else:
            cooldown = base_cooldown

        now = time.monotonic()
        wait = cooldown - (now - self._last_alert[rule])
        if wait > 0:
            log.debug("[COOLDOWN] %s %.0fs", rule, wait); return
        self._last_alert[rule] = now; self._streak[rule] = 0
        if src_ip: self._attacker_counts[src_ip] += 1
        write_alert(level, rule, detail)

    def _fire_now(self, rule, level, detail, src_ip=None):
        self._fire(rule, level, detail, confirm=1, src_ip=src_ip)

    def _clear(self, rule):
        if self._streak.get(rule): self._streak[rule] = 0

    def evaluate(self, ns: NetStats, af: int, sd: int, pr: int,
                 susp_procs: List[Dict], fim: List[Tuple[str, str]],
                 auth_ips: Dict[str, int], arp_suspicious: List[str] = None):
        b = self._b

        # H1 Brute-force
        if af > b.thr_auth_fail:
            top_ip = max(auth_ips, key=auth_ips.get) if auth_ips else None
            ip_info = f" top_src={top_ip}({auth_ips[top_ip]})" if top_ip else ""
            self._fire_now("brute_force",
                           rate_to_level(af, CFG["auth_fail_floor"]),
                           f"failures={af} thr={b.thr_auth_fail:.0f}{ip_info}",
                           src_ip=top_ip)
        else: self._clear("brute_force")

        # H2 Privilege escalation
        if sd > b.thr_sudo:
            lvl = "CRITICAL" if sd > b.thr_sudo * 3 else "HIGH"
            self._fire_now("priv_escalation", lvl,
                           f"sudo_su_events={sd} thr={b.thr_sudo:.0f}")
        else: self._clear("priv_escalation")

        # H3 Process anomaly
        if pr > b.thr_proc:
            self._fire_now("proc_anomaly",
                           rate_to_level(pr, CFG["process_spawn_floor"]),
                           f"new_procs={pr} thr={b.thr_proc:.0f}")
        else: self._clear("proc_anomaly")

        # H4 File integrity
        for _, detail in fim:
            write_alert("CRITICAL", "file_integrity", detail)

        # H5 Suspicious process
        for sp in susp_procs:
            write_alert("HIGH", "susp_process",
                        f"name={sp['name']} pid={sp['pid']} user={sp['user']} "
                        f"cmd={sp['cmd'][:80]}")

        # N1 SYN flood
        if ns.syn_rate > b.thr_syn and ns.syn_ratio > CFG["syn_ratio_min"]:
            self._fire("syn_flood", rate_to_level(ns.syn_rate, CFG["syn_floor"]),
                       f"syn={ns.syn_rate:.0f}/s thr={b.thr_syn:.0f} "
                       f"ratio={ns.syn_ratio * 100:.0f}% pkts={ns.syn_count}")
        else: self._clear("syn_flood")

        # N2 UDP flood
        if ns.udp_rate > b.thr_udp:
            self._fire("udp_flood", rate_to_level(ns.udp_rate, CFG["udp_floor"]),
                       f"udp={ns.udp_rate:.0f}/s thr={b.thr_udp:.0f} pkts={ns.udp_count}")
        else: self._clear("udp_flood")

        # N3 ICMP flood
        if ns.icmp_rate > b.thr_icmp:
            self._fire("icmp_flood", rate_to_level(ns.icmp_rate, CFG["icmp_floor"]),
                       f"icmp={ns.icmp_rate:.0f}/s thr={b.thr_icmp:.0f} pkts={ns.icmp_count}")
        else: self._clear("icmp_flood")

        # N4 Port scan
        active: Set[str] = set()
        for ip, spread in ns.src_port_spread.items():
            if spread >= CFG["port_scan_threshold"]:
                key = "scan_" + ip; active.add(key)
                lvl = "HIGH" if spread > CFG["port_scan_threshold"] * 4 else "MEDIUM"
                self._fire(key, lvl,
                           f"src={ip} ports={spread} thr={CFG['port_scan_threshold']}",
                           confirm=1, src_ip=ip)
        for key in list(self._streak):
            if key.startswith("scan_") and key not in active: self._clear(key)

        # N5 DNS tunneling
        for ip, count in ns.dns_counts.items():
            if count > b.thr_dns:
                self._fire("dns_tunnel",
                           "HIGH" if count > b.thr_dns * 3 else "MEDIUM",
                           f"src={ip} dns_queries={count}/s thr={b.thr_dns:.0f}",
                           confirm=2, src_ip=ip)

        # N6 ARP spoofing
        for ip, _mac, detail in (arp_suspicious or []):
            self._fire_now("arp_spoof", "HIGH", detail, src_ip=ip)

        log.debug("[WIN] syn=%.0f udp=%.0f icmp=%.0f af=%d sd=%d pr=%d fim=%d susp=%d arp=%d",
                  ns.syn_rate, ns.udp_rate, ns.icmp_rate, af, sd, pr, len(fim), len(susp_procs),
                  len(arp_suspicious or []))


# --- Auth Poller -------------------------------------------------------------

class AuthPoller(threading.Thread):
    def __init__(self, mon: AuthLogMonitor):
        super().__init__(daemon=True, name="auth_poller")
        self._mon = mon; self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            self._mon.poll(); self._stop.wait(0.1)

    def stop(self): self._stop.set()


# --- Shared State ------------------------------------------------------------

hids_state: Dict = {
    "phase": "stopped",
    "baseline_pct": 0.0,
    "uptime_start": None,
    "windows": 0,
    "packets_total": 0,
    "active_rules": 0,
    "last_ns": None,
    "monitors": {
        "auth_log": False, "psutil": False, "fim_files": 0,
        "iface": "—", "ntfy": False
    },
}
_state_lock = threading.Lock()


def _set_state(**kw):
    with _state_lock: hids_state.update(kw)


def get_state() -> Dict:
    with _state_lock: return dict(hids_state)


# --- Engine Thread -----------------------------------------------------------

class HIDSEngine(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="hids_engine")
        self._stop_event = threading.Event()

    def stop(self): self._stop_event.set()

    def run(self):
        log.info("═" * 60)
        log.info("Ulinzi HIDS — engine starting")
        log.info("═" * 60)

        local_ips = _get_local_ips()
        log.info("Local IPs: %s", local_ips or "(none detected)")

        ifaces = get_interfaces(); buf = PacketBuffer()
        sniffers: List[Sniffer] = []; net_active = False
        for iface in ifaces:
            sniffers.append(Sniffer(buf, iface, local_ips))

        auth_mon = AuthLogMonitor()
        auth_poll = AuthPoller(auth_mon)
        proc_mon = ProcessMonitor()
        fim = FileIntegrityMonitor()
        arp_track = ARPTracker(local_ips)
        ntfy_worker = NotificationWorker()
        ntfy_worker.start()

        ntfy_ok = CFG.get("ntfy_enabled", False) and REQUESTS_OK
        iface_label = ", ".join(ifaces) if ifaces else "N/A"

        _set_state(
            phase="baseline", baseline_pct=0.0, uptime_start=datetime.now(),
            monitors={
                "auth_log": auth_mon.available(),
                "psutil": proc_mon.available(),
                "fim_files": fim.file_count,
                "iface": iface_label,
                "ntfy": ntfy_ok,
            }
        )

        for sniffer in sniffers:
            sniffer.start()
        if sniffers:
            time.sleep(0.5)
            net_active = any(not s.failed for s in sniffers)
            if not net_active:
                mon = dict(hids_state["monitors"])
                mon["iface"] = "N/A (needs sudo)"
                _set_state(monitors=mon)

        auth_poll.start()

        active_rules = 0
        if auth_mon.available():   active_rules += 2   # H1, H2
        if proc_mon.available():   active_rules += 2   # H3, H5
        if fim.file_count > 0:     active_rules += 1   # H4
        if net_active:             active_rules += 6   # N1-N6
        _set_state(active_rules=active_rules, packets_total=0)

        db_log_system("engine_start",
                      f"ifaces={iface_label} net={net_active} "
                      f"auth={auth_mon.available()} psutil={proc_mon.available()} "
                      f"fim={fim.file_count} ntfy={ntfy_ok}")

        write_alert("INFO", "engine",
                    f"HIDS started ifaces={iface_label} "
                    f"net={'yes' if net_active else 'no'} "
                    f"auth={'yes' if auth_mon.available() else 'no'} "
                    f"psutil={'yes' if proc_mon.available() else 'no'} "
                    f"fim={fim.file_count} ntfy={'yes' if ntfy_ok else 'no'} "
                    f"baseline={CFG['baseline_seconds']}s")

        bl = Baseline(); phase_start = time.monotonic()
        engine: Optional[RuleEngine] = None; windows = 0; packets_total = 0

        log.info("BASELINE phase — %d seconds", CFG["baseline_seconds"])

        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(CFG["window_seconds"])
                if self._stop_event.is_set(): break

                pkts = buf.drain()
                ns = compute_net_stats(pkts, CFG["window_seconds"])
                for _ip, _mac in ns.arp_requests:
                    arp_track.note_request(_ip)
                arp_suspicious = arp_track.process_replies(ns.arp_replies)
                af, sd, ips = auth_mon.drain()
                pr, susp = proc_mon.count_new()
                fim_alerts = fim.drain()
                windows += 1
                packets_total += len(pkts)
                elapsed = time.monotonic() - phase_start
                _set_state(windows=windows, last_ns=ns, packets_total=packets_total)

                if hids_state["phase"] == "baseline":
                    bl.record(ns, af, sd, pr)
                    pct = min(elapsed / CFG["baseline_seconds"], 0.99)
                    _set_state(baseline_pct=pct)
                    log.info(
                        "[BASELINE %.0f%%] pkts=%d syn=%.1f udp=%.1f "
                        "icmp=%.1f af=%d sd=%d pr=%d",
                        pct * 100, len(pkts), ns.syn_rate, ns.udp_rate,
                        ns.icmp_rate, af, sd, pr)
                    if elapsed >= CFG["baseline_seconds"]:
                        bl.finalise(); engine = RuleEngine(bl)
                        _set_state(phase="detecting", baseline_pct=1.0)
                        log.info("DETECTION phase armed.")
                else:
                    log.info(
                        "[DETECTING] pkts=%d syn=%.1f udp=%.1f icmp=%.1f "
                        "af=%d sd=%d pr=%d fim=%d susp=%d",
                        len(pkts), ns.syn_rate, ns.udp_rate, ns.icmp_rate,
                        af, sd, pr, len(fim_alerts), len(susp))
                    engine.evaluate(ns, af, sd, pr, susp, fim_alerts, ips, arp_suspicious)

        finally:
            for sniffer in sniffers: sniffer.stop()
            auth_poll.stop(); proc_mon.stop(); fim.stop(); ntfy_worker.stop()
            _set_state(phase="stopped")
            db_log_system("engine_stop", f"windows={windows}")
            log.info("Engine stopped after %d windows.", windows)
            write_alert("INFO", "engine", f"HIDS stopped windows={windows}")


# --- Public API --------------------------------------------------------------

_engine_ref: Optional[HIDSEngine] = None


def start_engine() -> HIDSEngine:
    global _engine_ref
    if _engine_ref and _engine_ref.is_alive(): return _engine_ref
    load_config(); save_default_config()
    _ensure_logging(); init_db()
    _engine_ref = HIDSEngine(); _engine_ref.start(); return _engine_ref


def stop_engine():
    global _engine_ref
    if _engine_ref: _engine_ref.stop(); _engine_ref.join(timeout=6); _engine_ref = None


def is_running() -> bool:
    return _engine_ref is not None and _engine_ref.is_alive()


# --- Standalone Entry Point --------------------------------------------------

if __name__ == "__main__":
    load_config(); save_default_config()
    _ensure_logging(); init_db()

    def _sig(*_): stop_engine(); sys.exit(0)

    signal.signal(signal.SIGTERM, _sig); signal.signal(signal.SIGINT, _sig)
    eng = start_engine()
    try: eng.join()
    except KeyboardInterrupt: stop_engine()
