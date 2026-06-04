import subprocess, sys, os, shutil, json

ENTRY = "app.py"
NAME = "ulinzi"
DIST = "dist"


def run(cmd):
    print(f"\n$ {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"[ERROR] Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)


def main():
    print("=" * 50)
    print("  Ulinzi HIDS — PyInstaller build")
    print("=" * 50)

    missing = []
    for pkg in ("flask", "psutil", "requests", "PyInstaller"):
        try: __import__(pkg.lower())
        except ImportError: missing.append(pkg)
    if missing:
        print(f"[ERROR] Missing: {', '.join(missing)}")
        print(f"Install: pip install {' '.join(missing)} --break-system-packages")
        sys.exit(1)

    for d in ("build", DIST, f"{NAME}.spec"):
        if os.path.exists(d):
            shutil.rmtree(d) if os.path.isdir(d) else os.remove(d)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--name", NAME, "--distpath", DIST, "--clean", "--strip",
        "--hidden-import", "flask",
        "--hidden-import", "flask.templating",
        "--hidden-import", "jinja2",
        "--hidden-import", "jinja2.ext",
        "--hidden-import", "werkzeug",
        "--hidden-import", "werkzeug.serving",
        "--hidden-import", "werkzeug.routing",
        "--hidden-import", "click",
        "--hidden-import", "psutil",
        "--hidden-import", "requests",
        "--hidden-import", "sqlite3",
        "--hidden-import", "hids_engine",
        ENTRY,
    ]
    run(cmd)

    # Ship config.json (the proposal's documented configuration filename).
    # Prefer copying the user's existing config.json so their settings carry over.
    cfg_dest = os.path.join(DIST, "config.json")
    if os.path.exists("config.json"):
        shutil.copy("config.json", cfg_dest)
    else:
        default_cfg = {
            "interface": None,
            "learning_window_seconds": 60, "sampling_interval_seconds": 1,
            "percentile_threshold": 95, "threshold_multiplier": 3,
            "confirm_windows": 2, "cooldown_secs": 30, "file_check_interval": 5,
            "syn_floor": 100, "udp_floor": 500, "icmp_floor": 50, "total_floor": 800,
            "syn_ratio_threshold": 0.60, "port_scan_distinct_ports": 20,
            "dns_query_floor": 50, "auth_fail_floor": 3, "sudo_event_floor": 5,
            "process_spawn_floor": 20, "ntfy_enabled": False,
            "ntfy_topic": "ulinzi-alerts-CHANGE-ME", "ntfy_server": "https://ntfy.sh",
            "ntfy_min_level": "MEDIUM", "ntfy_token": "",
            "alert_log": "alerts.log", "json_log": "alerts.jsonl",
            "info_log": "hids.log", "db_path": "ulinzi.db",
            "dashboard_host": "0.0.0.0", "dashboard_port": 5000,
            "monitored_files": [
                "/etc/passwd", "/etc/shadow", "/etc/sudoers",
                "/etc/hosts", "/etc/ssh/sshd_config", "/etc/crontab"
            ]
        }
        with open(cfg_dest, "w") as fh:
            json.dump(default_cfg, fh, indent=2)

    run_sh = os.path.join(DIST, "run.sh")
    with open(run_sh, "w") as fh:
        fh.write("""#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
if [ "$EUID" -ne 0 ]; then
    echo "[ulinzi] WARNING: Not root. Network rules (N1-N6) disabled."
    echo "[ulinzi] Run: sudo ./run.sh for full monitoring."
    echo ""
fi
./ulinzi "$@"
""")
    os.chmod(run_sh, 0o755)
    os.chmod(os.path.join(DIST, NAME), 0o755)

    exe_size = os.path.getsize(os.path.join(DIST, NAME)) / 1024 / 1024
    print(f"""
{'=' * 50}
  BUILD SUCCESSFUL
{'=' * 50}
  Executable : {DIST}/{NAME}  ({exe_size:.1f} MB)
  Config     : {DIST}/config.json
  Launcher   : {DIST}/run.sh

  Run:
    cd {DIST}
    sudo ./ulinzi
{'=' * 50}
""")


if __name__ == "__main__":
    main()
