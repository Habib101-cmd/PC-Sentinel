"""Charge un compte de démonstration avec des audits fictifs (aucune donnée personnelle).

Usage : python scripts/seed_demo.py
Variables : PC_SENTINEL_API_URL (défaut https://localhost:8443), PC_SENTINEL_CA_FILE
"""
import json
import os
import ssl
import sys
from datetime import date, timedelta
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_URL = os.environ.get("PC_SENTINEL_API_URL", "https://localhost:8443").rstrip("/")
CA_FILE = os.environ.get("PC_SENTINEL_CA_FILE")
CONTEXT = ssl.create_default_context(cafile=CA_FILE) if CA_FILE else None

DEMO_USER = "demo"
DEMO_PASSWORD = "demo-pc-sentinel-2026"  # compte local de démonstration : ne jamais le créer sur un vrai serveur


def call(path, data=None, token=None, method=None):
    headers, body = {}, None
    if data is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(data).encode("utf-8")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(f"{API_URL}{path}", data=body, headers=headers,
                      method=method or ("POST" if body else "GET"))
    with urlopen(request, timeout=15, context=CONTEXT) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else None


def ok(check_id, data):
    return {"id": check_id, "status": "ok", "data": data}


def unavailable(check_id, error):
    return {"id": check_id, "status": "unavailable", "error": error}


def base_checks():
    return {
        "firewall": ok("firewall", {"profiles": {"Domain": "True", "Private": "True", "Public": "True"}}),
        "antivirus": ok("antivirus", {"products": [{"name": "Windows Defender", "enabled": True}]}),
        "updates": ok("updates", {"hotfix_id": "KB5000001",
                                  "last_update_date": (date.today() - timedelta(days=9)).isoformat()}),
        "startup": ok("startup", {"entries": [{
            "name": "OneDrive", "location": "Startup",
            "path": "%USERPROFILE%\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
            "signature": "Valid", "publisher": "Microsoft Corporation"}]}),
        "processes": ok("processes", {"paths": ["%USERPROFILE%\\AppData\\Local\\Programs\\Notes\\notes.exe"],
                                      "total_distinct": 58, "sent": 1}),
        "failed_logons": ok("failed_logons", {"count": 0, "period_hours": 24}),
    }


def scenarios():
    clean = base_checks()

    firewall = base_checks()
    firewall["firewall"] = ok("firewall", {"profiles": {"Domain": "True", "Private": "True", "Public": "False"}})

    risky = base_checks()
    risky["antivirus"] = ok("antivirus", {"products": [{"name": "Windows Defender", "enabled": False}]})
    risky["updates"] = ok("updates", {"hotfix_id": "KB4999999",
                                      "last_update_date": (date.today() - timedelta(days=120)).isoformat()})
    risky["failed_logons"] = ok("failed_logons", {"count": 37, "period_hours": 24})

    limited = base_checks()
    limited["failed_logons"] = unavailable(
        "failed_logons", "droits administrateur requis pour lire le journal Sécurité")
    limited["startup"] = ok("startup", {"entries": [
        {"name": "OneDrive", "location": "Startup",
         "path": "%USERPROFILE%\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
         "signature": "Valid", "publisher": "Microsoft Corporation"},
        {"name": "ToolboxHelper", "location": "HKU\\<SID>\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "path": "%USERPROFILE%\\Tools\\helper.exe", "signature": "NotSigned", "publisher": None},
    ]})
    limited["processes"] = ok("processes", {"paths": [
        "%USERPROFILE%\\Downloads\\installer-demo.exe",
        "%USERPROFILE%\\AppData\\Local\\Programs\\Notes\\notes.exe"], "total_distinct": 61, "sent": 2})

    return [
        ("PC-DEMO-PROPRE", "Windows 11", "10.0.22631", 3.4, clean),
        ("PC-DEMO-PAREFEU", "Windows 10", "10.0.19045", 4.1, firewall),
        ("PC-DEMO-RISQUE", "Windows 10", "10.0.19045", 5.8, risky),
        ("PC-DEMO-LIMITE", "Windows 11", "10.0.22631", 4.9, limited),
    ]


def main():
    creds = {"username": DEMO_USER, "password": DEMO_PASSWORD}
    try:
        try:
            call("/auth/register", creds)
            print(f"Compte « {DEMO_USER} » créé.")
        except HTTPError as error:
            if error.code != 409:
                raise
        token = call("/auth/login", creds)["access_token"]

        for old in call("/audits", token=token):  # le script peut être relancé sans doublons
            call(f"/audits/{old['audit_id']}", token=token, method="DELETE")

        for device, os_name, version, seconds, checks in scenarios():
            result = call("/audits", {
                "device_name": device,
                "os": {"name": os_name, "version": version},
                "duration_seconds": seconds,
                "checks": list(checks.values()),
            }, token)
            print(f"  {device} : {result['status']} ({len(result['alerts'])} alerte(s))")
    except HTTPError as error:
        sys.exit(f"Erreur de l'API ({error.code}) : {error.read().decode('utf-8')[:200]}")
    except URLError as error:
        sys.exit(f"Serveur injoignable ou certificat non reconnu : {error.reason}")

    print(f"\nConnectez-vous sur http://localhost:5173 avec « {DEMO_USER} » / « {DEMO_PASSWORD} ».")


if __name__ == "__main__":
    main()
