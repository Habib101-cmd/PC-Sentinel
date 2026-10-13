"""Agent local PC Sentinel : audit en lecture seule d'un PC Windows."""

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from getpass import getpass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

API_URL = os.environ.get("PC_SENTINEL_API_URL", "http://localhost:8000").rstrip("/")

# Cette liste est affichée à l'utilisateur AVANT le consentement.
# Elle doit toujours correspondre exactement à ce que l'agent collecte.
COLLECTED_DATA = [
    "Nom de l'ordinateur, nom et version de Windows",
    "État du pare-feu Windows pour chaque profil (domaine, privé, public)",
    "Antivirus enregistrés dans le Centre de sécurité Windows et leur état",
]

UTF8 = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "


# ---------------------------------------------------------------- PowerShell

def run_powershell(command, timeout=30):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", UTF8 + command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "commande en échec")
    return result.stdout.strip()


def as_list(raw):
    """PowerShell renvoie un objet seul (pas une liste) quand il n'y a qu'un résultat."""
    if not raw:
        return []
    data = json.loads(raw)
    return data if isinstance(data, list) else [data]


def safe_check(check_id, func, simulate_unavailable=()):
    """Un contrôle qui échoue devient « unavailable », jamais un faux résultat."""
    if check_id in simulate_unavailable:
        return {"id": check_id, "status": "unavailable", "error": "indisponibilité simulée"}
    try:
        return {"id": check_id, "status": "ok", "data": func()}
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError) as error:
        return {"id": check_id, "status": "unavailable", "error": str(error)[:300]}


# ------------------------------------------------------------------ Contrôles

def read_firewall():
    raw = run_powershell(
        "Get-NetFirewallProfile | Select-Object Name, "
        "@{n='Enabled';e={[string]$_.Enabled}} | ConvertTo-Json -Compress"
    )
    profiles = {p["Name"]: p["Enabled"] for p in as_list(raw)}
    if not profiles:
        raise RuntimeError("aucun profil de pare-feu renvoyé")
    return {"profiles": profiles}


def read_antivirus():
    raw = run_powershell(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
        "-ErrorAction Stop | Select-Object displayName, productState | "
        "ConvertTo-Json -Compress"
    )
    products = [
        # Le bit 0x1000 de productState signifie « protection activée ».
        {"name": p["displayName"], "enabled": bool(int(p["productState"]) & 0x1000)}
        for p in as_list(raw)
    ]
    return {"products": products}


def read_os():
    build = int(platform.version().split(".")[-1]) if platform.system() == "Windows" else 0
    name = "Windows 11" if build >= 22000 else platform.system() or "Inconnu"
    if name == "Windows" and build:
        name = "Windows 10"
    return {"name": name, "version": platform.version()}


# ------------------------------------------------------------------------ API

def send_request(path, data, token=None, method="POST"):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        f"{API_URL}{path}",
        data=json.dumps(data).encode("utf-8"),
        headers=headers,
        method=method,
    )
    with urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def check_transport_is_safe():
    parsed = urlparse(API_URL)
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not local:
        print("Refus : les échanges avec un serveur distant doivent utiliser HTTPS.")
        sys.exit(1)


def login(username, password):
    result = send_request("/auth/login", {"username": username, "password": password})
    return result["access_token"]


# ----------------------------------------------------------------------- Main

def ask_consent():
    print("=== PC Sentinel : audit local en lecture seule ===\n")
    print("Données qui seront collectées :")
    for item in COLLECTED_DATA:
        print(f"  - {item}")
    print("\nCet audit ne lit aucun fichier personnel, ne collecte aucun mot de passe")
    print("et ne modifie ni fichier ni paramètre de ce PC.")
    print(f"Les résultats seront envoyés à : {API_URL}\n")
    return input("Voulez-vous lancer cet audit ? [o/N] ").strip().lower() == "o"


def print_result(result):
    print(f"\nRésultat : {result['summary']}")
    for alert in result["alerts"]:
        print(f"  [{alert['severity']}] {alert['title']} ({alert['subject']})")
        print(f"      Conseil : {alert['recommendation']}")
    if result["unavailable_checks"]:
        print("\nContrôles non réalisés : " + ", ".join(result["unavailable_checks"]))
    print("\nUn audit sans alerte ne prouve pas l'absence d'attaque.")


def main():
    parser = argparse.ArgumentParser(description="Agent d'audit PC Sentinel")
    parser.add_argument(
        "--simulate-unavailable",
        nargs="*",
        default=[],
        metavar="CONTROLE",
        help="tests : force ces contrôles en indisponible (ex. antivirus)",
    )
    args = parser.parse_args()

    check_transport_is_safe()

    if not ask_consent():
        print("Audit annulé.")
        return

    username = input("Nom d'utilisateur : ")
    password = getpass("Mot de passe : ")

    try:
        token = login(username, password)
    except HTTPError as error:
        print(f"Connexion refusée ({error.code}).")
        return
    except URLError as error:
        print(f"Serveur injoignable : {error.reason}")
        return

    print("\nAudit en cours...")
    started = time.time()
    sim = tuple(args.simulate_unavailable)
    checks = [
        safe_check("firewall", read_firewall, sim),
        safe_check("antivirus", read_antivirus, sim),
    ]
    for check in checks:
        label = "réalisé" if check["status"] == "ok" else f"indisponible ({check['error']})"
        print(f"  - {check['id']} : {label}")

    audit = {
        "device_name": platform.node(),
        "os": read_os(),
        "duration_seconds": round(time.time() - started, 2),
        "checks": checks,
    }

    try:
        print_result(send_request("/audits", audit, token))
    except HTTPError as error:
        print(f"Erreur de l'API ({error.code}) : {error.read().decode('utf-8')[:300]}")
    except URLError as error:
        print(f"Serveur injoignable : {error.reason}")


if __name__ == "__main__":
    main()
