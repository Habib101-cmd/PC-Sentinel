"""Agent local PC Sentinel : audit en lecture seule d'un PC Windows."""

import argparse
import ctypes
import json
import os
import platform
import re
import ssl
import subprocess
import sys
import time
from getpass import getpass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

API_URL = os.environ.get("PC_SENTINEL_API_URL", "https://localhost:8443").rstrip("/")
CA_FILE = os.environ.get("PC_SENTINEL_CA_FILE")  # certificat de l'autorité locale (dev)
# Cette liste est affichée à l'utilisateur AVANT le consentement.
# Elle doit toujours correspondre exactement à ce que l'agent collecte.
COLLECTED_DATA = [
    "Nom de l'ordinateur, nom et version de Windows",
    "État du pare-feu Windows pour chaque profil (domaine, privé, public)",
    "Antivirus enregistrés dans le Centre de sécurité Windows et leur état",
    "Date et numéro du dernier correctif Windows installé",
    "Programmes lancés au démarrage : nom, emplacement, chemin du fichier (sans arguments) et signature numérique",
    "Chemin des programmes en cours d'exécution, hors dossiers système (sans arguments de commande)",
    "Nombre d'échecs de connexion Windows sur 24 h (droits administrateur requis)",
]
UTF8 = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "


# ---------------------------------------------------------------- PowerShell

def run_powershell(command, timeout=30, extra_env=None):
    # PSModulePath hérité de PowerShell 7 casse le chargement des modules de
    # Windows PowerShell 5.1 : on ne le transmet pas.
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    env.update(extra_env or {})
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", UTF8 + command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "commande en échec")
    return result.stdout.strip()


def safe_check(check_id, func, simulate_unavailable=()):
    """Un contrôle qui échoue devient « unavailable », jamais un faux résultat."""
    if check_id in simulate_unavailable:
        return {"id": check_id, "status": "unavailable", "error": "indisponibilité simulée"}
    try:
        return {"id": check_id, "status": "ok", "data": func()}
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError, KeyError, TypeError) as error:
        return {"id": check_id, "status": "unavailable", "error": str(error)[:300]}


def as_list(raw):
    """PowerShell renvoie un objet seul (pas une liste) quand il n'y a qu'un résultat."""
    if not raw:
        return []
    data = json.loads(raw)
    return data if isinstance(data, list) else [data]


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


SIGNATURE_CMD = (
    "$ErrorActionPreference = 'Stop'; "
    "(ConvertFrom-Json -InputObject $env:PCS_PATHS) | ForEach-Object { "
    "if (Test-Path -LiteralPath $_ -PathType Leaf) { "
    "$s = Get-AuthenticodeSignature -LiteralPath $_; "
    "$pub = $null; "
    "if ($s.SignerCertificate) { $pub = $s.SignerCertificate.GetNameInfo('SimpleName', $false) }; "
    "[pscustomobject]@{ path = $_; signature = [string]$s.Status; publisher = $pub } "
    "} else { [pscustomobject]@{ path = $_; signature = 'FileNotFound'; publisher = $null } } "
    "} | ConvertTo-Json -Compress"
)

FAILED_LOGON_CMD = (
    "$ErrorActionPreference = 'Stop'; "
    "try { $n = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; "
    "StartTime=(Get-Date).AddHours(-24)} | Measure-Object).Count } "
    "catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $n = 0 } else { throw } }; "
    "$n"
)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def anonymize_path(path):
    """Remplace le dossier utilisateur par %USERPROFILE% (collecte minimale)."""
    home = os.path.expanduser("~")
    if home and path.lower().startswith(home.lower()):
        return "%USERPROFILE%" + path[len(home):]
    return path


def is_system_path(path):
    roots = [os.environ.get(v) for v in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)")]
    return any(r and path.lower().startswith(r.lower() + "\\") for r in roots)


def extract_exe_path(command):
    """Extrait le chemin du programme d'une ligne de commande, sans les arguments."""
    command = (command or "").strip()
    match = re.match(r'^"([^"]+)"', command) or re.match(r"^(.+?\.exe)", command, re.IGNORECASE)
    return os.path.expandvars(match.group(1)) if match else None


def read_updates():
    raw = run_powershell(
        "Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 1 HotFixID, "
        "@{n='InstalledOn';e={$_.InstalledOn.ToString('yyyy-MM-dd')}} | ConvertTo-Json -Compress"
    )
    rows = as_list(raw)
    if not rows:
        raise RuntimeError("aucun correctif daté trouvé")
    return {"hotfix_id": rows[0]["HotFixID"], "last_update_date": rows[0]["InstalledOn"]}


def read_startup():
    raw = run_powershell(
        "Get-CimInstance Win32_StartupCommand | Select-Object Name, Location, Command "
        "| ConvertTo-Json -Compress"
    )
    items = as_list(raw)
    paths = sorted({p for p in (extract_exe_path(i.get("Command")) for i in items) if p})

    signatures = {}
    if paths:
        sig_raw = run_powershell(
            SIGNATURE_CMD, timeout=60, extra_env={"PCS_PATHS": json.dumps(paths)}
        )
        signatures = {s["path"]: s for s in as_list(sig_raw)}

    entries = []
    for item in items[:100]:
        path = extract_exe_path(item.get("Command"))
        sig = signatures.get(path, {})
        entries.append(
            {
                "name": str(item.get("Name") or "")[:100],
                "location": re.sub(r"S-1-5-21-[\d-]+", "<SID>", str(item.get("Location") or "")),
                "path": anonymize_path(path) if path else None,
                "signature": sig.get("signature", "Unknown"),
                "publisher": sig.get("publisher"),
            }
        )
    return {"entries": entries}


def read_processes():
    raw = run_powershell(
        "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | "
        "Select-Object -ExpandProperty ExecutablePath | Sort-Object -Unique | "
        "ConvertTo-Json -Compress",
        timeout=60,
    )
    all_paths = [p for p in as_list(raw) if isinstance(p, str)]
    kept = [anonymize_path(p) for p in all_paths if not is_system_path(p)][:300]
    return {"paths": kept, "total_distinct": len(all_paths), "sent": len(kept)}


def read_failed_logons():
    if not is_admin():
        raise RuntimeError("droits administrateur requis pour lire le journal Sécurité")
    raw = run_powershell(FAILED_LOGON_CMD, timeout=60)
    return {"count": int(raw), "period_hours": 24}
# ------------------------------------------------------------------------ API


def make_ssl_context():
    if CA_FILE:
        return ssl.create_default_context(cafile=CA_FILE)
    return None


def describe_url_error(error):
    if isinstance(error.reason, ssl.SSLCertVerificationError):
        return (
            "Certificat du serveur non reconnu. En développement, définissez "
            "PC_SENTINEL_CA_FILE avec le chemin de certs\\caddy-root.crt."
        )
    return f"Serveur injoignable : {error.reason}"


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
    with urlopen(request, timeout=15, context=make_ssl_context()) as response:
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
    if not is_admin():
        print("Lancé sans droits administrateur : le contrôle des échecs de connexion")
        print("sera indisponible, et seuls vos propres processus seront visibles.\n")
    return input("Voulez-vous lancer cet audit ? [o/N] ").strip().lower() == "o"


def print_result(result):
    print(f"\nRésultat : {result['summary']}")
    for alert in result["alerts"]:
        print(f"  [{alert['severity']}] {alert['title']} ({alert['subject']})")
        print(f"      Conseil : {alert['recommendation']}")
    if result["unavailable_checks"]:
        print("\nContrôles non réalisés : " + ", ".join(result["unavailable_checks"]))
    print("\nUn audit sans alerte ne prouve pas l'absence d'attaque.")


def describe_check(check):
    if check["status"] != "ok":
        return f"indisponible ({check['error']})"
    data = check["data"]
    if check["id"] == "firewall":
        return ", ".join(
            f"{n} {'actif' if s == 'True' else 'INACTIF'}"
            for n, s in data["profiles"].items()
        )
    if check["id"] == "antivirus":
        return ", ".join(
            f"{p['name']} ({'actif' if p['enabled'] else 'inactif'})"
            for p in data["products"]
        ) or "aucun produit"
    if check["id"] == "updates":
        return f"dernier correctif {data['hotfix_id']} le {data['last_update_date']}"
    if check["id"] == "startup":
        return f"{len(data['entries'])} programme(s) examiné(s)"
    if check["id"] == "processes":
        return f"{data['sent']} chemin(s) envoyé(s) sur {data['total_distinct']}"
    if check["id"] == "failed_logons":
        return f"{data['count']} échec(s) sur {data['period_hours']} h"
    return "réalisé"


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
        if error.code == 429:
            wait = error.headers.get("Retry-After", "quelques")
            print(f"Trop de tentatives de connexion : réessayez dans {wait} s.")
        else:
            print(f"Connexion refusée ({error.code}).")
        return
    except URLError as error:
        print(describe_url_error(error))
        return

    print("\nAudit en cours...")
    started = time.time()
    sim = tuple(args.simulate_unavailable)
    checks = [
        safe_check("firewall", read_firewall, sim),
        safe_check("antivirus", read_antivirus, sim),
        safe_check("updates", read_updates, sim),
        safe_check("startup", read_startup, sim),
        safe_check("processes", read_processes, sim),
        safe_check("failed_logons", read_failed_logons, sim),
    ]
    for check in checks:
        print(f"  - {check['id']} : {describe_check(check)}")
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
        print(describe_url_error(error))


if __name__ == "__main__":
    main()
