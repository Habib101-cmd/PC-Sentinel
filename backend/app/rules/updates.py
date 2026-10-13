from datetime import datetime, timezone

from .engine import Rule, register

MAX_AGE_DAYS = 60


def _outdated(checks: dict) -> list[str]:
    check = checks.get("updates")
    if not check or check["status"] != "ok":
        return []
    try:
        last = datetime.strptime(check["data"]["last_update_date"], "%Y-%m-%d").date()
    except (KeyError, ValueError):
        return []
    age = (datetime.now(timezone.utc).date() - last).days
    if age > MAX_AGE_DAYS:
        return [f"Dernier correctif : {last.isoformat()} (il y a {age} jours)"]
    return []


register(
    Rule(
        id="R004",
        version="1.0",
        title="Aucun correctif Windows récent",
        category="Mises à jour",
        severity="Faible",
        explanation=(
            f"Aucun correctif n'a été installé depuis plus de {MAX_AGE_DAYS} jours. "
            "Les mises à jour corrigent des failles que des attaquants exploitent."
        ),
        recommendation="Ouvrez Paramètres > Windows Update et installez les mises à jour proposées.",
        limits=(
            "La liste des correctifs vient de Get-HotFix, qui ne couvre pas toutes "
            "les mises à jour (pilotes, Microsoft Store, définitions antivirus)."
        ),
        check=_outdated,
    )
)
