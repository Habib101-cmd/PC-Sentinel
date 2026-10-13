from .engine import Rule, register

THRESHOLD = 10


def _many_failures(checks: dict) -> list[str]:
    check = checks.get("failed_logons")
    if not check or check["status"] != "ok":
        return []
    count = check["data"].get("count", 0)
    period = check["data"].get("period_hours", 24)
    if isinstance(count, int) and count >= THRESHOLD:
        return [f"{count} échecs de connexion sur les {period} dernières heures"]
    return []


register(
    Rule(
        id="R007",
        version="1.0",
        title="Échecs de connexion répétés",
        category="Authentification",
        severity="Moyen",
        explanation=(
            f"Au moins {THRESHOLD} tentatives de connexion Windows ont échoué sur la "
            "période. Cela peut indiquer quelqu'un qui devine un mot de passe."
        ),
        recommendation=(
            "Si ces échecs ne sont pas de votre fait, changez le mot de passe du compte "
            "et vérifiez que le bureau à distance n'est pas exposé."
        ),
        limits=(
            "Le journal compte aussi des erreurs bénignes (mot de passe tapé de travers, "
            "services mal configurés). Seul le nombre est analysé, pas la source."
        ),
        check=_many_failures,
    )
)
