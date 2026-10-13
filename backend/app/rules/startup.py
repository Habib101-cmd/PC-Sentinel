from .engine import Rule, register

RISKY_SIGNATURES = {"NotSigned", "HashMismatch", "NotTrusted"}


def _unsigned_entries(checks: dict) -> list[str]:
    check = checks.get("startup")
    if not check or check["status"] != "ok":
        return []
    subjects = []
    for entry in check["data"].get("entries", []):
        if entry.get("signature") in RISKY_SIGNATURES:
            text = f"{entry.get('name', '?')} : {entry.get('path', '?')}"
            if entry.get("publisher"):
                text += f" (éditeur : {entry['publisher']})"
            text += f" [{entry.get('location', 'emplacement inconnu')}]"
            subjects.append(text)
    return subjects


register(
    Rule(
        id="R005",
        version="1.0",
        title="Programme non signé au démarrage",
        category="Démarrage",
        severity="Faible",
        explanation=(
            "Ce programme se lance à chaque ouverture de session et sa signature "
            "numérique est absente ou invalide. Un éditeur identifiable est plus "
            "facile à vérifier."
        ),
        recommendation=(
            "Vérifiez que vous reconnaissez ce programme (Gestionnaire des tâches > "
            "Démarrage). En cas de doute, cherchez son nom en ligne ou analysez le "
            "fichier avec un antivirus."
        ),
        limits=(
            "De nombreux petits logiciels légitimes ne sont pas signés : c'est un "
            "indicateur à vérifier, pas une preuve. Seuls les programmes dont le "
            "chemin a pu être déterminé sont examinés."
        ),
        check=_unsigned_entries,
    )
)
