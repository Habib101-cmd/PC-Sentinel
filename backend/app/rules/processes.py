from .engine import Rule, register

UNUSUAL_LOCATIONS = (
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\$recycle.bin\\",
    "\\windows\\temp\\",
)


def _from_unusual_location(checks: dict) -> list[str]:
    check = checks.get("processes")
    if not check or check["status"] != "ok":
        return []
    return [
        path
        for path in check["data"].get("paths", [])
        if any(marker in path.lower() for marker in UNUSUAL_LOCATIONS)
    ]


register(
    Rule(
        id="R006",
        version="1.0",
        title="Processus lancé depuis un emplacement inhabituel",
        category="Processus",
        severity="Faible",
        explanation=(
            "Ce programme s'exécute depuis un dossier temporaire, de téléchargement "
            "ou partagé, où les logiciels légitimes sont rarement installés à "
            "demeure. Certains codes malveillants utilisent ces emplacements."
        ),
        recommendation=(
            "Identifiez le programme (nom du fichier, éditeur). Si vous ne l'avez pas "
            "lancé volontairement, fermez-le et faites analyser le fichier."
        ),
        limits=(
            "Des installeurs et outils portables légitimes s'exécutent depuis ces "
            "dossiers. Sans droits administrateur, seuls vos propres processus sont "
            "visibles. L'agent n'envoie pas les programmes des dossiers système."
        ),
        check=_from_unusual_location,
    )
)
