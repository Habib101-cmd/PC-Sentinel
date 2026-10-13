from .engine import Rule, register


def _disabled_profiles(checks: dict) -> list[str]:
    check = checks.get("firewall")
    if not check or check["status"] != "ok":
        return []
    profiles = check["data"].get("profiles", {})
    return [
        f"Profil {name}"
        for name, state in profiles.items()
        if str(state).lower() == "false"
    ]


register(
    Rule(
        id="R001",
        version="1.0",
        title="Pare-feu désactivé",
        category="Configuration",
        severity="Moyen",
        explanation=(
            "Le pare-feu Windows filtre les connexions entrantes. "
            "Désactivé, le PC est plus exposé aux accès non sollicités."
        ),
        recommendation=(
            "Activez le pare-feu dans Sécurité Windows > Pare-feu et protection réseau."
        ),
        limits=(
            "Un pare-feu tiers peut remplir ce rôle sans que le pare-feu Windows "
            "soit actif."
        ),
        check=_disabled_profiles,
    )
)
