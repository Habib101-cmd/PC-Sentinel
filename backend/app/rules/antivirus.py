from .engine import Rule, register


def _products(checks: dict) -> list[dict] | None:
    check = checks.get("antivirus")
    if not check or check["status"] != "ok":
        return None  # contrôle indisponible : aucune alerte inventée
    return check["data"].get("products", [])


def _all_disabled(checks: dict) -> list[str]:
    products = _products(checks)
    if products and not any(p.get("enabled") for p in products):
        return [p.get("name", "Antivirus inconnu") for p in products]
    return []


def _none_registered(checks: dict) -> list[str]:
    products = _products(checks)
    return ["Centre de sécurité Windows"] if products == [] else []


register(
    Rule(
        id="R002",
        version="1.0",
        title="Protection antivirus désactivée",
        category="Protection",
        severity="Élevé",
        explanation=(
            "Un antivirus est enregistré dans Windows, mais il est signalé comme "
            "désactivé : le PC n'est plus protégé en temps réel."
        ),
        recommendation="Réactivez la protection dans Sécurité Windows > Protection contre les virus.",
        limits=(
            "L'état est lu dans le Centre de sécurité Windows. Un produit peut "
            "le déclarer de façon inexacte."
        ),
        check=_all_disabled,
    )
)

register(
    Rule(
        id="R003",
        version="1.0",
        title="Aucun antivirus détecté",
        category="Protection",
        severity="Moyen",
        explanation="Aucun produit antivirus n'est enregistré dans le Centre de sécurité Windows.",
        recommendation="Activez Microsoft Defender ou installez une protection reconnue.",
        limits="Un antivirus non déclaré dans Windows ne serait pas visible par cet audit.",
        check=_none_registered,
    )
)
