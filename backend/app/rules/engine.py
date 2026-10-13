from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

RULESET_VERSION = "0.2.0"

EXPECTED_CHECKS = [
    "firewall", "antivirus", "updates", "startup", "processes", "failed_logons",
]


@dataclass(frozen=True)
class Rule:
    id: str
    version: str
    title: str
    category: str
    severity: str
    explanation: str
    recommendation: str
    limits: str
    check: Callable[[dict], list[str]]  # retourne la liste des éléments concernés


RULES: list[Rule] = []


def register(rule: Rule) -> Rule:
    RULES.append(rule)
    return rule


def evaluate(checks: list[dict]) -> tuple[list[dict], list[str]]:
    by_id = {c["id"]: c for c in checks}
    now = datetime.now(timezone.utc)

    alerts = []
    for rule in RULES:
        for subject in rule.check(by_id):
            alerts.append(
                {
                    "rule_id": rule.id,
                    "rule_version": rule.version,
                    "title": rule.title,
                    "category": rule.category,
                    "severity": rule.severity,
                    "detected_at": now,
                    "subject": subject,
                    "explanation": rule.explanation,
                    "recommendation": rule.recommendation,
                    "limits": rule.limits,
                }
            )

    unavailable = [c["id"] for c in checks if c["status"] != "ok"]
    unavailable += [i for i in EXPECTED_CHECKS if i not in by_id]
    return alerts, unavailable


def global_status(alerts: list[dict], unavailable: list[str]) -> tuple[str, str]:
    if any(a["severity"] == "Élevé" for a in alerts):
        return "a_risque", "Indicateurs à risque détectés. Ils sont à vérifier manuellement."
    if alerts or unavailable:
        return "a_verifier", "Éléments à vérifier : alertes ou contrôles indisponibles."
    return (
        "aucun_indicateur",
        "Aucun indicateur détecté. Cela ne prouve pas l'absence d'attaque.",
    )
