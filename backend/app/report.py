from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .schemas import AuditResult

STATUS_LABELS = {
    "aucun_indicateur": "Aucun indicateur détecté",
    "a_verifier": "Éléments à vérifier",
    "a_risque": "Indicateurs à risque détectés",
}
CHECK_LABELS = {
    "firewall": "Pare-feu",
    "antivirus": "Antivirus",
    "updates": "Mises à jour",
    "startup": "Programmes au démarrage",
    "processes": "Processus en cours",
    "failed_logons": "Échecs de connexion",
}
SEVERITY_ORDER = ["Élevé", "Moyen", "Faible", "Information"]
SEVERITY_CLASS = {"Élevé": "high", "Moyen": "medium", "Faible": "low", "Information": "info"}

# autoescape : les noms de programmes viennent du PC audité, ce sont des données non fiables.
env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def fmt(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%d/%m/%Y à %H:%M UTC")


def label(check_id: str) -> str:
    return CHECK_LABELS.get(check_id, check_id)


def render_report(result: AuditResult, checks: list[dict]) -> str:
    alerts = sorted(result.alerts, key=lambda a: SEVERITY_ORDER.index(a.severity))

    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for alert in alerts:
        counts[alert.severity] += 1

    # Une recommandation par règle, pour ne pas répéter le même conseil.
    recommendations, seen = [], set()
    for alert in alerts:
        if alert.rule_id not in seen:
            seen.add(alert.rule_id)
            recommendations.append(
                {"title": alert.title, "severity": alert.severity, "text": alert.recommendation}
            )

    by_id = {c["id"]: c for c in checks}
    unavailable = [
        {
            "label": label(check_id),
            "reason": by_id.get(check_id, {}).get("error") or "Contrôle non transmis par l'agent.",
        }
        for check_id in result.unavailable_checks
    ]

    return env.get_template("report.html").render(
        r=result,
        status_label=STATUS_LABELS.get(result.status, result.status),
        audited_at=fmt(result.audited_at),
        generated_at=fmt(datetime.now(timezone.utc)),
        counts=counts,
        severity_class=SEVERITY_CLASS,
        alerts=[
            {**a.model_dump(), "detected_at": fmt(a.detected_at), "css": SEVERITY_CLASS[a.severity]}
            for a in alerts
        ],
        recommendations=recommendations,
        performed=[label(c) for c in result.checks_performed],
        unavailable=unavailable,
    )
