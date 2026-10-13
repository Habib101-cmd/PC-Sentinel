import { SEVERITY_CLASS, formatDate } from "../labels.js";

export default function AlertCard({ alert }) {
  return (
    <details className="alert">
      <summary>
        <span className={`badge sev-${SEVERITY_CLASS[alert.severity]}`}>
          {alert.severity}
        </span>
        <strong>{alert.title}</strong>
        <span className="muted">{alert.subject}</span>
      </summary>
      <dl>
        <dt>Catégorie</dt>
        <dd>{alert.category}</dd>
        <dt>Élément concerné</dt>
        <dd>{alert.subject}</dd>
        <dt>Règle déclenchée</dt>
        <dd>
          {alert.rule_id} (version {alert.rule_version})
        </dd>
        <dt>Date et heure</dt>
        <dd>{formatDate(alert.detected_at)}</dd>
        <dt>Explication</dt>
        <dd>{alert.explanation}</dd>
        <dt>Recommandation</dt>
        <dd>{alert.recommendation}</dd>
        <dt>Limites du contrôle</dt>
        <dd>{alert.limits}</dd>
      </dl>
    </details>
  );
}