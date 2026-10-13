import { checkLabel, formatDate, sortBySeverity } from "../labels.js";
import AlertCard from "./AlertCard.jsx";
import StatusBadge from "./StatusBadge.jsx";

export default function AuditDetail({ audit, onBack, onDelete }) {
  const alerts = sortBySeverity(audit.alerts);

  return (
    <>
      <button className="secondary" onClick={onBack}>
        ← Retour au tableau de bord
      </button>

      <section className="card">
        <div className="card-head">
          <div>
            <h2>Audit du {formatDate(audit.audited_at)}</h2>
            <p className="muted">
              {audit.device_name} · {audit.os.name} ({audit.os.version}) · durée{" "}
              {audit.duration_seconds} s · règles v{audit.ruleset_version}
            </p>
          </div>
          <StatusBadge status={audit.status} />
        </div>
        <p>{audit.summary}</p>
      </section>

      <section className="card">
        <h2>Alertes ({alerts.length})</h2>
        {alerts.length === 0 ? (
          <p>Aucune alerte pour cet audit.</p>
        ) : (
          alerts.map((alert, index) => <AlertCard alert={alert} key={index} />)
        )}
      </section>

      <section className="card">
        <h2>Contrôles</h2>
        <p>
          <strong>Réalisés :</strong>{" "}
          {audit.checks_performed.map(checkLabel).join(", ") || "aucun"}
        </p>
        <p>
          <strong>Non réalisés :</strong>{" "}
          {audit.unavailable_checks.length
            ? audit.unavailable_checks.map(checkLabel).join(", ")
            : "aucun"}
        </p>
        {audit.unavailable_checks.length > 0 && (
          <p className="muted">
            Un contrôle non réalisé n'est ni bon ni mauvais : il n'a simplement pas pu
            être vérifié (droits insuffisants, fonction absente…).
          </p>
        )}
      </section>

      <button className="danger" onClick={onDelete}>
        Supprimer cet audit
      </button>
    </>
  );
}