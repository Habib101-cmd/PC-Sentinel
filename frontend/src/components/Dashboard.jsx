import {
    SEVERITIES,
    SEVERITY_CLASS,
    countBySeverity,
    formatDate,
    sortBySeverity,
  } from "../labels.js";
  import StatusBadge from "./StatusBadge.jsx";
  
  export default function Dashboard({ audits, loading, onSelect }) {
    if (audits.length === 0) {
      return (
        <section className="card empty">
          <h2>{loading ? "Chargement des audits…" : "Aucun audit enregistré"}</h2>
          {!loading && (
            <p>
              Lancez l'agent local sur votre PC Windows : <code>python agent/audit.py</code>,
              puis cliquez sur « Actualiser ».
            </p>
          )}
        </section>
      );
    }
  
    const last = audits[0];
    const counts = countBySeverity(last.alerts);
    const topAlerts = sortBySeverity(last.alerts).slice(0, 3);
  
    return (
      <>
        <section className="card">
          <div className="card-head">
            <div>
              <h2>Dernier audit</h2>
              <p className="muted">
                {formatDate(last.audited_at)} · {last.device_name}
              </p>
            </div>
            <StatusBadge status={last.status} />
          </div>
          <p>{last.summary}</p>
  
          <div className="counters">
            {SEVERITIES.map((severity) => (
              <div className={`counter sev-${SEVERITY_CLASS[severity]}`} key={severity}>
                <strong>{counts[severity]}</strong>
                <span>{severity}</span>
              </div>
            ))}
          </div>
  
          {last.unavailable_checks.length > 0 && (
            <p className="muted">
              {last.unavailable_checks.length} contrôle(s) non réalisé(s) : ouvrez le
              détail pour les connaître.
            </p>
          )}
  
          <button onClick={() => onSelect(last.audit_id)}>Voir le détail</button>
        </section>
  
        {topAlerts.length > 0 && (
          <section className="card">
            <h2>Recommandations principales</h2>
            <ul className="reco">
              {topAlerts.map((alert, index) => (
                <li key={index}>
                  <span className={`badge sev-${SEVERITY_CLASS[alert.severity]}`}>
                    {alert.severity}
                  </span>{" "}
                  <strong>{alert.title}</strong>
                  <p>{alert.recommendation}</p>
                </li>
              ))}
            </ul>
          </section>
        )}
  
        <section className="card">
          <h2>Historique</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Appareil</th>
                  <th>État</th>
                  <th>Alertes</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {audits.map((audit) => (
                  <tr key={audit.audit_id}>
                    <td>{formatDate(audit.audited_at)}</td>
                    <td>{audit.device_name}</td>
                    <td>
                      <StatusBadge status={audit.status} />
                    </td>
                    <td>{audit.alerts.length}</td>
                    <td>
                      <button className="secondary" onClick={() => onSelect(audit.audit_id)}>
                        Détail
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </>
    );
  }