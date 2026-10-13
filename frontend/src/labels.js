export const STATUS_LABELS = {
  aucun_indicateur: "Aucun indicateur détecté",
  a_verifier: "Éléments à vérifier",
  a_risque: "Indicateurs à risque détectés",
};

export const SEVERITIES = ["Élevé", "Moyen", "Faible", "Information"];

export const SEVERITY_CLASS = {
  Élevé: "high",
  Moyen: "medium",
  Faible: "low",
  Information: "info",
};

export const CHECK_LABELS = {
  firewall: "Pare-feu",
  antivirus: "Antivirus",
  updates: "Mises à jour",
  startup: "Programmes au démarrage",
  processes: "Processus en cours",
  failed_logons: "Échecs de connexion",
};

export const DISCLAIMER =
  "Un audit sans alerte ne prouve pas l'absence d'attaque. Les résultats sont des indicateurs à vérifier, pas des preuves de compromission.";

export const formatDate = (iso) => new Date(iso).toLocaleString("fr-FR");

export const checkLabel = (id) => CHECK_LABELS[id] || id;

export function countBySeverity(alerts) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const alert of alerts) {
    if (alert.severity in counts) counts[alert.severity] += 1;
  }
  return counts;
}

export const sortBySeverity = (alerts) =>
  [...alerts].sort(
    (a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
  );
