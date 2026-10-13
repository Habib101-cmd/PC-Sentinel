import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  clearToken,
  deleteAccount,
  deleteAudit,
  getToken,
  listAudits,
} from "./api.js";
import AuditDetail from "./components/AuditDetail.jsx";
import Dashboard from "./components/Dashboard.jsx";
import Login from "./components/Login.jsx";
import { DISCLAIMER } from "./labels.js";

export default function App() {
  const [loggedIn, setLoggedIn] = useState(Boolean(getToken()));
  const [audits, setAudits] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const logout = useCallback((message = "") => {
    clearToken();
    setLoggedIn(false);
    setAudits([]);
    setSelectedId(null);
    setError("");
    setNotice(message);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setAudits(await listAudits());
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout("Session expirée, reconnectez-vous.");
      } else {
        setError(err.message);
      }
    } finally {
      setLoading(false);
    }
  }, [logout]);

  useEffect(() => {
    if (loggedIn) refresh();
  }, [loggedIn, refresh]);

  async function handleDeleteAudit(id) {
    if (!window.confirm("Supprimer définitivement cet audit ?")) return;
    try {
      await deleteAudit(id);
      setSelectedId(null);
      await refresh();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleDeleteAccount() {
    if (
      !window.confirm(
        "Supprimer votre compte et TOUS vos audits ? Cette action est irréversible."
      )
    )
      return;
    try {
      await deleteAccount();
      logout("Compte supprimé.");
    } catch (err) {
      setError(err.message);
    }
  }

  if (!loggedIn) {
    return (
      <Login
        notice={notice}
        onLoggedIn={() => {
          setNotice("");
          setLoggedIn(true);
        }}
      />
    );
  }

  const selected = audits.find((a) => a.audit_id === selectedId);

  return (
    <div className="app">
      <header className="topbar">
        <div>
          <p className="eyebrow">Audit de sécurité</p>
          <h1>PC Sentinel</h1>
        </div>
        <div className="actions">
          <button onClick={refresh} disabled={loading}>
            {loading ? "Chargement…" : "Actualiser"}
          </button>
          <button className="secondary" onClick={() => logout()}>
            Déconnexion
          </button>
          <button className="danger" onClick={handleDeleteAccount}>
            Supprimer mon compte
          </button>
        </div>
      </header>

      {error && <p className="error" role="alert">{error}</p>}

      <main>
        {selected ? (
          <AuditDetail
            audit={selected}
            onBack={() => setSelectedId(null)}
            onDelete={() => handleDeleteAudit(selected.audit_id)}
          />
        ) : (
          <Dashboard audits={audits} loading={loading} onSelect={setSelectedId} />
        )}
      </main>

      <footer className="disclaimer">{DISCLAIMER}</footer>
    </div>
  );
}