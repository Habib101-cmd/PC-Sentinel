import { useState } from "react";
import { login, register } from "../api.js";

export default function Login({ onLoggedIn, notice }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const isRegister = mode === "register";

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    if (isRegister) {
      if (!/^[a-zA-Z0-9_-]{3,50}$/.test(username)) {
        setError("Nom d'utilisateur : 3 à 50 caractères (lettres, chiffres, _ et -).");
        return;
      }
      if (password.length < 12) {
        setError("Le mot de passe doit contenir au moins 12 caractères.");
        return;
      }
    }

    setBusy(true);
    try {
      if (isRegister) await register(username, password);
      await login(username, password);
      onLoggedIn();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page">
      <section className="card login-card">
        <p className="eyebrow">Audit de sécurité</p>
        <h1>PC Sentinel</h1>
        <p>
          {isRegister
            ? "Créez un compte pour conserver vos audits."
            : "Connectez-vous pour consulter vos audits."}
        </p>

        {notice && <p className="notice">{notice}</p>}

        <form onSubmit={handleSubmit}>
          <label>
            Nom d'utilisateur
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </label>
          <label>
            Mot de passe
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete={isRegister ? "new-password" : "current-password"}
              required
            />
          </label>
          <button type="submit" disabled={busy}>
            {busy ? "Patientez…" : isRegister ? "Créer mon compte" : "Se connecter"}
          </button>
        </form>

        {error && <p className="error" role="alert">{error}</p>}

        <button
          type="button"
          className="text-button"
          onClick={() => {
            setMode(isRegister ? "login" : "register");
            setError("");
          }}
        >
          {isRegister ? "J'ai déjà un compte" : "Créer un nouveau compte"}
        </button>
      </section>
    </main>
  );
}