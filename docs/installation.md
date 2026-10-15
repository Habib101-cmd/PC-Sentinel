# Installation

## Prérequis

Windows 10 ou 11, Git, Docker Desktop, Python 3.12, VS Code (conseillé).

## Serveur (API, base, interface)

1. `git clone https://github.com/Habib101-cmd/PC-Sentinel.git` puis `cd PC-Sentinel`
2. Copier `.env.example` en `.env` et remplacer les valeurs :
   - `POSTGRES_PASSWORD` : `python -c "import secrets; print(secrets.token_urlsafe(24))"`
   - `JWT_SECRET` (32 caractères minimum) : `python -c "import secrets; print(secrets.token_urlsafe(48))"`
3. `docker compose up --build`
4. L'API démarre sur https://localhost:8443 (documentation interactive : `/docs`), l'interface sur http://localhost:5173.

## Certificat local (développement)

```powershell
mkdir certs
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt certs/caddy-root.crt
$env:PC_SENTINEL_CA_FILE = "$PWD\certs\caddy-root.crt"
```

Pour le navigateur, ouvrir une fois https://localhost:8443/health et accepter le certificat.

## Agent

Aucune dépendance : `python agent/audit.py` (Python 3.12, Windows 10 ou 11).
Pour tous les contrôles, lancer dans un PowerShell administrateur.

## Tests

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pytest
```

## Données de démonstration

`python scripts/seed_demo.py` crée le compte `demo` avec quatre audits fictifs.
