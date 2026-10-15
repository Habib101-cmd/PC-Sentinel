import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from sqlalchemy import select

from app.auth import JWT_ALGORITHM, JWT_SECRET
from app.database import SessionLocal
from app.models import Audit, User
from app.ratelimit import SlidingWindowLimiter


def bad_login(client, name="alice"):
    return client.post(
        "/auth/login", json={"username": name, "password": "mauvais-mot-de-passe"}
    )


def make_token(user_id, secret=JWT_SECRET, delta=timedelta(hours=1)):
    return jwt.encode(
        {"sub": str(user_id), "exp": datetime.now(timezone.utc) + delta},
        secret,
        algorithm=JWT_ALGORITHM,
    )


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------ comptes

def test_inscription_puis_connexion(client, password):
    creds = {"username": "alice", "password": password}
    assert client.post("/auth/register", json=creds).status_code == 201
    login = client.post("/auth/login", json=creds)
    assert login.status_code == 200
    token = login.json()["access_token"]
    assert client.get("/me", headers=bearer(token)).json() == {"username": "alice"}


def test_nom_deja_pris(client, new_user, password):
    new_user("alice")
    again = client.post("/auth/register", json={"username": "alice", "password": password})
    assert again.status_code == 409


@pytest.mark.parametrize("creds", [
    {"username": "alice", "password": "court"},
    {"username": "al", "password": "motdepasse-solide-123"},
    {"username": "alice !", "password": "motdepasse-solide-123"},
    {"username": "alice"},
])
def test_inscription_invalide(client, creds):
    assert client.post("/auth/register", json=creds).status_code == 422


def test_mot_de_passe_stocke_hache(client, new_user, password):
    new_user("alice")
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "alice"))
    assert user.password_hash != password
    assert user.password_hash.startswith("$argon2")


def test_mauvais_identifiants_meme_message(client, new_user, password):
    new_user("alice")
    wrong_password = client.post("/auth/login", json={"username": "alice", "password": "x" * 12})
    unknown_user = client.post("/auth/login", json={"username": "inconnu", "password": password})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_routes_protegees_sans_jeton(client):
    assert client.get("/audits").status_code in (401, 403)
    assert client.post("/audits", json={}).status_code in (401, 403)
    assert client.get("/me").status_code in (401, 403)


def test_jetons_falsifies_ou_expires(client, new_user):
    new_user("alice")  # crée l'utilisateur numéro 1
    assert client.get("/me", headers=bearer(make_token(1))).status_code == 200  # contrôle du test
    assert client.get("/me", headers=bearer(make_token(1, delta=timedelta(hours=-1)))).status_code == 401
    assert client.get("/me", headers=bearer(make_token(1, secret="x" * 40))).status_code == 401
    assert client.get("/me", headers=bearer("pas-un-jeton")).status_code == 401


# ------------------------------------------------------------ limites de tentatives

def test_blocage_apres_cinq_echecs(client, new_user, password):
    new_user("alice")
    assert [bad_login(client).status_code for _ in range(5)] == [401] * 5

    blocked = bad_login(client)
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0

    good = client.post("/auth/login", json={"username": "alice", "password": password})
    assert good.status_code == 429  # même avec le bon mot de passe

    new_user("bob")  # un autre compte n'est pas bloqué


def test_blocage_par_adresse_tous_noms_confondus(client):
    codes = {bad_login(client, f"user{i}").status_code for i in range(20)}
    assert codes == {401}
    assert bad_login(client, "user99").status_code == 429


def test_limite_de_creations_de_compte(client, password):
    codes = [
        client.post("/auth/register", json={"username": f"user{i:02d}", "password": password}).status_code
        for i in range(11)
    ]
    assert codes == [201] * 10 + [429]


def test_limiteur_fenetre_glissante():
    limiter = SlidingWindowLimiter(limit=2, window_seconds=1)
    limiter.add("k")
    assert limiter.retry_after("k") == 0
    limiter.add("k")
    assert limiter.retry_after("k") > 0
    time.sleep(1.1)
    assert limiter.retry_after("k") == 0


# ------------------------------------------------------------ audits

def test_audit_sans_indicateur(client, new_user, payload):
    r = client.post("/audits", json=payload(), headers=new_user("alice"))
    assert r.status_code == 201
    data = r.json()
    assert data["status"] == "aucun_indicateur"
    assert data["alerts"] == []
    assert data["unavailable_checks"] == []
    assert len(data["checks_performed"]) == 6
    assert "ne prouve pas" in data["summary"]


def test_audit_avec_alerte_complete(client, new_user, payload, checks_with):
    fw = {"id": "firewall", "status": "ok", "data": {"profiles": {"Domain": "True", "Private": "True", "Public": "False"}}}
    data = client.post("/audits", json=payload(checks=checks_with(firewall=fw)), headers=new_user("alice")).json()
    assert data["status"] == "a_verifier"
    alert = data["alerts"][0]
    for field in ("title", "category", "severity", "detected_at", "subject",
                  "rule_id", "explanation", "recommendation", "limits"):
        assert alert[field], f"champ « {field} » manquant"
    assert alert["subject"] == "Profil Public"


def test_audit_antivirus_desactive_est_a_risque(client, new_user, payload, checks_with):
    av = {"id": "antivirus", "status": "ok", "data": {"products": [{"name": "X", "enabled": False}]}}
    data = client.post("/audits", json=payload(checks=checks_with(antivirus=av)), headers=new_user("alice")).json()
    assert data["status"] == "a_risque"
    assert data["alerts"][0]["severity"] == "Élevé"


def test_controle_indisponible_jamais_presente_comme_sain(client, new_user, payload, checks_with):
    broken = {"id": "antivirus", "status": "unavailable", "error": "accès refusé"}
    data = client.post("/audits", json=payload(checks=checks_with(antivirus=broken)), headers=new_user("alice")).json()
    assert data["status"] == "a_verifier"
    assert data["unavailable_checks"] == ["antivirus"]
    assert data["alerts"] == []
    assert "Aucun indicateur détecté" not in data["summary"]


@pytest.mark.parametrize("change", [
    {"device_name": ""},
    {"duration_seconds": -1},
    {"duration_seconds": 99999},
    {"checks": [{"id": "firewall", "status": "peut-etre"}]},
    {"checks": "pas une liste"},
    {"os": {"name": "", "version": "1"}},
    {"checks": [{"id": "firewall", "status": "ok", "data": {"x": "a" * 250_000}}]},
])
def test_audit_invalide_refuse(client, new_user, payload, change):
    assert client.post("/audits", json=payload(**change), headers=new_user("alice")).status_code == 422


def test_audit_sans_champ_obligatoire(client, new_user, payload):
    body = payload()
    del body["os"]
    assert client.post("/audits", json=body, headers=new_user("alice")).status_code == 422


# ------------------------------------------------------------ isolation entre utilisateurs

def test_un_utilisateur_ne_voit_pas_les_audits_d_un_autre(client, new_user, payload):
    alice, bob = new_user("alice"), new_user("bob")
    audit_id = client.post("/audits", json=payload(), headers=alice).json()["audit_id"]

    assert client.get(f"/audits/{audit_id}", headers=bob).status_code == 404
    assert client.get(f"/audits/{audit_id}/report", headers=bob).status_code == 404
    assert client.delete(f"/audits/{audit_id}", headers=bob).status_code == 404
    assert client.get("/audits", headers=bob).json() == []

    assert client.get(f"/audits/{audit_id}", headers=alice).status_code == 200
    assert len(client.get("/audits", headers=alice).json()) == 1


def test_historique_trie_du_plus_recent_au_plus_ancien(client, new_user, payload):
    alice = new_user("alice")
    first = client.post("/audits", json=payload(), headers=alice).json()["audit_id"]
    time.sleep(0.01)
    second = client.post("/audits", json=payload(), headers=alice).json()["audit_id"]
    listed = [a["audit_id"] for a in client.get("/audits", headers=alice).json()]
    assert listed == [second, first]


# ------------------------------------------------------------ suppression

def test_suppression_d_un_audit(client, new_user, payload):
    alice = new_user("alice")
    audit_id = client.post("/audits", json=payload(), headers=alice).json()["audit_id"]
    assert client.delete(f"/audits/{audit_id}", headers=alice).status_code == 204
    assert client.get(f"/audits/{audit_id}", headers=alice).status_code == 404
    assert client.delete(f"/audits/{audit_id}", headers=alice).status_code == 404


def test_suppression_du_compte(client, new_user, payload, password):
    alice, bob = new_user("alice"), new_user("bob")
    client.post("/audits", json=payload(), headers=alice)
    bob_audit = client.post("/audits", json=payload(), headers=bob).json()["audit_id"]

    assert client.delete("/users/me", headers=alice).status_code == 204
    assert client.post("/auth/login", json={"username": "alice", "password": password}).status_code == 401
    assert client.get("/audits", headers=alice).status_code == 401  # jeton devenu inutilisable

    assert client.get(f"/audits/{bob_audit}", headers=bob).status_code == 200  # Bob n'est pas touché
    with SessionLocal() as db:
        assert len(db.scalars(select(Audit)).all()) == 1


# ------------------------------------------------------------ rapport

def test_rapport_contient_les_informations_et_les_limites(client, new_user, payload, checks_with):
    alice = new_user("alice")
    broken = {"id": "failed_logons", "status": "unavailable", "error": "droits administrateur requis"}
    audit_id = client.post("/audits", json=payload(checks=checks_with(failed_logons=broken)),
                           headers=alice).json()["audit_id"]

    report = client.get(f"/audits/{audit_id}/report", headers=alice)
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("text/html")
    assert "attachment" in report.headers["content-disposition"]
    assert report.headers["cache-control"] == "no-store"

    html = report.text
    for expected in ("PC-TEST", "Windows 11", "Durée de l'audit", "Contrôles effectués",
                     "Contrôles non réalisés", "Échecs de connexion",
                     "droits administrateur requis", "Limites de cet audit",
                     "ne prouve pas l'absence d'attaque", "default-src 'none'"):
        assert expected in html, f"« {expected} » absent du rapport"


def test_rapport_echappe_les_donnees_non_fiables(client, new_user, payload, checks_with):
    alice = new_user("alice")
    evil = {"id": "processes", "status": "ok", "data": {
        "paths": ["%USERPROFILE%\\Downloads\\<script>alert('xss')</script>.exe"],
        "total_distinct": 1, "sent": 1}}
    body = payload(device_name="<b>PC-PIEGE</b>", checks=checks_with(processes=evil))
    audit_id = client.post("/audits", json=body, headers=alice).json()["audit_id"]

    html = client.get(f"/audits/{audit_id}/report", headers=alice).text
    assert "<script>" not in html
    assert "<b>PC-PIEGE</b>" not in html
    assert "&lt;script&gt;" in html


# ------------------------------------------------------------ journal

def test_journal_sans_secret(client, new_user, log_messages, password):
    headers = new_user("alice")
    token = headers["Authorization"].split()[1]
    client.post("/auth/login", json={"username": "alice", "password": "Tres-Secret-Faux-123"})
    client.post("/auth/login", json={"username": "inconnu-xyz", "password": "Autre-Secret-456"})

    text = "\n".join(log_messages)
    assert "login_failed" in text
    assert "register_ok" in text
    for secret in ("Tres-Secret-Faux-123", "Autre-Secret-456", password, "inconnu-xyz", token):
        assert secret not in text
