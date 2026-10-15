from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.rules import RULES, RULESET_VERSION, evaluate, global_status
from app.rules.engine import EXPECTED_CHECKS

SEVERITIES = {"Information", "Faible", "Moyen", "Élevé"}


def run(checks):
    alerts, unavailable = evaluate(checks)
    status, summary = global_status(alerts, unavailable)
    return alerts, unavailable, status, summary


def ids(alerts):
    return [a["rule_id"] for a in alerts]


def ok(check_id, data):
    return {"id": check_id, "status": "ok", "data": data}


def days_ago(n):
    return (datetime.now(timezone.utc).date() - timedelta(days=n)).isoformat()


# ------------------------------------------------------------ cas général

def test_pc_sans_indicateur(checks_with):
    alerts, unavailable, status, summary = run(checks_with())
    assert alerts == []
    assert unavailable == []
    assert status == "aucun_indicateur"
    assert "ne prouve pas" in summary


@pytest.mark.parametrize("check_id", EXPECTED_CHECKS)
def test_controle_indisponible_ne_cree_jamais_d_alerte(checks_with, check_id):
    broken = {"id": check_id, "status": "unavailable", "error": "test"}
    alerts, unavailable, status, _ = run(checks_with(**{check_id: broken}))
    assert alerts == []
    assert unavailable == [check_id]
    assert status == "a_verifier"  # jamais « aucun indicateur »


@pytest.mark.parametrize("check_id", EXPECTED_CHECKS)
def test_controle_absent_compte_comme_indisponible(checks_with, check_id):
    alerts, unavailable, status, _ = run(checks_with(**{check_id: None}))
    assert alerts == []
    assert check_id in unavailable
    assert status == "a_verifier"


# ------------------------------------------------------------ R001 pare-feu

def test_r001_pare_feu_desactive(checks_with):
    fw = ok("firewall", {"profiles": {"Domain": "True", "Private": "True", "Public": "False"}})
    alerts, _, status, _ = run(checks_with(firewall=fw))
    assert ids(alerts) == ["R001"]
    assert alerts[0]["subject"] == "Profil Public"
    assert alerts[0]["severity"] == "Moyen"
    assert status == "a_verifier"


# ------------------------------------------------------------ R002 / R003 antivirus

def test_r002_tous_les_antivirus_inactifs(checks_with):
    av = ok("antivirus", {"products": [{"name": "Windows Defender", "enabled": False}]})
    alerts, _, status, _ = run(checks_with(antivirus=av))
    assert ids(alerts) == ["R002"]
    assert status == "a_risque"


def test_defender_passif_avec_autre_antivirus_actif_ne_declenche_rien(checks_with):
    av = ok("antivirus", {"products": [
        {"name": "Windows Defender", "enabled": False},
        {"name": "McAfee", "enabled": True},
    ]})
    alerts, _, status, _ = run(checks_with(antivirus=av))
    assert alerts == []
    assert status == "aucun_indicateur"


def test_r003_aucun_antivirus_enregistre(checks_with):
    alerts, _, status, _ = run(checks_with(antivirus=ok("antivirus", {"products": []})))
    assert ids(alerts) == ["R003"]
    assert status == "a_verifier"


# ------------------------------------------------------------ R004 mises à jour

def test_r004_limite_de_60_jours(checks_with):
    at_limit = ok("updates", {"hotfix_id": "KB1", "last_update_date": days_ago(60)})
    assert run(checks_with(updates=at_limit))[0] == []

    too_old = ok("updates", {"hotfix_id": "KB1", "last_update_date": days_ago(61)})
    alerts = run(checks_with(updates=too_old))[0]
    assert ids(alerts) == ["R004"]
    assert alerts[0]["severity"] == "Faible"


def test_r004_date_illisible_ne_cree_pas_d_alerte(checks_with):
    bad = ok("updates", {"hotfix_id": "KB1", "last_update_date": "pas-une-date"})
    assert run(checks_with(updates=bad))[0] == []


# ------------------------------------------------------------ R005 démarrage

def entry(signature, publisher=None):
    return ok("startup", {"entries": [{
        "name": "ToolboxHelper", "location": "Startup",
        "path": "%USERPROFILE%\\Tools\\helper.exe",
        "signature": signature, "publisher": publisher,
    }]})


def test_r005_programme_non_signe(checks_with):
    alerts = run(checks_with(startup=entry("NotSigned")))[0]
    assert ids(alerts) == ["R005"]
    assert "ToolboxHelper" in alerts[0]["subject"]


def test_r005_affiche_l_editeur_quand_il_existe(checks_with):
    alerts = run(checks_with(startup=entry("HashMismatch", publisher="Acme SA")))[0]
    assert "Acme SA" in alerts[0]["subject"]


@pytest.mark.parametrize("signature", ["Valid", "Unknown", "FileNotFound"])
def test_r005_pas_d_alerte_si_signature_valide_ou_non_verifiee(checks_with, signature):
    assert run(checks_with(startup=entry(signature)))[0] == []


# ------------------------------------------------------------ R006 processus

@pytest.mark.parametrize("path", [
    "%USERPROFILE%\\Downloads\\setup.exe",
    "%USERPROFILE%\\DOWNLOADS\\SETUP.EXE",  # la casse ne doit pas compter
    "%USERPROFILE%\\AppData\\Local\\Temp\\x.exe",
    "C:\\Users\\Public\\x.exe",
])
def test_r006_emplacement_inhabituel(checks_with, path):
    proc = ok("processes", {"paths": [path], "total_distinct": 1, "sent": 1})
    alerts = run(checks_with(processes=proc))[0]
    assert ids(alerts) == ["R006"]
    assert alerts[0]["subject"] == path


def test_r006_emplacement_normal(checks_with):
    proc = ok("processes", {"paths": ["D:\\Games\\game.exe"], "total_distinct": 1, "sent": 1})
    assert run(checks_with(processes=proc))[0] == []


# ------------------------------------------------------------ R007 connexions

def test_r007_seuil_de_10_echecs(checks_with):
    assert run(checks_with(failed_logons=ok("failed_logons", {"count": 9, "period_hours": 24})))[0] == []
    alerts = run(checks_with(failed_logons=ok("failed_logons", {"count": 10, "period_hours": 24})))[0]
    assert ids(alerts) == ["R007"]
    assert alerts[0]["severity"] == "Moyen"


# ------------------------------------------------------------ combinaisons

def test_plusieurs_problemes_et_statut_global(checks_with):
    fw = ok("firewall", {"profiles": {"Public": "False"}})
    av = ok("antivirus", {"products": [{"name": "X", "enabled": False}]})
    alerts, _, status, _ = run(checks_with(firewall=fw, antivirus=av))
    assert set(ids(alerts)) == {"R001", "R002"}
    assert status == "a_risque"  # une alerte Élevé suffit


# ------------------------------------------------------------ qualité du catalogue

@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_chaque_regle_est_documentee(rule):
    assert rule.id.startswith("R") and rule.id[1:].isdigit()
    assert rule.severity in SEVERITIES
    for field in ("title", "category", "explanation", "recommendation", "limits", "version"):
        assert getattr(rule, field).strip(), f"{rule.id} : champ « {field} » vide"


def test_identifiants_de_regles_uniques():
    all_ids = [r.id for r in RULES]
    assert len(all_ids) == len(set(all_ids))


def test_catalogue_markdown_a_jour():
    catalog = Path(__file__).resolve().parents[2] / "docs" / "rules.md"
    if not catalog.exists():
        pytest.skip("docs/rules.md absent (exécution hors dépôt)")
    text = catalog.read_text(encoding="utf-8")
    hint = "Relancez : cd backend ; python -m app.rules.export_catalog"
    assert f"Version du jeu de règles : {RULESET_VERSION}" in text, hint
    for rule in RULES:
        assert f"## {rule.id} : {rule.title}" in text, hint
