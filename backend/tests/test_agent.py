import sys
from pathlib import Path

import pytest

AGENT_DIR = Path(__file__).resolve().parents[2] / "agent"
if not (AGENT_DIR / "audit.py").exists():
    pytest.skip("dossier agent/ absent", allow_module_level=True)
sys.path.insert(0, str(AGENT_DIR))

import audit  # noqa: E402


def test_extract_exe_path_supprime_les_arguments():
    command = '"C:\\Program Files\\App\\app.exe" --token=SECRET'
    path = audit.extract_exe_path(command)
    assert path == "C:\\Program Files\\App\\app.exe"
    assert "SECRET" not in path


def test_extract_exe_path_sans_guillemets():
    assert audit.extract_exe_path("C:\\Tools\\tool.exe -k secret") == "C:\\Tools\\tool.exe"
    assert audit.extract_exe_path("C:\\Tools\\TOOL.EXE /x") == "C:\\Tools\\TOOL.EXE"


@pytest.mark.parametrize("command", ["", None, "rundll32 shell.dll,Run"])
def test_extract_exe_path_sans_executable(command):
    assert audit.extract_exe_path(command) is None


def test_anonymize_path_masque_le_dossier_utilisateur(monkeypatch):
    monkeypatch.setattr(audit.os.path, "expanduser", lambda p: "C:\\Users\\alice")
    assert audit.anonymize_path("C:\\Users\\Alice\\Downloads\\x.exe") == "%USERPROFILE%\\Downloads\\x.exe"
    assert audit.anonymize_path("D:\\Games\\x.exe") == "D:\\Games\\x.exe"


def test_is_system_path(monkeypatch):
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setenv("ProgramFiles", "C:\\Program Files")
    monkeypatch.setenv("ProgramFiles(x86)", "C:\\Program Files (x86)")
    assert audit.is_system_path("C:\\Windows\\System32\\cmd.exe")
    assert audit.is_system_path("c:\\program files\\app\\a.exe")
    assert not audit.is_system_path("C:\\Windowsfake\\x.exe")
    assert not audit.is_system_path("C:\\Users\\alice\\x.exe")


def test_as_list():
    assert audit.as_list("") == []
    assert audit.as_list('{"a": 1}') == [{"a": 1}]
    assert audit.as_list('[{"a": 1}, {"a": 2}]') == [{"a": 1}, {"a": 2}]


def test_controle_en_echec_devient_indisponible():
    def boom():
        raise RuntimeError("accès refusé")

    result = audit.safe_check("firewall", boom)
    assert result["status"] == "unavailable"
    assert "accès refusé" in result["error"]
    assert "data" not in result


def test_controle_reussi_et_simule():
    assert audit.safe_check("x", lambda: {"a": 1}) == {"id": "x", "status": "ok", "data": {"a": 1}}
    simulated = audit.safe_check("x", lambda: {"a": 1}, simulate_unavailable=("x",))
    assert simulated["status"] == "unavailable"


def test_message_d_erreur_tronque():
    def boom():
        raise RuntimeError("x" * 1000)

    assert len(audit.safe_check("x", boom)["error"]) == 300


def test_http_distant_refuse(monkeypatch):
    monkeypatch.setattr(audit, "API_URL", "http://exemple.com")
    with pytest.raises(SystemExit):
        audit.check_transport_is_safe()


@pytest.mark.parametrize("url", [
    "http://localhost:8000", "http://127.0.0.1:8000",
    "https://localhost:8443", "https://exemple.com",
])
def test_urls_autorisees(monkeypatch, url):
    monkeypatch.setattr(audit, "API_URL", url)
    audit.check_transport_is_safe()
