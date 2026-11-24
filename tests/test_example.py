"""fixed_app.py için pytest testleri + Bandit'i test sürecine bağlayan güvenlik testi."""
import json
import os
import sqlite3
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fixed_app  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------- Yardımcı: örnek veritabanı ----------
@pytest.fixture
def db(tmp_path, monkeypatch):
    """Geçici klasörde app.db oluşturur (get_user 'app.db' dosyasını açar)."""
    monkeypatch.chdir(tmp_path)
    conn = sqlite3.connect("app.db")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    conn.executemany("INSERT INTO users VALUES (?, ?)", [(1, "alice"), (2, "bob")])
    conn.commit()
    conn.close()


# ---------- Komut enjeksiyonu (B602 / B605) ----------
@pytest.mark.parametrize("payload", ["8.8.8.8; rm -rf /", "$(whoami)", "a && ls", "host name"])
def test_ping_rejects_injection(payload):
    with pytest.raises(ValueError):
        fixed_app.ping_host(payload)


def test_ping_uses_list_args_without_shell(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(fixed_app.subprocess, "run", fake_run)
    assert fixed_app.ping_host("example.com") == "ok"
    assert isinstance(captured["cmd"], list)
    assert not captured["kwargs"].get("shell", False)
    assert "timeout" in captured["kwargs"]


# ---------- Şifre hashleme (B324) ----------
def test_hash_password_roundtrip():
    stored = fixed_app.hash_password("gizli123")
    assert fixed_app.verify_password("gizli123", stored)
    assert not fixed_app.verify_password("yanlis", stored)


def test_hash_password_uses_random_salt():
    assert fixed_app.hash_password("aynisifre") != fixed_app.hash_password("aynisifre")


# ---------- SQL injection (B608) ----------
def test_get_user_normal(db):
    assert fixed_app.get_user("alice") == [(1, "alice")]


def test_get_user_sql_injection_blocked(db):
    assert fixed_app.get_user("' OR '1'='1") == []


def test_vulnerable_version_is_actually_injectable(db):
    """Karşılaştırma: zafiyetli sürümde aynı payload tüm kullanıcıları döndürür."""
    import vulnerable_app
    assert len(vulnerable_app.get_user("' OR '1'='1")) == 2


# ---------- Deserialization (B301 / B506) ----------
def test_load_data_json():
    assert fixed_app.load_data('{"a": 1}') == {"a": 1}


def test_yaml_safe_load_blocks_code_execution():
    import yaml
    evil = '!!python/object/apply:os.system ["echo hacked"]'
    with pytest.raises(yaml.YAMLError):
        fixed_app.load_config(evil)


# ---------- eval (B307) ----------
def test_calc_accepts_literals():
    assert fixed_app.calc("[1, 2, 3]") == [1, 2, 3]


def test_calc_rejects_code():
    with pytest.raises(ValueError):
        fixed_app.calc("__import__('os').system('echo hacked')")


# ---------- Rastgelelik (B311) ----------
def test_make_token_format_and_uniqueness():
    t1, t2 = fixed_app.make_token(), fixed_app.make_token()
    assert len(t1) == 32 and t1 != t2


# ---------- assert yerine istisna (B101) ----------
def test_check_admin():
    assert fixed_app.check_admin("admin") is True
    with pytest.raises(PermissionError):
        fixed_app.check_admin("misafir")


# ---------- SSL / timeout (B501 / B113) ----------
def test_fetch_has_timeout_and_keeps_ssl_verification(monkeypatch):
    captured = {}
    monkeypatch.setattr(fixed_app.requests, "get", lambda url, **kw: captured.update(kw))
    fixed_app.fetch("https://example.com")
    assert captured.get("timeout")
    assert captured.get("verify", True) is True


# ---------- Bandit'i testin içine bağlama ----------
def _run_bandit(target):
    pytest.importorskip("bandit")
    proc = subprocess.run(
        [sys.executable, "-m", "bandit", "-f", "json", "-ll", target],
        capture_output=True, text=True, cwd=ROOT,
    )
    return json.loads(proc.stdout)["results"]


def test_bandit_finds_no_medium_or_high_issues_in_fixed_app():
    assert _run_bandit("fixed_app.py") == []


def test_bandit_detects_known_issues_in_vulnerable_app():
    ids = {r["test_id"] for r in _run_bandit("vulnerable_app.py")}
    assert {"B602", "B605", "B608"} <= ids