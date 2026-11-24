"""Bandit demo: vulnerable_app.py dosyasının düzeltilmiş hali."""
import ast
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import subprocess  # nosec B404 - sadece sabit argüman listesiyle, shell olmadan kullanılıyor

import requests
import yaml

# Sırlar koddan çıkarıldı, ortam değişkeninden okunuyor
PASSWORD = os.environ.get("APP_PASSWORD")
API_TOKEN = os.environ.get("APP_API_TOKEN")

# Hostname / IPv4 için basit beyaz liste doğrulaması
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def ping_host(host):
    if not HOST_RE.fullmatch(host):
        raise ValueError("Geçersiz host adı")
    # shell yok, argümanlar liste olarak veriliyor: komut enjeksiyonu mümkün değil
    result = subprocess.run(  # nosec B603 - host yukarıda doğrulandı, shell=False
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result.stdout


def hash_password(pw, salt=None):
    """PBKDF2-HMAC-SHA256 + rastgele salt (standart kütüphane)."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000)
    return salt.hex() + ":" + digest.hex()


def verify_password(pw, stored):
    salt_hex, digest_hex = stored.split(":")
    candidate = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), 600_000)
    return hmac.compare_digest(candidate.hex(), digest_hex)  # sabit zamanlı karşılaştırma


def get_user(name):
    conn = sqlite3.connect("app.db")
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE name = ?", (name,))  # parametreli sorgu
        return cur.fetchall()
    finally:
        conn.close()


def load_data(data):
    return json.loads(data)  # pickle yerine güvenli format


def load_config(text):
    return yaml.safe_load(text)


def fetch(url):
    # verify varsayılan olarak True, timeout eklendi
    return requests.get(url, timeout=10)


def make_token():
    return secrets.token_hex(16)  # kriptografik olarak güvenli


def calc(expr):
    return ast.literal_eval(expr)  # sadece literal'ler (sayı, string, liste...), kod çalıştırmaz


def check_admin(user):
    if user != "admin":
        raise PermissionError("Yetkisiz kullanıcı")
    return True