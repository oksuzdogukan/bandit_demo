import os
import pickle
import subprocess
import hashlib
import sqlite3
import yaml
import requests
import random

PASSWORD = "admin123"                      # B105: sabit şifre
API_KEY = "sk-test-12345"                  # B105

def run_cmd(user_input):
    os.system("ping " + user_input)        # B605: komut enjeksiyonu
    subprocess.call(user_input, shell=True)  # B602: shell=True

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # B324: zayıf hash

def get_user(name):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)  # B608: SQL injection
    return cur.fetchall()

def load_data(data):
    return pickle.loads(data)              # B301: güvensiz deserialization

def load_config(text):
    return yaml.load(text)                 # B506: güvensiz yaml.load

def fetch(url):
    return requests.get(url, verify=False) # B501: SSL doğrulama kapalı

def make_token():
    return random.randint(0, 999999)       # B311: kriptografik olmayan rastgelelik

def calc(expr):
    return eval(expr)                      # B307: eval

assert PASSWORD != ""                      # B101: assert kullanımı