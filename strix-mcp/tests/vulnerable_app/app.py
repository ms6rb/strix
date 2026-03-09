"""Intentionally vulnerable Flask app for integration testing.
DO NOT deploy this anywhere — it contains real vulnerabilities by design.
"""
import sqlite3
from flask import Flask, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@test.com')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'user@test.com')")
    conn.commit()
    return conn


@app.route("/")
def index():
    return "<h1>Vulnerable Test App</h1><a href='/search?q=test'>Search</a>"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN: Reflected XSS — user input rendered without escaping
    conn = get_db()
    # VULN: SQL Injection — user input concatenated into query
    cursor = conn.execute(f"SELECT * FROM users WHERE name LIKE '%{q}%'")
    results = cursor.fetchall()
    conn.close()
    return f"<h1>Search: {q}</h1><pre>{results}</pre>"


@app.route("/api/users")
def api_users():
    conn = get_db()
    cursor = conn.execute("SELECT * FROM users")
    users = [{"id": r[0], "name": r[1], "email": r[2]} for r in cursor.fetchall()]
    conn.close()
    return {"users": users}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
