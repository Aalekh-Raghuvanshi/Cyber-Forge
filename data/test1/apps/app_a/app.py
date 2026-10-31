from __future__ import annotations

import os
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, Response, abort, jsonify, redirect, render_template_string, request, send_from_directory
from markupsafe import escape

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
ROOT_DIR = Path(__file__).resolve().parent
FILES_DIR = ROOT_DIR / "data" / "files"
DB_PATH = os.environ.get("DB_PATH", "/tmp/benchmark.sqlite3")


def db_connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = db_connect()
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, sku TEXT, price INTEGER);
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, handle TEXT, display_name TEXT);
        CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, status TEXT, owner TEXT, customer TEXT);
        CREATE TABLE IF NOT EXISTS inventory (id INTEGER PRIMARY KEY, sku TEXT, description TEXT);
        CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY, owner TEXT, title TEXT);
        CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, actor TEXT, event TEXT);
        CREATE TABLE IF NOT EXISTS shipments (id INTEGER PRIMARY KEY, state TEXT, tracking TEXT);
        CREATE TABLE IF NOT EXISTS coupons (id INTEGER PRIMARY KEY, code TEXT, discount INTEGER);
        CREATE TABLE IF NOT EXISTS billing (id INTEGER PRIMARY KEY, customer TEXT, amount INTEGER);
        CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, actor TEXT, event TEXT);
    """)
    connection.executemany("INSERT OR IGNORE INTO products VALUES (?, ?, ?, ?)", [
        (1, "Widget", "SKU-100", 25), (2, "Gadget", "SKU-200", 40), (3, "Cable", "SKU-300", 8)
    ])
    connection.executemany("INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?)", [
        (1, "ada@example.test", "ada", "Ada Lovelace"),
        (2, "grace@example.test", "grace", "Grace Hopper"),
        (3, "linus@example.test", "linus", "Linus Example")
    ])
    connection.executemany("INSERT OR IGNORE INTO orders VALUES (?, ?, ?, ?)", [
        (1, "open", "ada", "acme"), (2, "closed", "grace", "globex"), (3, "open", "linus", "initech")
    ])
    connection.executemany("INSERT OR IGNORE INTO inventory VALUES (?, ?, ?)", [
        (1, "SKU-100", "Widget stock"), (2, "SKU-200", "Gadget stock"), (3, "SKU-300", "Cable stock")
    ])
    connection.executemany("INSERT OR IGNORE INTO reports VALUES (?, ?, ?)", [
        (1, "ada", "Quarterly"), (2, "grace", "Operations"), (3, "linus", "Usage")
    ])
    connection.executemany("INSERT OR IGNORE INTO audit VALUES (?, ?, ?)", [
        (1, "ada", "login"), (2, "grace", "export"), (3, "linus", "update")
    ])
    connection.executemany("INSERT OR IGNORE INTO shipments VALUES (?, ?, ?)", [
        (1, "queued", "TRK-001"), (2, "sent", "TRK-002"), (3, "delivered", "TRK-003")
    ])
    connection.executemany("INSERT OR IGNORE INTO coupons VALUES (?, ?, ?)", [
        (1, "SAVE10", 10), (2, "WELCOME", 15), (3, "SPRING", 20)
    ])
    connection.executemany("INSERT OR IGNORE INTO billing VALUES (?, ?, ?)", [
        (1, "acme", 120), (2, "globex", 240), (3, "initech", 360)
    ])
    connection.executemany("INSERT OR IGNORE INTO events VALUES (?, ?, ?)", [
        (1, "ada", "created"), (2, "grace", "approved"), (3, "linus", "deleted")
    ])
    connection.commit()
    connection.close()


@app.get("/__health")
def health():
    return jsonify({"status": "ok"})

@app.get("/api/catalog/search")
def product_search():
    term = request.args.get("term", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, name, sku, price FROM products WHERE name LIKE '%" + term + "%'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/api/customers/lookup")
def customer_lookup():
    email = request.args.get("email", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, email, handle, display_name FROM users WHERE email = '" + email + "'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/api/orders/status")
def order_status():
    status = request.args.get("status", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, status, owner, customer FROM orders WHERE status = '" + status + "'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/api/warehouse/sku")
def inventory_sku():
    sku = request.args.get("sku", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, sku, description FROM inventory WHERE sku = '" + sku + "'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/api/reports/owner")
def report_owner():
    owner = request.args.get("owner", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, owner, title FROM reports WHERE owner = '" + owner + "'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/api/audit/actor")
def audit_actor():
    actor = request.args.get("actor", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, actor, event FROM audit WHERE actor = '" + actor + "'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/ui/search")
def search_reflection():
    q = request.args.get("q", "")
    return Response(f"<main><h1>Search Reflection</h1><p>{q}</p></main>", mimetype="text/html")

@app.get("/ui/feedback/preview")
def feedback_preview():
    message = request.args.get("message", "")
    return Response(f"<main><h1>Feedback Preview</h1><p>{message}</p></main>", mimetype="text/html")

@app.get("/ui/profile/card")
def profile_card():
    name = request.args.get("name", "")
    return Response(f"<main><h1>Profile Card</h1><p>{name}</p></main>", mimetype="text/html")

@app.get("/ui/support/preview")
def ticket_preview():
    subject = request.args.get("subject", "")
    return Response(f"<main><h1>Ticket Preview</h1><p>{subject}</p></main>", mimetype="text/html")

@app.get("/ui/campaign/banner")
def campaign_banner():
    text = request.args.get("text", "")
    return Response(f"<main><h1>Campaign Banner</h1><p>{text}</p></main>", mimetype="text/html")

@app.get("/ui/catalog/suggest")
def catalog_suggest():
    term = request.args.get("term", "")
    return Response(f"<main><h1>Catalog Suggest</h1><p>{term}</p></main>", mimetype="text/html")

@app.get("/files/download")
def file_download():
    filename = request.args.get("filename", "public.txt")
    contents = open(os.path.join(FILES_DIR, filename), "r", encoding="utf-8").read()
    return Response(contents, mimetype="text/plain")

@app.get("/docs/view")
def document_view():
    doc = request.args.get("doc", "public.txt")
    contents = open(os.path.join(FILES_DIR, doc), "r", encoding="utf-8").read()
    return Response(contents, mimetype="text/plain")

@app.get("/reports/export")
def report_export():
    name = request.args.get("name", "public.txt")
    contents = open(os.path.join(FILES_DIR, name), "r", encoding="utf-8").read()
    return Response(contents, mimetype="text/plain")

@app.get("/avatars/load")
def avatar_load():
    file = request.args.get("file", "public.txt")
    contents = open(os.path.join(FILES_DIR, file), "r", encoding="utf-8").read()
    return Response(contents, mimetype="text/plain")

@app.get("/auth/continue")
def auth_continue():
    return redirect(request.args.get("next", "/"))

@app.get("/links/open")
def external_link():
    return redirect(request.args.get("to", "/"))

@app.get("/admin/diagnostics/ping")
def diagnostic_ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run("printf 'probe_A19=' " + host, shell=True, capture_output=True, text=True, timeout=2)
    return Response(result.stdout, mimetype="text/plain")

@app.get("/ops/check")
def ops_check():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run("printf 'probe_A20=' " + host, shell=True, capture_output=True, text=True, timeout=2)
    return Response(result.stdout, mimetype="text/plain")

@app.get("/api/products/find")
def find_products():
    term = request.args.get("term", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, name FROM products WHERE name LIKE ?", (f"%{term}%",)).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/api/products/sort")
def sort_products():
    sort = request.args.get("sort", "name")
    sort = sort if sort in {"name", "price"} else "name"
    query = f"SELECT id, name FROM products ORDER BY {sort}"
    connection = db_connect()
    rows = connection.execute(query).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/ui/preview")
def render_preview():
    q = request.args.get("q", "")
    return Response(f"<h1>{escape(q)}</h1>", mimetype="text/html")

@app.get("/ui/template-preview")
def render_template_preview():
    value = request.args.get("value", "")
    return render_template_string("<p>{{ value }}</p>", value=value)

@app.get("/files/download-preview")
def download_preview():
    filename = request.args.get("filename", "public.txt")
    base = FILES_DIR.resolve()
    candidate = (base / filename).resolve()
    if not candidate.is_relative_to(base):
        abort(400)
    return Response(candidate.read_text(encoding="utf-8"), mimetype="text/plain")

@app.get("/media/get")
def get_media():
    filename = request.args.get("filename", "public.txt")
    try:
        return send_from_directory(FILES_DIR, filename, as_attachment=False)
    except Exception:
        abort(404)

@app.get("/auth/local-return")
def auth_local_return():
    next = request.args.get("next", "/")
    allowed = {"/", "/dashboard", "/profile"}
    target = next if next in allowed else "/"
    return redirect(target)

@app.get("/links/relative")
def navigate_local():
    next = request.args.get("next", "/")
    parsed = urlparse(next)
    target = next if not parsed.scheme and not parsed.netloc and next.startswith("/") else "/"
    return redirect(target)

@app.get("/tools/echo")
def echo_utility():
    value = request.args.get("value", "hello")
    result = subprocess.run(["/bin/echo", value], shell=False, capture_output=True, text=True, timeout=2)
    return Response(result.stdout, mimetype="text/plain")

@app.get("/tools/hostname")
def host_utility():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run(["/bin/echo", "host=" + host], shell=False, capture_output=True, text=True, timeout=2)
    return Response(result.stdout, mimetype="text/plain")

@app.get("/")
def index():
    items = "\n".join([
        '<li><a href="/api/catalog/search?term=Widget">Product Search endpoint</a></li>',
        '<li><a href="/api/customers/lookup?email=safe-value">Customer Lookup endpoint</a></li>',
        '<li><a href="/api/orders/status?status=safe-value">Order Status endpoint</a></li>',
        '<li><a href="/api/warehouse/sku?sku=safe-value">Inventory Sku endpoint</a></li>',
        '<li><a href="/api/reports/owner?owner=safe-value">Report Owner endpoint</a></li>',
        '<li><a href="/api/audit/actor?actor=safe-value">Audit Actor endpoint</a></li>',
        '<li><a href="/ui/search?q=hello">Search Reflection page</a></li>',
        '<li><a href="/ui/feedback/preview?message=hello">Feedback Preview page</a></li>',
        '<li><a href="/ui/profile/card?name=hello">Profile Card page</a></li>',
        '<li><a href="/ui/support/preview?subject=hello">Ticket Preview page</a></li>',
        '<li><a href="/ui/campaign/banner?text=hello">Campaign Banner page</a></li>',
        '<li><a href="/ui/catalog/suggest?term=hello">Catalog Suggest page</a></li>',
        '<li><a href="/files/download?filename=public.txt">File Download resource</a></li>',
        '<li><a href="/docs/view?doc=public.txt">Document View resource</a></li>',
        '<li><a href="/reports/export?name=public.txt">Report Export resource</a></li>',
        '<li><a href="/avatars/load?file=public.txt">Avatar Load resource</a></li>',
        '<li><a href="/auth/continue?next=%2F">Auth Continue navigation</a></li>',
        '<li><a href="/links/open?to=%2F">External Link navigation</a></li>',
        '<li><a href="/admin/diagnostics/ping?host=127.0.0.1">Diagnostic Ping diagnostics</a></li>',
        '<li><a href="/ops/check?host=127.0.0.1">Ops Check diagnostics</a></li>',
        '<li><a href="/api/products/find?term=Widget">Product search endpoint</a></li>',
        '<li><a href="/api/products/sort?sort=name">Product sorting endpoint</a></li>',
        '<li><a href="/ui/preview?q=hello">Content preview page</a></li>',
        '<li><a href="/ui/template-preview?value=hello">Template preview page</a></li>',
        '<li><a href="/files/download-preview?filename=public.txt">Download preview resource</a></li>',
        '<li><a href="/media/get?filename=public.txt">Media resource endpoint</a></li>',
        '<li><a href="/auth/local-return?next=/dashboard">Authentication return endpoint</a></li>',
        '<li><a href="/links/relative?next=/profile">Local navigation endpoint</a></li>',
        '<li><a href="/tools/echo?value=hello">Utility echo endpoint</a></li>',
        '<li><a href="/tools/hostname?host=127.0.0.1">Host utility endpoint</a></li>'
    ])
    return Response("<html><body><h1>Security Benchmark Surface</h1><ul>" + items + "</ul></body></html>", mimetype="text/html")

initialize_database()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
