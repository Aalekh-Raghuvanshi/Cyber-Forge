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

@app.get("/v2/store/filter")
def store_filter():
    keyword = request.args.get("keyword", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, name, sku, price FROM products WHERE name LIKE '%" + keyword + "%'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/v2/accounts/by-handle")
def account_by_handle():
    handle = request.args.get("handle", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, email, handle, display_name FROM users WHERE handle = '" + handle + "'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/v2/shipment/state")
def shipment_by_state():
    state = request.args.get("state", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, state, tracking FROM shipments WHERE state = '" + state + "'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/v2/coupons/lookup")
def coupon_lookup():
    code = request.args.get("code", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, code, discount FROM coupons WHERE code = '" + code + "'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/v2/billing/by-customer")
def billing_by_customer():
    customer = request.args.get("customer", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, customer, amount FROM billing WHERE customer = '" + customer + "'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/v2/events/by-actor")
def event_by_actor():
    actor = request.args.get("actor", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, actor, event FROM events WHERE actor = '" + actor + "'" ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/v2/ui/global-search")
def ui_global_search():
    query = request.args.get("query", "")
    return Response(f"<main><h1>Ui Global Search</h1><p>{query}</p></main>", mimetype="text/html")

@app.get("/v2/ui/review/preview")
def review_body_preview():
    body = request.args.get("body", "")
    return Response(f"<main><h1>Review Body Preview</h1><p>{body}</p></main>", mimetype="text/html")

@app.get("/v2/ui/member/badge")
def member_badge():
    label = request.args.get("label", "")
    return Response(f"<main><h1>Member Badge</h1><p>{label}</p></main>", mimetype="text/html")

@app.get("/v2/ui/help/subject")
def help_subject():
    title = request.args.get("title", "")
    return Response(f"<main><h1>Help Subject</h1><p>{title}</p></main>", mimetype="text/html")

@app.get("/v2/ui/promo/caption")
def promo_caption():
    caption = request.args.get("caption", "")
    return Response(f"<main><h1>Promo Caption</h1><p>{caption}</p></main>", mimetype="text/html")

@app.get("/v2/ui/autocomplete")
def autocomplete():
    q = request.args.get("q", "")
    return Response(f"<main><h1>Autocomplete</h1><p>{q}</p></main>", mimetype="text/html")

@app.get("/v2/assets/fetch")
def asset_fetch():
    path = request.args.get("path", "public.txt")
    contents = open(os.path.join(FILES_DIR, path), "r", encoding="utf-8").read()
    return Response(contents, mimetype="text/plain")

@app.get("/v2/archive/open")
def archive_open():
    entry = request.args.get("entry", "public.txt")
    contents = open(os.path.join(FILES_DIR, entry), "r", encoding="utf-8").read()
    return Response(contents, mimetype="text/plain")

@app.get("/v2/invoice/render")
def invoice_render():
    file = request.args.get("file", "public.txt")
    contents = open(os.path.join(FILES_DIR, file), "r", encoding="utf-8").read()
    return Response(contents, mimetype="text/plain")

@app.get("/v2/media/load")
def media_load():
    asset = request.args.get("asset", "public.txt")
    contents = open(os.path.join(FILES_DIR, asset), "r", encoding="utf-8").read()
    return Response(contents, mimetype="text/plain")

@app.get("/v2/login/finish")
def login_finish():
    return redirect(request.args.get("return_to", "/"))

@app.get("/v2/navigate")
def navigate_external():
    return redirect(request.args.get("target", "/"))

@app.get("/v2/system/trace")
def system_trace():
    address = request.args.get("address", "127.0.0.1")
    result = subprocess.run("printf 'probe_B19=' " + address, shell=True, capture_output=True, text=True, timeout=2)
    return Response(result.stdout, mimetype="text/plain")

@app.get("/v2/maintenance/lookup")
def maintenance_lookup():
    node = request.args.get("node", "127.0.0.1")
    result = subprocess.run("printf 'probe_B20=' " + node, shell=True, capture_output=True, text=True, timeout=2)
    return Response(result.stdout, mimetype="text/plain")

@app.get("/v2/catalog/lookup")
def find_products():
    keyword = request.args.get("keyword", "")
    connection = db_connect()
    rows = connection.execute("SELECT id, name FROM products WHERE name LIKE ?", (f"%{keyword}%",)).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/v2/catalog/order")
def sort_products():
    sort = request.args.get("sort", "name")
    sort = sort if sort in {"name", "price"} else "name"
    query = f"SELECT id, name FROM products ORDER BY {sort}"
    connection = db_connect()
    rows = connection.execute(query).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])

@app.get("/v2/view/preview")
def render_preview():
    query = request.args.get("query", "")
    return Response(f"<h1>{escape(query)}</h1>", mimetype="text/html")

@app.get("/v2/view/template-preview")
def render_template_preview():
    value = request.args.get("value", "")
    return render_template_string("<p>{{ value }}</p>", value=value)

@app.get("/v2/storage/get")
def download_preview():
    path = request.args.get("path", "public.txt")
    base = FILES_DIR.resolve()
    candidate = (base / path).resolve()
    if not candidate.is_relative_to(base):
        abort(400)
    return Response(candidate.read_text(encoding="utf-8"), mimetype="text/plain")

@app.get("/v2/storage/serve")
def get_media():
    path = request.args.get("path", "public.txt")
    try:
        return send_from_directory(FILES_DIR, path, as_attachment=False)
    except Exception:
        abort(404)

@app.get("/v2/auth/return")
def auth_local_return():
    return_to = request.args.get("return_to", "/")
    allowed = {"/", "/dashboard", "/profile"}
    target = return_to if return_to in allowed else "/"
    return redirect(target)

@app.get("/v2/navigation/local")
def navigate_local():
    next = request.args.get("next", "/")
    parsed = urlparse(next)
    target = next if not parsed.scheme and not parsed.netloc and next.startswith("/") else "/"
    return redirect(target)

@app.get("/v2/tools/echo")
def echo_utility():
    value = request.args.get("value", "hello")
    result = subprocess.run(["/bin/echo", value], shell=False, capture_output=True, text=True, timeout=2)
    return Response(result.stdout, mimetype="text/plain")

@app.get("/v2/tools/host")
def host_utility():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run(["/bin/echo", "host=" + host], shell=False, capture_output=True, text=True, timeout=2)
    return Response(result.stdout, mimetype="text/plain")

@app.get("/")
def index():
    items = "\n".join([
        '<li><a href="/v2/store/filter?keyword=Widget">Store Filter endpoint</a></li>',
        '<li><a href="/v2/accounts/by-handle?handle=safe-value">Account By Handle endpoint</a></li>',
        '<li><a href="/v2/shipment/state?state=safe-value">Shipment By State endpoint</a></li>',
        '<li><a href="/v2/coupons/lookup?code=safe-value">Coupon Lookup endpoint</a></li>',
        '<li><a href="/v2/billing/by-customer?customer=safe-value">Billing By Customer endpoint</a></li>',
        '<li><a href="/v2/events/by-actor?actor=safe-value">Event By Actor endpoint</a></li>',
        '<li><a href="/v2/ui/global-search?query=hello">Ui Global Search page</a></li>',
        '<li><a href="/v2/ui/review/preview?body=hello">Review Body Preview page</a></li>',
        '<li><a href="/v2/ui/member/badge?label=hello">Member Badge page</a></li>',
        '<li><a href="/v2/ui/help/subject?title=hello">Help Subject page</a></li>',
        '<li><a href="/v2/ui/promo/caption?caption=hello">Promo Caption page</a></li>',
        '<li><a href="/v2/ui/autocomplete?q=hello">Autocomplete page</a></li>',
        '<li><a href="/v2/assets/fetch?path=public.txt">Asset Fetch resource</a></li>',
        '<li><a href="/v2/archive/open?entry=public.txt">Archive Open resource</a></li>',
        '<li><a href="/v2/invoice/render?file=public.txt">Invoice Render resource</a></li>',
        '<li><a href="/v2/media/load?asset=public.txt">Media Load resource</a></li>',
        '<li><a href="/v2/login/finish?return_to=%2F">Login Finish navigation</a></li>',
        '<li><a href="/v2/navigate?target=%2F">Navigate External navigation</a></li>',
        '<li><a href="/v2/system/trace?address=127.0.0.1">System Trace diagnostics</a></li>',
        '<li><a href="/v2/maintenance/lookup?node=127.0.0.1">Maintenance Lookup diagnostics</a></li>',
        '<li><a href="/v2/catalog/lookup?keyword=Widget">Product search endpoint</a></li>',
        '<li><a href="/v2/catalog/order?sort=name">Product sorting endpoint</a></li>',
        '<li><a href="/v2/view/preview?query=hello">Content preview page</a></li>',
        '<li><a href="/v2/view/template-preview?value=hello">Template preview page</a></li>',
        '<li><a href="/v2/storage/get?path=public.txt">Download preview resource</a></li>',
        '<li><a href="/v2/storage/serve?path=public.txt">Media resource endpoint</a></li>',
        '<li><a href="/v2/auth/return?return_to=/dashboard">Authentication return endpoint</a></li>',
        '<li><a href="/v2/navigation/local?next=/profile">Local navigation endpoint</a></li>',
        '<li><a href="/v2/tools/echo?value=hello">Utility echo endpoint</a></li>',
        '<li><a href="/v2/tools/host?host=127.0.0.1">Host utility endpoint</a></li>'
    ])
    return Response("<html><body><h1>Security Benchmark Surface</h1><ul>" + items + "</ul></body></html>", mimetype="text/html")

initialize_database()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
