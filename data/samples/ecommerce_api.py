"""
Sample E-Commerce API for SAST + DAST Correlation Engine
Contains routes with deliberate vulnerabilities to test correlation.
"""

import os
import sqlite3
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# FR-1 Hardcoded Secret (CWE-798 - Code Only)
DATABASE_PASSWORD = "SuperSecretDbPassword123!"
JWT_SIGNING_SECRET = "sk-live-9876543210abcdefghijklmnop"

@app.route("/api/ping", methods=["GET"])
def ping_host():
    """OS Command Injection (CWE-78)"""
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return jsonify({"status": "ok", "output": output.decode()})

@app.route("/api/search", methods=["GET"])
def search_catalog():
    """Cross-Site Scripting (CWE-79)"""
    query = request.args.get("q", "")
    return f"<h1>Search results for: {query}</h1>"

@app.route("/api/orders", methods=["GET"])
def get_orders():
    """SQL Injection (CWE-89) - Correlates with DAST on /api/orders"""
    order_id = request.args.get("id", "")
    conn = sqlite3.connect("ecommerce.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM orders WHERE id = '{order_id}'"
    cursor.execute(query)
    records = cursor.fetchall()
    return jsonify({"orders": records})

@app.route("/api/download", methods=["GET"])
def download_invoice():
    """Path Traversal (CWE-22)"""
    filename = request.args.get("file", "invoice.pdf")
    filepath = os.path.join("/var/invoices", filename)
    with open(filepath, "r") as f:
        content = f.read()
    return content

if __name__ == "__main__":
    app.run(port=5000, debug=True)
