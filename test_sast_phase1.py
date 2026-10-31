"""
Comprehensive Phase 1 Verification Tests.
Validates:
- FR-1: Primary SAST Detector for 6 core vulnerability types with canonical CWEs
- FR-3: Common Finding Format, Canonical CWE Normalizer, and Deterministic SHA256 Fingerprinting
- FR-4: AST Route Map Extractor and Finding Route Enrichment
- API: POST /api/sast/scan and GET /api/sast/routes endpoints
"""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.models.schemas import RouteEntry, UnifiedFinding, SASTScanResponse, CorrelatedIssue
from backend.services.cwe_normalizer import normalize_cwe, compute_dedup_key, CANONICAL_CWE_METADATA
from backend.services.route_mapper import (
    extract_routes_from_python_code,
    extract_routes_from_js_code,
    extract_routes_from_folder,
    find_matching_route,
    enrich_finding_with_route
)
from backend.services.static_analyzer import get_static_analyzer
from backend.services.sast_scanner import get_sast_scanner_service
from backend.app import app


# ---------------------------------------------------------------------------
# Test 1: FR-3 Canonical CWE Normalizer & Deduplication Fingerprints
# ---------------------------------------------------------------------------

def test_cwe_normalizer_canonical_mappings():
    """Verify variant and child CWEs map deterministically to the 6 core canonical CWEs."""
    # 1. SQL Injection -> CWE-89
    cwe, name, sev, _ = normalize_cwe("CWE-89")
    assert cwe == "CWE-89"
    assert "SQL" in name

    cwe_child, _, _, _ = normalize_cwe("CWE-564")  # Hibernate injection
    assert cwe_child == "CWE-89"

    cwe_kw, _, _, _ = normalize_cwe(None, rule_name="python.sqlalchemy.injection")
    assert cwe_kw == "CWE-89"

    # 2. XSS -> CWE-79
    cwe, name, sev, _ = normalize_cwe("CWE-79")
    assert cwe == "CWE-79"
    cwe_child, _, _, _ = normalize_cwe("CWE-80")
    assert cwe_child == "CWE-79"
    cwe_kw, _, _, _ = normalize_cwe(None, rule_name="javascript.express.security.audit.xss")
    assert cwe_kw == "CWE-79"

    # 3. Path Traversal -> CWE-22
    cwe, name, sev, _ = normalize_cwe("CWE-22")
    assert cwe == "CWE-22"
    cwe_child, _, _, _ = normalize_cwe("CWE-23")
    assert cwe_child == "CWE-22"
    cwe_kw, _, _, _ = normalize_cwe(None, rule_name="python.lang.security.path-traversal")
    assert cwe_kw == "CWE-22"

    # 4. OS Command Injection -> CWE-78
    cwe, name, sev, _ = normalize_cwe("CWE-78")
    assert cwe == "CWE-78"
    cwe_child, _, _, _ = normalize_cwe("CWE-88")
    assert cwe_child == "CWE-78"
    cwe_kw, _, _, _ = normalize_cwe(None, rule_name="python.subprocess.command-injection")
    assert cwe_kw == "CWE-78"

    # 5. Hardcoded Credentials -> CWE-798
    cwe, name, sev, _ = normalize_cwe("CWE-798")
    assert cwe == "CWE-798"
    cwe_child, _, _, _ = normalize_cwe("CWE-259")
    assert cwe_child == "CWE-798"
    cwe_kw, _, _, _ = normalize_cwe(None, rule_name="generic.secrets.security.hardcoded-secret")
    assert cwe_kw == "CWE-798"

    # 6. Weak Hashing -> CWE-328
    cwe, name, sev, _ = normalize_cwe("CWE-328")
    assert cwe == "CWE-328"
    cwe_child, _, _, _ = normalize_cwe("CWE-327")
    assert cwe_child == "CWE-328"
    cwe_kw, _, _, _ = normalize_cwe(None, rule_name="python.hashlib.md5-sha1-weak-hash")
    assert cwe_kw == "CWE-328"


def test_dedup_key_determinism():
    """Verify dedup_key produces exact SHA256 matches and merges duplicates across scans."""
    key1 = compute_dedup_key("SAST", "orders.py", 88, "CWE-89")
    key2 = compute_dedup_key("SAST", "./orders.py", 88, "cwe-89")
    key3 = compute_dedup_key("SAST", "orders.py", 89, "CWE-89")

    # Normalized relative paths and uppercase CWE should match
    assert key1 == key2
    # Different line number must have distinct hash
    assert key1 != key3
    assert len(key1) == 64


# ---------------------------------------------------------------------------
# Test 2: FR-1 Deterministic SAST Detection (All 6 Core Vulnerabilities)
# ---------------------------------------------------------------------------

def test_sast_detects_sql_injection():
    """Deterministic detection of SQL Injection (CWE-89)."""
    code = """
def get_user_orders(user_id):
    query = "SELECT * FROM orders WHERE user_id = '%s'" % user_id
    cursor.execute(query)
"""
    analyzer = get_static_analyzer()
    findings = analyzer.analyze_code(code, file_path="orders.py")
    assert any(f.cwe_id == "CWE-89" for f in findings)
    sql_finding = next(f for f in findings if f.cwe_id == "CWE-89")
    assert sql_finding.severity in ("CRITICAL", "HIGH")
    assert sql_finding.file == "orders.py"
    assert sql_finding.line > 0


def test_sast_detects_xss():
    """Deterministic detection of XSS (CWE-79)."""
    code = """
from flask import render_template_string

def render_profile(bio):
    template = "<div>User bio: " + bio + "</div>"
    return render_template_string(template)
"""
    analyzer = get_static_analyzer()
    findings = analyzer.analyze_code(code, file_path="profile.py")
    assert any(f.cwe_id == "CWE-79" for f in findings)
    xss_finding = next(f for f in findings if f.cwe_id == "CWE-79")
    assert xss_finding.cwe_id == "CWE-79"


def test_sast_detects_path_traversal():
    """Deterministic detection of Path Traversal (CWE-22)."""
    code = """
def view_file(user_path):
    with open("/data/files/" + user_path, "r") as f:
        return f.read()
"""
    analyzer = get_static_analyzer()
    findings = analyzer.analyze_code(code, file_path="files.py")
    assert any(f.cwe_id == "CWE-22" for f in findings)
    finding = next(f for f in findings if f.cwe_id == "CWE-22")
    assert "Path Traversal" in finding.vulnerability_type


def test_sast_detects_command_injection():
    """Deterministic detection of OS Command Injection (CWE-78)."""
    code = """
import os
import subprocess

def ping_host(host):
    os.system("ping -c 1 " + host)
    subprocess.call("echo " + host, shell=True)
"""
    analyzer = get_static_analyzer()
    findings = analyzer.analyze_code(code, file_path="network.py")
    assert any(f.cwe_id == "CWE-78" for f in findings)
    finding = next(f for f in findings if f.cwe_id == "CWE-78")
    assert finding.severity == "CRITICAL"


def test_sast_detects_hardcoded_secrets():
    """Deterministic detection of Hardcoded Secrets (CWE-798)."""
    code = """
AWS_SECRET_KEY = "AKIA1234567890ABCDEF"
jwt_secret = "super_secret_token_123456"
"""
    analyzer = get_static_analyzer()
    findings = analyzer.analyze_code(code, file_path="config.py")
    assert any(f.cwe_id == "CWE-798" for f in findings)
    finding = next(f for f in findings if f.cwe_id == "CWE-798")
    assert finding.cwe_id == "CWE-798"


def test_sast_detects_weak_crypto():
    """Deterministic detection of Weak Hashing (CWE-328)."""
    code = """
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
"""
    analyzer = get_static_analyzer()
    findings = analyzer.analyze_code(code, file_path="auth.py")
    assert any(f.cwe_id == "CWE-328" for f in findings)
    finding = next(f for f in findings if f.cwe_id == "CWE-328")
    assert finding.cwe_id == "CWE-328"


# ---------------------------------------------------------------------------
# Test 3: FR-4 AST Route Mapper & Finding Route Enrichment
# ---------------------------------------------------------------------------

def test_ast_route_mapper_python_fastapi_and_flask():
    """Verify route extraction from Python source code AST."""
    code = """
from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter(prefix="/api")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/users")
async def create_user():
    return {"user": "created"}

@router.delete("/orders/{order_id}")
def delete_order(order_id: int):
    return {"deleted": order_id}

@app.route("/legacy", methods=["GET", "POST"])
def legacy_handler():
    return "legacy"
"""
    routes = extract_routes_from_python_code(code, file_path="server.py")
    assert len(routes) == 4

    health_route = next(r for r in routes if r.url_path == "/health")
    assert health_route.http_method == ["GET"]
    assert health_route.handler_function == "health"
    assert health_route.start_line > 0
    assert health_route.end_line >= health_route.start_line
    assert "GET /health -> health(), server.py lines" in health_route.display

    orders_route = next(r for r in routes if r.url_path == "/api/orders/{order_id}")
    assert orders_route.http_method == ["DELETE"]
    assert orders_route.handler_function == "delete_order"

    legacy_route = next(r for r in routes if r.url_path == "/legacy")
    assert set(legacy_route.http_method) == {"GET", "POST"}


def test_ast_route_mapper_express_fallback():
    """Verify Node.js/Express regex fallback extractor."""
    code = """
const express = require('express');
const app = express();

app.get('/api/orders', function get_orders(req, res) {
    res.json({ orders: [] });
});

router.post('/api/checkout', (req, res) => {
    res.send('ok');
});
"""
    routes = extract_routes_from_js_code(code, file_path="app.js")
    assert len(routes) >= 2
    get_orders = next(r for r in routes if r.url_path == "/api/orders")
    assert get_orders.http_method == ["GET"]
    assert "lines" in get_orders.display


def test_enrich_finding_with_route_matching():
    """Verify that a finding inside an endpoint function is automatically enriched with route data."""
    # Example from FR-4: GET /api/orders -> get_orders(), orders.py lines 80 to 95
    routes = [
        RouteEntry(
            http_method=["GET"],
            url_path="/api/orders",
            handler_function="get_orders",
            file="orders.py",
            start_line=80,
            end_line=95,
            display="GET /api/orders -> get_orders(), orders.py lines 80 to 95"
        )
    ]

    finding = UnifiedFinding(
        finding_id="sast-12345",
        dedup_key="abcdef123456",
        source_scanner="SAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        confidence="HIGH",
        file="orders.py",
        line=88,  # Line 88 is inside lines 80 to 95
        end_line=88,
        code_snippet="cursor.execute('SELECT * FROM orders WHERE id = %s' % order_id)",
        status_label="Code only"
    )

    enriched = enrich_finding_with_route(finding, routes)
    assert enriched.url_path == "/api/orders"
    assert enriched.http_method == "GET"
    assert enriched.handler_function == "get_orders"


# ---------------------------------------------------------------------------
# Test 4: End-to-End SAST Scan Workflow & Deduplication
# ---------------------------------------------------------------------------

def test_sast_scan_workflow_with_sample_project():
    """Create a temporary project and verify complete SAST scan with route enrichment and dedup."""
    with tempfile.TemporaryDirectory() as temp_dir:
        sample_code = """
from fastapi import FastAPI, Request
app = FastAPI()

# lines 6-12: get_orders route
@app.get("/api/orders")
def get_orders(request: Request):
    user_id = request.query_params.get("user_id")
    query = "SELECT * FROM orders WHERE user_id = " + user_id
    cursor.execute(query)
    return {"orders": []}

# lines 14-17: ping route
@app.post("/api/ping")
def ping_server(host: str):
    import os
    os.system("ping -c 1 " + host)
    return {"status": "pinged"}
"""
        file_path = os.path.join(temp_dir, "orders.py")
        with open(file_path, "w") as f:
            f.write(sample_code)

        scanner = get_sast_scanner_service()
        response: SASTScanResponse = scanner.scan_folder(temp_dir)

        assert response.success is True
        assert response.total_findings >= 2
        assert len(response.route_map) == 2

        # Verify route entries
        route_paths = [r.url_path for r in response.route_map]
        assert "/api/orders" in route_paths
        assert "/api/ping" in route_paths

        # Verify route enrichment on the SQL Injection finding
        sql_finding = next(f for f in response.findings if f.cwe_id == "CWE-89")
        assert sql_finding.file == "orders.py"
        assert sql_finding.url_path == "/api/orders"
        assert sql_finding.handler_function == "get_orders"
        assert sql_finding.http_method == "GET"

        # Verify Command Injection finding enriched with ping route
        cmd_finding = next(f for f in response.findings if f.cwe_id == "CWE-78")
        assert cmd_finding.url_path == "/api/ping"
        assert cmd_finding.handler_function == "ping_server"

        # Verify running scan twice doesn't duplicate findings (FR-6 preparation)
        second_response = scanner.scan_folder(temp_dir)
        assert second_response.total_findings == response.total_findings
        first_keys = {f.dedup_key for f in response.findings}
        second_keys = {f.dedup_key for f in second_response.findings}
        assert first_keys == second_keys


# ---------------------------------------------------------------------------
# Test 5: FastAPI HTTP API Endpoints
# ---------------------------------------------------------------------------

def test_api_sast_scan_endpoint():
    """Verify POST /api/sast/scan works seamlessly."""
    client = TestClient(app)

    payload = {
        "files": [
            {
                "filename": "orders.py",
                "content": """
from fastapi import FastAPI
app = FastAPI()

@app.get("/api/orders")
def get_orders(order_id: str):
    query = "SELECT * FROM orders WHERE id = " + order_id
    cursor.execute(query)
    return {"id": order_id}
"""
            }
        ],
        "generate_fixes": False
    }

    res = client.post("/api/sast/scan", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["total_findings"] >= 1
    assert len(data["route_map"]) >= 1

    finding = data["findings"][0]
    assert finding["cwe_id"] == "CWE-89"
    assert finding["url_path"] == "/api/orders"
    assert finding["handler_function"] == "get_orders"
    assert finding["status_label"] == "Code only"
    assert "dedup_key" in finding


def test_api_sast_routes_endpoint():
    """Verify GET /api/sast/routes works properly."""
    client = TestClient(app)
    res = client.get("/api/sast/routes", params={"source_folder": "backend"})
    assert res.status_code == 200
    routes = res.json()
    assert isinstance(routes, list)
    # Backend has endpoints in backend/routes/analyze.py
    route_paths = [r["url_path"] for r in routes]
    assert any("/api/sast/scan" in p or "/analyze" in p for p in route_paths)
