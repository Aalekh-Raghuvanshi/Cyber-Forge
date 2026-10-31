"""
Verification Test Suite for Benchmark Evaluation Flaw Fixes.
Validates the 6 critical fixes:
1. Non-Python noise elimination (strictly Python-only .py files).
2. Elimination of route drift (module-level findings stay None, never attach GET /health).
3. Intra-file helper function call-graph linking.
4. SQL injection multi-line taint detection in sql_injection_lab/app.py + DAST POST /lab Confirmed correlation.
5. New Python CWE rules (CWE-1336 SSTI, CWE-611 XXE, CWE-918 SSRF, CWE-117 Log Injection, CWE-209 Debug mode, CWE-862 Auth Bypass, CWE-614 Cookie).
6. Context-aware Python remediations (yaml.safe_load for YAML CWE-502, bcrypt for CWE-328).
"""

import os
import pytest
from backend.models.schemas import RouteEntry, UnifiedFinding
from backend.services.static_analyzer import get_static_analyzer
from backend.services.sast_scanner import get_sast_scanner_service
from backend.services.route_mapper import (
    extract_routes_from_folder,
    find_matching_route,
    enrich_finding_with_route,
    paths_match
)
from backend.services.correlator import get_correlation_engine
from backend.services.llm_service import get_deterministic_remediation
from backend.services.cwe_normalizer import are_cwes_equivalent


# ---------------------------------------------------------------------------
# Test 1: Non-Python Noise Elimination
# ---------------------------------------------------------------------------

def test_non_python_files_produce_zero_findings():
    """Verify that non-Python files (.js, .html, .ts, etc.) produce 0 findings."""
    analyzer = get_static_analyzer()

    js_code = """
    // Simulating introduction/static/js/lab_manager.js
    function executeLab(labId) {
        document.getElementById("output").innerHTML = "<div>" + labId + "</div>";
        eval("runLab(" + labId + ")");
        fetch("/api/run?id=" + labId);
    }
    """
    findings_js = analyzer.analyze_code(js_code, file_path="introduction/static/js/lab_manager.js")
    assert len(findings_js) == 0, f"Expected 0 findings for .js file, got {len(findings_js)}"

    html_code = "<script>document.write(location.search);</script>"
    findings_html = analyzer.analyze_code(html_code, file_path="template.html")
    assert len(findings_html) == 0, f"Expected 0 findings for .html file, got {len(findings_html)}"

    sast = get_sast_scanner_service()
    res = sast.scan_files([
        {"filename": "static/js/app.js", "content": js_code},
        {"filename": "templates/index.html", "content": html_code}
    ])
    assert res.total_findings == 0, f"Expected 0 SAST findings for non-Python upload, got {res.total_findings}"


# ---------------------------------------------------------------------------
# Test 2: Elimination of Route Drift & Module Scope None Route
# ---------------------------------------------------------------------------

def test_module_level_findings_have_none_route():
    """
    Verify that findings at module scope (outside any function, e.g. SECRET_KEY = ...)
    have url_path=None, handler_function=None, matched_route=None.
    Strictly forbidden to fall back to GET /health or files_routes[0].
    """
    routes = [
        RouteEntry(
            http_method=["GET"],
            url_path="/health",
            handler_function="health_check",
            file="app.py",
            start_line=38,
            end_line=40,
            display="GET /health -> health_check(), app.py lines 38 to 40"
        ),
        RouteEntry(
            http_method=["GET", "POST"],
            url_path="/lab",
            handler_function="lab",
            file="app.py",
            start_line=42,
            end_line=75,
            display="GET, POST /lab -> lab(), app.py lines 42 to 75"
        )
    ]

    # Finding at module scope: line 7 (SECRET_KEY = ...)
    finding = UnifiedFinding(
        finding_id="sast-secret-key",
        dedup_key="key-secret",
        source_scanner="SAST",
        cwe_id="CWE-798",
        vulnerability_type="Hard-coded Credentials",
        severity="LOW",
        file="app.py",
        line=7,
        code_snippet='app.config["SECRET_KEY"] = "your-secret-key-here"'
    )

    enriched = enrich_finding_with_route(finding, routes)
    assert enriched.url_path is None, f"Expected url_path to be None, got {enriched.url_path}"
    assert enriched.handler_function is None
    assert enriched.matched_route is None


# ---------------------------------------------------------------------------
# Test 3: Intra-File Helper Function Call-Graph Linking
# ---------------------------------------------------------------------------

def test_intra_file_helper_function_linking(tmp_path):
    """
    Verify that when a finding occurs inside a helper function called by a route handler,
    the finding links to that route handler.
    """
    code = '''
from flask import Flask, request
app = Flask(__name__)

def execute_untrusted_query(query_str):
    import sqlite3
    conn = sqlite3.connect("db.sqlite3")
    c = conn.cursor()
    return c.execute(query_str).fetchall()

@app.route("/search", methods=["GET"])
def search_handler():
    q = request.args.get("q", "")
    sql = f"SELECT * FROM items WHERE name = '{q}'"
    return str(execute_untrusted_query(sql))

@app.route("/health")
def health_check():
    return "OK"
'''
    test_file = tmp_path / "views.py"
    test_file.write_text(code, encoding="utf-8")

    routes = extract_routes_from_folder(str(tmp_path))
    assert len(routes) >= 2

    # Line 9 is inside execute_untrusted_query (lines 5-9)
    # execute_untrusted_query is called by search_handler (lines 11-15, /search)
    finding = UnifiedFinding(
        finding_id="sast-helper-call",
        dedup_key="key-helper",
        source_scanner="SAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        file=str(test_file),
        line=9,
        code_snippet="return c.execute(query_str).fetchall()"
    )

    enriched = enrich_finding_with_route(finding, routes)
    assert enriched.url_path == "/search", f"Expected /search, got {enriched.url_path}"
    assert enriched.handler_function == "search_handler"


# ---------------------------------------------------------------------------
# Test 4: Same-Function Duplicate SAST Findings Merge
# ---------------------------------------------------------------------------

def test_same_function_duplicate_sast_findings_merge():
    """
    Verify that multiple SAST findings of the same CWE inside the same route handler
    (or within 6 lines) merge into 1 single finding before DAST correlation.
    """
    correlator = get_correlation_engine()

    route = RouteEntry(
        http_method=["POST"],
        url_path="/lab2",
        handler_function="lab2",
        file="dockerized_labs/command_injection_lab/app.py",
        start_line=42,
        end_line=54,
        display="POST /lab2 -> lab2(), dockerized_labs/command_injection_lab/app.py lines 42 to 54"
    )

    # Line 44: docstring or early expression
    sast_line44 = UnifiedFinding(
        finding_id="sast-cwe94-line44",
        dedup_key="dedup-44",
        source_scanner="SAST",
        cwe_id="CWE-94",
        vulnerability_type="Code Injection",
        severity="CRITICAL",
        file="dockerized_labs/command_injection_lab/app.py",
        line=44,
        code_snippet='"""Lab 2: Python eval() Code Execution"""',
        url_path="/lab2",
        handler_function="lab2"
    )

    # Line 49: actual eval
    sast_line49 = UnifiedFinding(
        finding_id="sast-cwe94-line49",
        dedup_key="dedup-49",
        source_scanner="SAST",
        cwe_id="CWE-94",
        vulnerability_type="Code Injection",
        severity="CRITICAL",
        file="dockerized_labs/command_injection_lab/app.py",
        line=49,
        code_snippet="output = eval(expression)",
        url_path="/lab2",
        handler_function="lab2"
    )

    dast_alert = UnifiedFinding(
        finding_id="dast-lab2",
        dedup_key="dast-dedup-lab2",
        source_scanner="DAST",
        cwe_id="CWE-94",
        vulnerability_type="Code Injection",
        severity="HIGH",
        url_path="/lab2",
        http_method="POST",
        parameter="val",
        payload="__import__('os').system('id')",
        evidence="0"
    )

    issues = correlator.correlate(
        sast_findings=[sast_line44, sast_line49],
        dast_findings=[dast_alert],
        route_map=[route]
    )

    # Must merge into exactly 1 Confirmed issue (Rank #1)
    assert len(issues) == 1, f"Expected 1 issue after deduplication, got {len(issues)}"
    assert issues[0].status_label == "Confirmed"
    assert issues[0].priority_rank == 1
    assert issues[0].merged_count >= 2


# ---------------------------------------------------------------------------
# Test 5: SQL Injection Multi-Line Taint & DAST POST /lab Correlation
# ---------------------------------------------------------------------------

def test_sql_injection_lab_correlates_with_dast_post_lab():
    """
    Verify that sql_injection_lab/app.py's multi-line SQL query construction:
      sql_query = f"SELECT * FROM users WHERE username='{username}'..."
      ...
      result = c.execute(sql_query).fetchone()
    is detected by the static analyzer and correlates with DAST POST /lab into Confirmed.
    """
    pygoat_sqli_file = "data/pygoat/dockerized_labs/sql_injection_lab/app.py"
    if not os.path.exists(pygoat_sqli_file):
        pytest.skip("PyGoat sql_injection_lab/app.py not found on disk")

    with open(pygoat_sqli_file, "r", encoding="utf-8") as f:
        code = f.read()

    analyzer = get_static_analyzer()
    findings = analyzer.analyze_code(code, file_path=pygoat_sqli_file)

    # Confirm SQL Injection is detected
    sqli_findings = [f for f in findings if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) >= 1, "Expected static analyzer to detect CWE-89 in sql_injection_lab/app.py"

    # Extract route map for sql_injection_lab
    sqli_folder = os.path.dirname(pygoat_sqli_file)
    routes = extract_routes_from_folder(sqli_folder)
    lab_route = next((r for r in routes if r.url_path == "/lab"), None)
    assert lab_route is not None, "Expected /lab route in route map"

    # DAST alert on POST /lab
    dast_sqli = UnifiedFinding(
        finding_id="dast-sqli-lab",
        dedup_key="dast-sqli-lab-key",
        source_scanner="DAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="HIGH",
        url_path="/lab",
        http_method="POST",
        parameter="username",
        payload="admin' OR '1'='1",
        evidence="syntax error"
    )

    correlator = get_correlation_engine()
    issues = correlator.correlate(
        sast_findings=findings,
        dast_findings=[dast_sqli],
        route_map=routes
    )

    # Ensure Confirmed issue exists for CWE-89 on /lab
    confirmed_sqli = next((i for i in issues if i.status_label == "Confirmed" and i.cwe_id == "CWE-89"), None)
    assert confirmed_sqli is not None, "Expected Confirmed SQL Injection issue for POST /lab"
    assert confirmed_sqli.priority_rank == 1
    assert confirmed_sqli.url_path == "/lab"


# ---------------------------------------------------------------------------
# Test 6: Context-Aware Python Remediation Templates
# ---------------------------------------------------------------------------

def test_context_aware_remediations():
    """Verify context-sensitive fixes for YAML (CWE-502) and bcrypt (CWE-328)."""
    # 1. YAML Deserialization
    sug_yaml, code_yaml = get_deterministic_remediation(
        "CWE-502",
        code_snippet="data = yaml.load(user_yaml_file)"
    )
    assert "yaml.safe_load" in code_yaml, f"Expected yaml.safe_load in fixed_code, got: {code_yaml}"
    assert "yaml.safe_load" in sug_yaml

    # 2. Pickle Deserialization
    sug_pickle, code_pickle = get_deterministic_remediation(
        "CWE-502",
        code_snippet="obj = pickle.loads(raw_data)"
    )
    assert "json.loads" in code_pickle, f"Expected json.loads in fixed_code, got: {code_pickle}"

    # 3. Weak Password Hashing (CWE-328)
    sug_hash, code_hash = get_deterministic_remediation(
        "CWE-328",
        code_snippet="hash_val = hashlib.md5(password.encode()).hexdigest()"
    )
    assert "bcrypt.hashpw" in code_hash, f"Expected bcrypt.hashpw in fixed_code, got: {code_hash}"
    assert "sha256" not in code_hash.lower()


# ---------------------------------------------------------------------------
# Test 7: New Python CWE Rules (SSTI, XXE, SSRF, Log Injection, Debug, Auth)
# ---------------------------------------------------------------------------

def test_new_python_cwe_rules():
    """Verify new detection rules for CWE-1336, CWE-611, CWE-918, CWE-117, CWE-209, CWE-862, CWE-614."""
    analyzer = get_static_analyzer()

    # 1. SSTI (CWE-1336)
    ssti_code = """
from flask import render_template_string, request

def view_blog():
    content = request.args.get("content", "")
    return render_template_string(f"<div>{content}</div>")
"""
    f_ssti = analyzer.analyze_code(ssti_code, file_path="blog.py")
    assert any(f.cwe_id == "CWE-1336" for f in f_ssti), "Expected CWE-1336 for render_template_string"
    assert are_cwes_equivalent("CWE-1336", "CWE-94")
    assert are_cwes_equivalent("CWE-1336", "CWE-79")

    # 2. XXE (CWE-611)
    xxe_code = """
import xml.etree.ElementTree as ET

def parse_xml(data):
    return ET.fromstring(data)
"""
    f_xxe = analyzer.analyze_code(xxe_code, file_path="xml_parser.py")
    assert any(f.cwe_id == "CWE-611" for f in f_xxe), "Expected CWE-611 for XML parsing"

    # 3. SSRF (CWE-918)
    ssrf_code = """
import requests

def fetch_url(request):
    target = request.args.get("target_url")
    return requests.get(target).text
"""
    f_ssrf = analyzer.analyze_code(ssrf_code, file_path="fetcher.py")
    assert any(f.cwe_id == "CWE-918" for f in f_ssrf), "Expected CWE-918 for outbound HTTP requests"

    # 4. Log Injection (CWE-117)
    log_code = """
import logging

def login(request):
    user = request.args.get("username")
    logging.info(f"User login attempt: {user}")
"""
    f_log = analyzer.analyze_code(log_code, file_path="auth.py")
    assert any(f.cwe_id == "CWE-117" for f in f_log), "Expected CWE-117 for raw request logging"

    # 5. Debug Mode (CWE-209)
    debug_code = """
from flask import Flask
app = Flask(__name__)
DEBUG = True
app.run(debug=True)
"""
    f_debug = analyzer.analyze_code(debug_code, file_path="app.py")
    assert any(f.cwe_id == "CWE-209" for f in f_debug), "Expected CWE-209 for DEBUG=True"

    # 6. Auth Bypass via Headers/Cookies (CWE-862)
    auth_code = """
def check_admin(request):
    if request.cookies.get("admin") == "1":
        return True
    return False
"""
    f_auth = analyzer.analyze_code(auth_code, file_path="auth_check.py")
    assert any(f.cwe_id == "CWE-862" for f in f_auth), "Expected CWE-862 for unverified cookie auth"

    # 7. Insecure Cookie (CWE-614)
    cookie_code = """
def set_session(response, token):
    response.set_cookie("session_id", token)
"""
    f_cookie = analyzer.analyze_code(cookie_code, file_path="session.py")
    assert any(f.cwe_id == "CWE-614" for f in f_cookie), "Expected CWE-614 for missing HttpOnly/Secure"
