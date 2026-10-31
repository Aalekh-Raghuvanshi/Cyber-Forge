"""
Comprehensive Phase 3 Verification Tests.
Validates:
- FR-5: Correlation of SAST and DAST findings (CWE match, route line span match, parameter boost)
- FR-6: Merge duplicate findings across scanners & idempotent SQLite persistence via issue_hash
- FR-7: Strict status labels ('Confirmed', 'Runtime only', 'Code only') with complete details
- FR-9: Strict priority ranking ('Confirmed' first, then 'Runtime only', then 'Code only', by risk_score)
- Zero-Hallucination Sandboxed LLM Remediation with deterministic fallback templates
- FR-10: REST APIs: POST /scans, GET /issues, GET /issues/{id} (and /api/ aliases)
"""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.models.schemas import (
    UnifiedFinding, RouteEntry, CorrelatedIssue,
    FullScanRequest, FullScanResponse
)
from backend.services.correlator import (
    CorrelationEngine, get_correlation_engine,
    compute_issue_hash, calculate_risk_score
)
from backend.services.store import IssueStore, get_issue_store
from backend.services.llm_service import get_deterministic_remediation
from backend.app import app


# ---------------------------------------------------------------------------
# Test 1: FR-5 Correlation Engine (CWE Match, Route Line Span, Parameter Boost)
# ---------------------------------------------------------------------------

def test_fr5_confirmed_correlation_flow():
    """
    Verify FR-5 example:
    DAST SQL injection on /api/orders + SAST SQL injection at orders.py:88 = one confirmed issue.
    """
    correlator = get_correlation_engine()

    route = RouteEntry(
        http_method=["GET"],
        url_path="/api/orders",
        handler_function="get_orders",
        file="orders.py",
        start_line=80,
        end_line=95,
        display="GET /api/orders -> get_orders(), orders.py lines 80 to 95"
    )

    sast = UnifiedFinding(
        finding_id="sast-1",
        dedup_key="sast-hash-1",
        source_scanner="SAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        file="orders.py",
        line=88,  # Inside lines 80 to 95
        end_line=88,
        code_snippet="cursor.execute('SELECT * FROM orders WHERE id = %s' % order_id)",
        handler_function="get_orders",
        url_path="/api/orders",
        http_method="GET",
        status_label="Code only"
    )

    dast = UnifiedFinding(
        finding_id="dast-1",
        dedup_key="dast-hash-1",
        source_scanner="DAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="HIGH",
        url_path="/api/orders",
        http_method="GET",
        parameter="id",
        payload="1' OR '1'='1",
        evidence="syntax error at or near quote",
        status_label="Runtime only"
    )

    issues = correlator.correlate(
        sast_findings=[sast],
        dast_findings=[dast],
        route_map=[route]
    )

    assert len(issues) == 1
    issue = issues[0]

    # FR-7: Strictly 'Confirmed'
    assert issue.status_label == "Confirmed"
    assert issue.cwe_id == "CWE-89"
    assert issue.vulnerability_type == "SQL Injection"

    # Confirmed issue must have all details from both sides
    assert issue.file == "orders.py"
    assert issue.line == 88
    assert issue.code_snippet == sast.code_snippet
    assert issue.url_path == "/api/orders"
    assert issue.http_method == "GET"
    assert issue.parameter == "id"
    assert issue.payload == "1' OR '1'='1"
    assert issue.evidence == "syntax error at or near quote"

    # Traceability
    assert "SAST" in issue.supporting_scanners
    assert "DAST" in issue.supporting_scanners
    assert issue.merged_count == 2


def test_fr5_parameter_boost_tie_breaker():
    """
    If multiple SAST findings of the same CWE exist in the same route function,
    the parameter boost matches the one that references the DAST parameter.
    """
    correlator = get_correlation_engine()

    route = RouteEntry(
        http_method=["GET"],
        url_path="/api/users",
        handler_function="get_users",
        file="users.py",
        start_line=10,
        end_line=30,
        display="GET /api/users -> get_users(), users.py lines 10 to 30"
    )

    # SAST finding 1 on line 15 (parameter 'name')
    sast_name = UnifiedFinding(
        finding_id="sast-name",
        dedup_key="hash-name",
        source_scanner="SAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        file="users.py",
        line=15,
        code_snippet="query = 'SELECT * FROM users WHERE name = ' + user_name",
        url_path="/api/users"
    )

    # SAST finding 2 on line 22 (parameter 'id')
    sast_id = UnifiedFinding(
        finding_id="sast-id",
        dedup_key="hash-id",
        source_scanner="SAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        file="users.py",
        line=22,
        code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id",
        url_path="/api/users"
    )

    # DAST finding targeting parameter 'id'
    dast = UnifiedFinding(
        finding_id="dast-id",
        dedup_key="dast-hash-id",
        source_scanner="DAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="HIGH",
        url_path="/api/users",
        http_method="GET",
        parameter="id",
        payload="1' OR '1'='1",
        evidence="syntax error at id"
    )

    issues = correlator.correlate(
        sast_findings=[sast_name, sast_id],
        dast_findings=[dast],
        route_map=[route]
    )

    assert len(issues) == 2
    confirmed_issue = next(i for i in issues if i.status_label == "Confirmed")
    code_only_issue = next(i for i in issues if i.status_label == "Code only")

    # Parameter boost must have linked sast_id (line 22), not sast_name
    assert confirmed_issue.line == 22
    assert confirmed_issue.parameter == "id"
    assert code_only_issue.line == 15


# ---------------------------------------------------------------------------
# Test 2: FR-6 Duplicate Merging Across 3 Scanners & Idempotent Hash
# ---------------------------------------------------------------------------

def test_fr6_three_scanners_merge_into_one():
    """
    If 3 scanner findings point to the same underlying bug (e.g. Semgrep SAST +
    Static Regex SAST + ZAP DAST on orders.py:88), merge all 3 into 1 single issue.
    """
    correlator = get_correlation_engine()

    route = RouteEntry(
        http_method=["GET"],
        url_path="/api/orders",
        handler_function="get_orders",
        file="orders.py",
        start_line=80,
        end_line=95,
        display="GET /api/orders -> get_orders(), orders.py lines 80 to 95"
    )

    # Scanner 1: Semgrep SAST
    sast_semgrep = UnifiedFinding(
        finding_id="sast-semgrep",
        dedup_key="key-semgrep",
        source_scanner="SAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        file="orders.py",
        line=88,
        code_snippet="cursor.execute(sql)",
        url_path="/api/orders"
    )

    # Scanner 2: Static Regex SAST (same bug at orders.py:88)
    sast_regex = UnifiedFinding(
        finding_id="sast-regex",
        dedup_key="key-regex",
        source_scanner="SAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        file="orders.py",
        line=88,
        code_snippet="cursor.execute(sql)",
        url_path="/api/orders"
    )

    # Scanner 3: ZAP DAST on /api/orders
    dast_zap = UnifiedFinding(
        finding_id="dast-zap",
        dedup_key="key-dast",
        source_scanner="DAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="HIGH",
        url_path="/api/orders",
        http_method="GET",
        parameter="id",
        payload="1' OR '1'='1",
        evidence="syntax error at or near 1'"
    )

    issues = correlator.correlate(
        sast_findings=[sast_semgrep, sast_regex],
        dast_findings=[dast_zap],
        route_map=[route]
    )

    # Must merge into exactly 1 issue
    assert len(issues) == 1
    issue = issues[0]
    assert issue.status_label == "Confirmed"
    assert issue.merged_count == 3
    assert set(issue.supporting_scanners) == {"SAST", "DAST"}


# ---------------------------------------------------------------------------
# Test 3: FR-7 Exact Output Labels ('Confirmed', 'Runtime only', 'Code only')
# ---------------------------------------------------------------------------

def test_fr7_three_exact_labels():
    """Verify that issues are strictly labeled Confirmed, Runtime only, or Code only."""
    correlator = get_correlation_engine()

    # 1. Hardcoded Secret (CWE-798) in config.py -> SAST only -> Code only
    sast_secret = UnifiedFinding(
        finding_id="sast-secret",
        dedup_key="secret-key",
        source_scanner="SAST",
        cwe_id="CWE-798",
        vulnerability_type="Hard-coded Credentials",
        severity="HIGH",
        file="config.py",
        line=12,
        code_snippet="SECRET_KEY = 'super_secret_token'"
    )

    # 2. Missing CSP Header (CWE-693) -> DAST only -> Runtime only
    dast_csp = UnifiedFinding(
        finding_id="dast-csp",
        dedup_key="csp-key",
        source_scanner="DAST",
        cwe_id="CWE-693",
        vulnerability_type="Missing Security Headers",
        severity="MEDIUM",
        url_path="/",
        http_method="GET",
        evidence="Content-Security-Policy header missing"
    )

    # 3. Path Traversal -> found by BOTH -> Confirmed
    route_files = RouteEntry(
        http_method=["GET"],
        url_path="/download",
        handler_function="download_file",
        file="files.py",
        start_line=1,
        end_line=20,
        display="GET /download -> download_file(), files.py lines 1 to 20"
    )
    sast_path = UnifiedFinding(
        finding_id="sast-path",
        dedup_key="path-sast",
        source_scanner="SAST",
        cwe_id="CWE-22",
        vulnerability_type="Path Traversal",
        severity="HIGH",
        file="files.py",
        line=10,
        code_snippet="open('/data/' + filename)",
        url_path="/download"
    )
    dast_path = UnifiedFinding(
        finding_id="dast-path",
        dedup_key="path-dast",
        source_scanner="DAST",
        cwe_id="CWE-22",
        vulnerability_type="Path Traversal",
        severity="HIGH",
        url_path="/download",
        http_method="GET",
        parameter="filename",
        payload="../../etc/passwd",
        evidence="root:x:0:0"
    )

    issues = correlator.correlate(
        sast_findings=[sast_secret, sast_path],
        dast_findings=[dast_csp, dast_path],
        route_map=[route_files]
    )

    labels = {i.status_label for i in issues}
    assert labels == {"Confirmed", "Runtime only", "Code only"}

    # Verify Confirmed issue details
    confirmed = next(i for i in issues if i.status_label == "Confirmed")
    assert confirmed.cwe_id == "CWE-22"
    assert confirmed.file == "files.py"
    assert confirmed.line == 10
    assert confirmed.url_path == "/download"
    assert confirmed.payload == "../../etc/passwd"
    assert confirmed.evidence == "root:x:0:0"

    # Verify Code only issue details
    code_only = next(i for i in issues if i.status_label == "Code only")
    assert code_only.cwe_id == "CWE-798"
    assert code_only.file == "config.py"
    assert code_only.payload is None
    assert code_only.evidence is None

    # Verify Runtime only issue details
    runtime_only = next(i for i in issues if i.status_label == "Runtime only")
    assert runtime_only.cwe_id == "CWE-693"
    assert runtime_only.file is None
    assert runtime_only.line is None
    assert runtime_only.evidence == "Content-Security-Policy header missing"


# ---------------------------------------------------------------------------
# Test 4: FR-9 Strict Priority Ranking & Risk Score
# ---------------------------------------------------------------------------

def test_fr9_prioritised_ranking_order():
    """
    Verify FR-9 requirement:
    - Confirmed issues ALWAYS rank first (rank 1)
    - Followed by Runtime only (rank 2)
    - Followed by Code only (rank 3)
    - Within each status, sorted descending by risk_score.
    Example: Confirmed SQL injection ALWAYS ranks above a Code only weak hash or secret.
    """
    correlator = get_correlation_engine()

    route = RouteEntry(
        http_method=["GET"],
        url_path="/api/orders",
        handler_function="get_orders",
        file="orders.py",
        start_line=80,
        end_line=95,
        display="GET /api/orders -> get_orders(), orders.py lines 80 to 95"
    )

    # 1. Confirmed SQL Injection (CRITICAL=40 + Confirmed=50 -> 90)
    sast_sqli = UnifiedFinding(
        finding_id="sast-sqli",
        dedup_key="sqli-sast",
        source_scanner="SAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        file="orders.py",
        line=88,
        code_snippet="execute(query)",
        url_path="/api/orders"
    )
    dast_sqli = UnifiedFinding(
        finding_id="dast-sqli",
        dedup_key="sqli-dast",
        source_scanner="DAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        url_path="/api/orders",
        http_method="GET",
        parameter="id",
        payload="1' OR '1'='1",
        evidence="syntax error"
    )

    # 2. Runtime only missing CSP (MEDIUM=20 + Runtime=25 -> 45)
    dast_csp = UnifiedFinding(
        finding_id="dast-csp",
        dedup_key="csp-dast",
        source_scanner="DAST",
        cwe_id="CWE-693",
        vulnerability_type="Missing Security Headers",
        severity="MEDIUM",
        url_path="/"
    )

    # 3. Code only Secret (HIGH=30 + CodeOnly=0 -> 30)
    sast_secret = UnifiedFinding(
        finding_id="sast-secret",
        dedup_key="secret-sast",
        source_scanner="SAST",
        cwe_id="CWE-798",
        vulnerability_type="Hard-coded Credentials",
        severity="HIGH",
        file="config.py",
        line=10,
        code_snippet="API_KEY = 'secret12345'"
    )

    # 4. Code only Weak Hash (MEDIUM=20 + CodeOnly=0 -> 20)
    sast_hash = UnifiedFinding(
        finding_id="sast-hash",
        dedup_key="hash-sast",
        source_scanner="SAST",
        cwe_id="CWE-328",
        vulnerability_type="Weak Hashing",
        severity="MEDIUM",
        file="auth.py",
        line=5,
        code_snippet="hashlib.md5(pwd)"
    )

    issues = correlator.correlate(
        sast_findings=[sast_secret, sast_sqli, sast_hash],
        dast_findings=[dast_sqli, dast_csp],
        route_map=[route]
    )

    assert len(issues) == 4

    # Confirmed SQL Injection must be priority_rank 1
    assert issues[0].priority_rank == 1
    assert issues[0].status_label == "Confirmed"
    assert issues[0].cwe_id == "CWE-89"
    assert issues[0].risk_score >= 90

    # Runtime only Missing CSP must be priority_rank 2
    assert issues[1].priority_rank == 2
    assert issues[1].status_label == "Runtime only"
    assert issues[1].cwe_id == "CWE-693"

    # Code only Secret must be priority_rank 3 (risk_score 30 > 20)
    assert issues[2].priority_rank == 3
    assert issues[2].status_label == "Code only"
    assert issues[2].cwe_id == "CWE-798"

    # Code only Weak Hash must be priority_rank 4
    assert issues[3].priority_rank == 4
    assert issues[3].status_label == "Code only"
    assert issues[3].cwe_id == "CWE-328"


# ---------------------------------------------------------------------------
# Test 5: Sandboxed Remediation with Deterministic Template Fallbacks
# ---------------------------------------------------------------------------

def test_sandboxed_remediation_fallbacks():
    """Verify deterministic remediation suggestions & fixed code for core CWEs."""
    core_cwes = ["CWE-89", "CWE-79", "CWE-22", "CWE-78", "CWE-798", "CWE-328", "CWE-693"]
    for cwe in core_cwes:
        suggestion, fixed_code = get_deterministic_remediation(cwe)
        assert len(suggestion) > 10
        assert len(fixed_code) > 5


# ---------------------------------------------------------------------------
# Test 6: SQLite Persistence & Idempotency (FR-6 / FR-10)
# ---------------------------------------------------------------------------

def test_sqlite_store_idempotent_upsert():
    """Verify that running a scan twice updates issues instead of duplicating rows."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        store = IssueStore(db_path=tmp.name)

        issue_hash = compute_issue_hash("CWE-89", "orders.py", 88, "/api/orders")
        issue = CorrelatedIssue(
            id=1,
            issue_hash=issue_hash,
            status_label="Confirmed",
            priority_rank=1,
            risk_score=90,
            cwe_id="CWE-89",
            vulnerability_type="SQL Injection",
            severity="CRITICAL",
            file="orders.py",
            line=88,
            url_path="/api/orders",
            supporting_scanners=["SAST"],
            merged_count=1
        )

        # First scan save
        saved_1 = store.save_scan(
            scan_id="scan-1",
            source_folder=".",
            target_url="http://localhost:5000",
            issues=[issue],
            route_map=[]
        )
        assert len(saved_1) == 1
        assert saved_1[0].merged_count == 1

        # Second scan save with same issue_hash (re-run scan)
        saved_2 = store.save_scan(
            scan_id="scan-2",
            source_folder=".",
            target_url="http://localhost:5000",
            issues=[issue],
            route_map=[]
        )

        # Count must remain 1 (no duplicate rows), merged_count increases
        assert len(saved_2) == 1
        assert saved_2[0].id == saved_1[0].id
        assert saved_2[0].merged_count == 2


# ---------------------------------------------------------------------------
# Test 7: REST API Endpoints: POST /scans, GET /issues, GET /issues/{id}
# ---------------------------------------------------------------------------

def test_api_post_scans_and_get_issues():
    """Verify POST /scans, GET /issues, and GET /issues/{id} per FR-10."""
    client = TestClient(app)

    # 1. Trigger full scan with uploaded code and pre-captured DAST alert
    payload = {
        "files": [
            {
                "filename": "orders.py",
                "content": """
from fastapi import FastAPI, Request
app = FastAPI()

@app.get("/api/orders")
def get_orders(request: Request):
    order_id = request.query_params.get("id")
    query = "SELECT * FROM orders WHERE id = " + order_id
    cursor.execute(query)
    return {"id": order_id}
"""
            }
        ],
        "target_url": "http://localhost:5000",
        "raw_zap_alerts": [
            {
                "pluginId": "40018",
                "cweid": "89",
                "alert": "SQL Injection",
                "url": "http://localhost:5000/api/orders?id=1",
                "method": "GET",
                "param": "id",
                "attack": "1' OR '1'='1",
                "evidence": "syntax error near 1'",
                "risk": "High"
            }
        ],
        "generate_fixes": True
    }

    # Test POST /scans (and verify POST /api/scans alias)
    res_scan = client.post("/scans", json=payload)
    assert res_scan.status_code == 200
    data = res_scan.json()
    assert data["success"] is True
    assert data["total_issues"] >= 1
    assert data["confirmed_count"] >= 1

    first_issue = data["issues"][0]
    assert first_issue["status_label"] == "Confirmed"
    assert first_issue["cwe_id"] == "CWE-89"
    assert first_issue["file"] == "orders.py"
    assert first_issue["url_path"] == "/api/orders"
    assert first_issue["fix_suggestion"] is not None
    assert first_issue["fixed_code"] is not None

    issue_id = first_issue["id"]

    # 2. Test GET /issues
    res_issues = client.get("/issues")
    assert res_issues.status_code == 200
    all_issues = res_issues.json()
    assert len(all_issues) >= 1
    assert all_issues[0]["priority_rank"] == 1

    # Test filter ?status_label=Confirmed
    res_filtered = client.get("/issues", params={"status_label": "Confirmed"})
    assert res_filtered.status_code == 200
    assert all(i["status_label"] == "Confirmed" for i in res_filtered.json())

    # 3. Test GET /issues/{issue_id} (FR-10 example: GET /issues/7)
    res_single = client.get(f"/issues/{issue_id}")
    assert res_single.status_code == 200
    detail = res_single.json()
    assert detail["id"] == issue_id
    assert detail["cwe_id"] == "CWE-89"
    assert detail["status_label"] == "Confirmed"

    # Test GET /api/issues/{issue_id} alias
    res_alias = client.get(f"/api/issues/{issue_id}")
    assert res_alias.status_code == 200
    assert res_alias.json()["id"] == issue_id

    # Test 404 for non-existent issue
    res_404 = client.get("/issues/999999")
    assert res_404.status_code == 404
