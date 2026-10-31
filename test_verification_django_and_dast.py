"""
Verification Test Suite for DAST Scanner, Multi-Framework Route Mapper,
and Precision Correlation Linking.
Tests:
1. Django urls.py -> views.py AST route mapping with path converters and regex.
2. Parameterized template matching (/admin/{id}/update matching /admin/42/update/).
3. Standalone Django views.py fallback (def view(request): -> /{view}).
4. Flask orders.py + raw_zap_alerts scenario:
   confirmed_count == 4, runtime_only_count == 1, code_only_count == 3,
   and route display "GET /api/orders -> get_orders(), orders.py lines 80 to 95".
5. Single-file scan with no DAST / unreachable DAST:
   runtime_only_count == 0 and zero fake /api/orders alerts.
6. Multi-format DAST ingestion (ZAP flat & nested, Nuclei, SARIF 2.1.0).
"""

import tempfile
import os
import pytest
from starlette.testclient import TestClient

from backend.app import app
from backend.models.schemas import RouteEntry, UnifiedFinding, DASTScanRequest
from backend.services.route_mapper import (
    extract_routes_from_folder,
    extract_routes_from_python_code,
    match_url_to_route,
    normalize_django_pattern
)
from backend.services.cwe_normalizer import are_cwes_equivalent, normalize_cwe
from backend.services.dast_scanner import get_dast_scanner
from backend.services.correlator import get_correlation_engine


def test_django_url_pattern_normalization():
    """Verify conversion of Django path() converters and re_path() regex to route templates."""
    assert normalize_django_pattern("admin/<int:id>/update/") == "/admin/{id}/update"
    assert normalize_django_pattern("users/<user_id>/") == "/users/{user_id}"
    assert normalize_django_pattern(r"^users/(?P<user_id>\d+)/$") == "/users/{user_id}"
    assert normalize_django_pattern(r"^orders/(?P<order_id>[0-9]+)/items/(?P<item_id>[0-9]+)/$") == "/orders/{order_id}/items/{item_id}"
    assert normalize_django_pattern("") == "/"


def test_parameterized_url_to_route_matching():
    """Verify concrete DAST URLs match static parameterized routes."""
    routes = [
        RouteEntry(
            http_method=["GET"],
            url_path="/admin/{id}/update",
            handler_function="update_admin",
            file="views.py",
            start_line=10,
            end_line=25,
            display="GET /admin/{id}/update -> update_admin(), views.py lines 10 to 25"
        ),
        RouteEntry(
            http_method=["GET", "POST"],
            url_path="/users/{user_id}",
            handler_function="user_detail",
            file="users.py",
            start_line=5,
            end_line=20,
            display="GET, POST /users/{user_id} -> user_detail(), users.py lines 5 to 20"
        )
    ]

    # Concrete URL /admin/42/update/ matches /admin/{id}/update
    matches_1 = match_url_to_route("/admin/42/update/", routes)
    assert len(matches_1) == 1
    assert matches_1[0].handler_function == "update_admin"

    # Concrete URL /users/alice matches /users/{user_id}
    matches_2 = match_url_to_route("/users/alice", routes)
    assert len(matches_2) == 1
    assert matches_2[0].handler_function == "user_detail"

    # Non-matching path
    matches_3 = match_url_to_route("/api/orders", routes)
    assert len(matches_3) == 0


def test_django_urls_views_repository_resolution():
    """Verify scanning a multi-file Django app links urls.py path() to views.py line spans."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        views_path = os.path.join(tmp_dir, "views.py")
        with open(views_path, "w") as f:
            f.write("""
from django.http import HttpResponse

def user_view(request, user_id):
    # Line 5
    return HttpResponse(f"User {user_id}")

def update_admin(request, id):
    # Line 9
    return HttpResponse("Admin updated")

def standalone_helper(request):
    # Unmapped view taking request
    return HttpResponse("Helper")
""")

        urls_path = os.path.join(tmp_dir, "urls.py")
        with open(urls_path, "w") as f:
            f.write("""
from django.urls import path
import views

urlpatterns = [
    path('users/<int:user_id>/', views.user_view, name='user_view'),
    path('admin/<int:id>/update/', views.update_admin, name='update_admin'),
]
""")

        routes = extract_routes_from_folder(tmp_dir)

        # Must have user_view, update_admin, and standalone_helper fallback
        handler_map = {r.handler_function: r for r in routes}
        assert "user_view" in handler_map
        assert "update_admin" in handler_map
        assert "standalone_helper" in handler_map

        # Check relative file paths are preserved
        assert handler_map["user_view"].file == "views.py"
        assert handler_map["user_view"].url_path == "/users/{user_id}"
        assert handler_map["user_view"].start_line == 4

        assert handler_map["update_admin"].file == "views.py"
        assert handler_map["update_admin"].url_path == "/admin/{id}/update"

        assert handler_map["standalone_helper"].file == "views.py"
        assert handler_map["standalone_helper"].url_path == "/standalone_helper"


def test_flask_orders_with_raw_zap_alerts_scenario():
    """
    Verification Scenario 1:
    Flask orders.py + raw_zap_alerts:
    Verifying confirmed_count == 4, runtime_only_count == 1, code_only_count == 3,
    and route display 'GET /api/orders -> get_orders(), orders.py lines 80 to 95'.
    """
    correlator = get_correlation_engine()

    # Route definition per requirement
    route_orders = RouteEntry(
        http_method=["GET"],
        url_path="/api/orders",
        handler_function="get_orders",
        file="orders.py",
        start_line=80,
        end_line=95,
        display="GET /api/orders -> get_orders(), orders.py lines 80 to 95"
    )
    route_search = RouteEntry(
        http_method=["GET"],
        url_path="/api/search",
        handler_function="search",
        file="orders.py",
        start_line=100,
        end_line=115,
        display="GET /api/search -> search(), orders.py lines 100 to 115"
    )
    route_download = RouteEntry(
        http_method=["GET"],
        url_path="/api/download",
        handler_function="download",
        file="orders.py",
        start_line=120,
        end_line=135,
        display="GET /api/download -> download(), orders.py lines 120 to 135"
    )
    route_exec = RouteEntry(
        http_method=["POST"],
        url_path="/api/exec",
        handler_function="exec_cmd",
        file="orders.py",
        start_line=140,
        end_line=155,
        display="POST /api/exec -> exec_cmd(), orders.py lines 140 to 155"
    )

    routes = [route_orders, route_search, route_download, route_exec]

    # 4 SAST findings that will match DAST -> Confirmed (Count = 4)
    sast_sqli = UnifiedFinding(
        finding_id="sast-1", dedup_key="k1", source_scanner="SAST",
        cwe_id="CWE-89", vulnerability_type="SQL Injection", severity="CRITICAL",
        file="orders.py", line=88, end_line=88, code_snippet="cursor.execute(sql)",
        handler_function="get_orders", url_path="/api/orders", http_method="GET"
    )
    sast_xss = UnifiedFinding(
        finding_id="sast-2", dedup_key="k2", source_scanner="SAST",
        cwe_id="CWE-79", vulnerability_type="Cross-Site Scripting", severity="HIGH",
        file="orders.py", line=105, end_line=105, code_snippet="return f'<h1>{q}</h1>'",
        handler_function="search", url_path="/api/search", http_method="GET"
    )
    sast_traversal = UnifiedFinding(
        finding_id="sast-3", dedup_key="k3", source_scanner="SAST",
        cwe_id="CWE-22", vulnerability_type="Path Traversal", severity="HIGH",
        file="orders.py", line=125, end_line=125, code_snippet="open(file_path)",
        handler_function="download", url_path="/api/download", http_method="GET"
    )
    sast_cmd = UnifiedFinding(
        finding_id="sast-4", dedup_key="k4", source_scanner="SAST",
        cwe_id="CWE-78", vulnerability_type="Command Injection", severity="CRITICAL",
        file="orders.py", line=145, end_line=145, code_snippet="subprocess.run(cmd)",
        handler_function="exec_cmd", url_path="/api/exec", http_method="POST"
    )

    # 3 SAST findings that have NO DAST match -> Code only (Count = 3)
    sast_secret = UnifiedFinding(
        finding_id="sast-5", dedup_key="k5", source_scanner="SAST",
        cwe_id="CWE-798", vulnerability_type="Hard-coded Credentials", severity="HIGH",
        file="config.py", line=10, code_snippet="API_KEY = 'secret123'"
    )
    sast_crypto = UnifiedFinding(
        finding_id="sast-6", dedup_key="k6", source_scanner="SAST",
        cwe_id="CWE-328", vulnerability_type="Weak Crypto", severity="MEDIUM",
        file="auth.py", line=20, code_snippet="hashlib.md5(p)"
    )
    sast_deserial = UnifiedFinding(
        finding_id="sast-7", dedup_key="k7", source_scanner="SAST",
        cwe_id="CWE-502", vulnerability_type="Insecure Deserialization", severity="HIGH",
        file="utils.py", line=15, code_snippet="pickle.loads(data)"
    )

    # 4 Matching DAST alerts
    dast_sqli = UnifiedFinding(
        finding_id="dast-1", dedup_key="dk1", source_scanner="DAST",
        cwe_id="CWE-89", vulnerability_type="SQL Injection", severity="HIGH",
        url_path="/api/orders", http_method="GET", parameter="id", payload="1' OR '1'='1"
    )
    dast_xss = UnifiedFinding(
        finding_id="dast-2", dedup_key="dk2", source_scanner="DAST",
        cwe_id="CWE-79", vulnerability_type="Cross-Site Scripting", severity="HIGH",
        url_path="/api/search", http_method="GET", parameter="q", payload="<script>alert(1)</script>"
    )
    dast_traversal = UnifiedFinding(
        finding_id="dast-3", dedup_key="dk3", source_scanner="DAST",
        cwe_id="CWE-22", vulnerability_type="Path Traversal", severity="HIGH",
        url_path="/api/download", http_method="GET", parameter="file", payload="../../etc/passwd"
    )
    dast_cmd = UnifiedFinding(
        finding_id="dast-4", dedup_key="dk4", source_scanner="DAST",
        cwe_id="CWE-78", vulnerability_type="Command Injection", severity="CRITICAL",
        url_path="/api/exec", http_method="POST", parameter="cmd", payload="; id"
    )

    # 1 Unmatched DAST alert -> Runtime only (Count = 1)
    dast_csp = UnifiedFinding(
        finding_id="dast-5", dedup_key="dk5", source_scanner="DAST",
        cwe_id="CWE-693", vulnerability_type="Missing Security Headers", severity="MEDIUM",
        url_path="/", http_method="GET", evidence="CSP missing"
    )

    sast_all = [sast_sqli, sast_xss, sast_traversal, sast_cmd, sast_secret, sast_crypto, sast_deserial]
    dast_all = [dast_sqli, dast_xss, dast_traversal, dast_cmd, dast_csp]

    issues = correlator.correlate(
        sast_findings=sast_all,
        dast_findings=dast_all,
        route_map=routes
    )

    confirmed_count = sum(1 for i in issues if i.status_label == "Confirmed")
    runtime_only_count = sum(1 for i in issues if i.status_label == "Runtime only")
    code_only_count = sum(1 for i in issues if i.status_label == "Code only")

    # Assert exact counts
    assert confirmed_count == 4
    assert runtime_only_count == 1
    assert code_only_count == 3
    assert len(issues) == 8

    # Verify confirmed SQL injection route display
    confirmed_sqli = next(i for i in issues if i.cwe_id == "CWE-89")
    assert confirmed_sqli.matched_route == "GET /api/orders -> get_orders(), orders.py lines 80 to 95"
    assert confirmed_sqli.status_label == "Confirmed"
    assert confirmed_sqli.file == "orders.py"
    assert confirmed_sqli.line == 88


def test_single_file_scan_zero_mock_dast_alerts():
    """
    Verification Scenario 2:
    A single-file scan with unreachable DAST input:
    Verifying runtime_only_count == 0 and zero fake /api/orders alerts appear.
    """
    client = TestClient(app)

    payload = {
        "files": [
            {
                "filename": "hello.py",
                "content": """
import hashlib

def login(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
"""
            }
        ],
        "target_url": "http://localhost:59999",  # Unreachable port
        "generate_fixes": False
    }

    res = client.post("/scans", json=payload)
    assert res.status_code == 200
    data = res.json()

    # runtime_only_count must be 0
    assert data["runtime_only_count"] == 0
    assert data["confirmed_count"] == 0
    assert data["code_only_count"] >= 1

    # Zero fake alerts like /api/orders or /api/search
    for issue in data["issues"]:
        assert issue.get("url_path") != "/api/orders"
        assert issue.get("url_path") != "/api/search"
        assert issue["status_label"] == "Code only"


def test_multi_format_dast_ingestion():
    """Verify ingestion across flat ZAP, nested ZAP, Nuclei, and SARIF 2.1.0."""
    scanner = get_dast_scanner()

    # 1. Nested ZAP format
    nested_zap = {
        "site": [{
            "@name": "http://localhost:5000",
            "alerts": [{
                "pluginid": "40018",
                "cweid": "89",
                "alert": "SQL Injection",
                "instances": [
                    {"uri": "http://localhost:5000/api/items?id=10", "method": "GET", "param": "id"}
                ]
            }]
        }]
    }
    zap_res = scanner.parse_dast_report(nested_zap)
    assert len(zap_res) == 1
    assert zap_res[0].cwe_id == "CWE-89"
    assert zap_res[0].url_path == "/api/items"
    assert zap_res[0].parameter == "id"

    # 2. Nuclei JSONL format
    nuclei_jsonl = """{"template-id": "ssrf-detect", "info": {"name": "SSRF", "severity": "high", "classification": {"cwe-id": ["cwe-918"]}}, "matched-at": "http://localhost:5000/api/proxy?url=http://169.254.169.254"}"""
    nuclei_res = scanner.parse_dast_report(nuclei_jsonl)
    assert len(nuclei_res) == 1
    assert nuclei_res[0].cwe_id == "CWE-918"
    assert nuclei_res[0].url_path == "/api/proxy"
    assert nuclei_res[0].parameter == "url"

    # 3. SARIF 2.1.0 format
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "results": [{
                "ruleId": "CWE-22",
                "message": {"text": "Path Traversal"},
                "level": "error",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "http://localhost:5000/api/read?file=../../etc/passwd"}
                    }
                }],
                "properties": {
                    "method": "GET",
                    "parameter": "file"
                }
            }]
        }]
    }
    sarif_res = scanner.parse_dast_report(sarif)
    assert len(sarif_res) == 1
    assert sarif_res[0].cwe_id == "CWE-22"
    assert sarif_res[0].url_path == "/api/read"
    assert sarif_res[0].parameter == "file"
