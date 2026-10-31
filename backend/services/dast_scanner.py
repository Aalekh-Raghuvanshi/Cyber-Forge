"""
DAST Scanner Service & OWASP ZAP Alert Normalizer.
Fulfills FR-2, FR-3, and FR-6:
- Live OWASP ZAP API integration via httpx.
- Local verification / report ingestion mode for offline demo reliability.
- Full URL to relative url_path normalization.
- Mapping to canonical CWEs with 'Runtime only' status label.
- Idempotent deduplication via SHA256 of DAST:http_method:url_path:parameter:cwe_id.
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional, Set
import httpx

from backend.models.schemas import UnifiedFinding, DASTScanRequest, DASTScanResponse
from backend.services.cwe_normalizer import normalize_cwe, compute_dast_dedup_key, SEVERITY_ORDER
from backend.utils.logger import get_logger

logger = get_logger("dast_scanner")


class DASTScanner:
    """
    Orchestrates DAST alert extraction and normalization.
    Supports Mode A (Live OWASP ZAP Daemon) and Mode B (Local Verification / Report Ingestion).
    """

    def __init__(self, default_timeout: float = 15.0):
        self.default_timeout = default_timeout

    def normalize_url_path(self, full_url: str) -> str:
        """
        Strips scheme, host, port, and query string from URL; normalizes slashes.
        Example: 'http://localhost:5000/api/orders?id=1' -> '/api/orders'
        """
        if not full_url:
            return "/"

        parsed = urllib.parse.urlparse(full_url)
        path = parsed.path.strip()

        if not path or path == "":
            return "/"

        # Normalize redundant slashes and trailing slash (except root)
        norm = re.sub(r'/+', '/', path)
        if norm != "/" and norm.endswith("/"):
            norm = norm[:-1]

        if not norm.startswith("/"):
            norm = f"/{norm}"

        return norm

    def parse_zap_alerts(self, alerts: List[Dict[str, Any]]) -> List[UnifiedFinding]:
        """
        Converts raw OWASP ZAP alert dicts into deduplicated UnifiedFinding objects.
        Fulfills FR-3 and FR-6.
        """
        findings_map: Dict[str, UnifiedFinding] = {}

        for alert in alerts:
            raw_url = alert.get("url") or alert.get("uri") or "/"
            url_path = self.normalize_url_path(raw_url)
            http_method = (alert.get("method") or "GET").strip().upper()

            parameter = alert.get("param") or alert.get("parameter") or None
            if parameter:
                parameter = str(parameter).strip()
                if parameter in ("", "None", "null"):
                    parameter = None

            payload = alert.get("attack") or alert.get("payload") or None
            if payload:
                payload = str(payload).strip()
                if payload in ("", "None", "null"):
                    payload = None

            evidence = alert.get("evidence") or None
            if evidence:
                evidence = str(evidence).strip()
                if evidence in ("", "None", "null"):
                    evidence = None

            raw_cwe = alert.get("cweid") or alert.get("cwe_id")
            plugin_id = alert.get("pluginId") or alert.get("plugin_id")
            alert_name = alert.get("alert") or alert.get("name") or "Security Alert"

            cwe_id, vuln_type, canonical_sev, default_desc = normalize_cwe(
                raw_cwe=raw_cwe,
                rule_name=str(plugin_id) if plugin_id else alert_name,
                message=alert_name,
                plugin_id=plugin_id
            )

            # Map ZAP risk level to severity
            raw_risk = str(alert.get("risk") or alert.get("severity") or "").upper()
            if "HIGH" in raw_risk:
                severity = "CRITICAL" if cwe_id in ("CWE-89", "CWE-78", "CWE-94") else "HIGH"
            elif "MED" in raw_risk:
                severity = "MEDIUM"
            elif "LOW" in raw_risk or "INFO" in raw_risk:
                severity = "LOW"
            else:
                severity = canonical_sev

            # Map confidence
            raw_conf = str(alert.get("confidence") or "MEDIUM").upper()
            confidence = "HIGH" if "HIGH" in raw_conf else ("LOW" if "LOW" in raw_conf else "MEDIUM")

            # Deterministic dedup_key (FR-6): DAST:http_method:url_path:parameter:cwe_id
            dedup_key = compute_dast_dedup_key(
                http_method=http_method,
                url_path=url_path,
                parameter=parameter,
                cwe_id=cwe_id
            )
            finding_id = f"dast-{dedup_key[:12]}"

            description = alert.get("description") or default_desc
            fix_suggestion = alert.get("solution") or None

            # FR-6: Merge duplicate alerts for the same bug
            if dedup_key not in findings_map:
                findings_map[dedup_key] = UnifiedFinding(
                    finding_id=finding_id,
                    dedup_key=dedup_key,
                    source_scanner="DAST",
                    cwe_id=cwe_id,
                    vulnerability_type=vuln_type,
                    severity=severity,
                    confidence=confidence,
                    file=None,
                    line=None,
                    end_line=None,
                    code_snippet=None,
                    handler_function=None,
                    url_path=url_path,
                    http_method=http_method,
                    parameter=parameter,
                    payload=payload,
                    evidence=evidence,
                    status_label="Runtime only",  # FR-7 default before correlation
                    description=description,
                    fix_suggestion=fix_suggestion
                )
            else:
                # Merge evidence & payload into existing finding
                existing = findings_map[dedup_key]
                if evidence and existing.evidence and evidence not in existing.evidence:
                    existing.evidence = f"{existing.evidence} | {evidence}"
                elif evidence and not existing.evidence:
                    existing.evidence = evidence

                if payload and not existing.payload:
                    existing.payload = payload

                # Elevate severity if higher
                if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(existing.severity, 0):
                    existing.severity = severity

        # Return sorted by severity
        sorted_findings = list(findings_map.values())
        sorted_findings.sort(
            key=lambda f: (-SEVERITY_ORDER.get(f.severity.upper(), 0), f.url_path or "", f.parameter or "")
        )
        return sorted_findings

    def run_zap_scan(
        self,
        target_url: str,
        seed_routes: Optional[List[str]] = None,
        zap_api_url: str = "http://localhost:8090",
        zap_api_key: Optional[str] = None
    ) -> List[UnifiedFinding]:
        """
        Mode A: Connects to live OWASP ZAP headless daemon, seeds URLs,
        polls spider scan, and retrieves resulting alerts.
        """
        base_api = zap_api_url.rstrip("/")
        params: Dict[str, str] = {}
        if zap_api_key:
            params["apikey"] = zap_api_key

        logger.info(f"Connecting to live OWASP ZAP daemon at {base_api} for {target_url}")

        with httpx.Client(timeout=self.default_timeout) as client:
            # Check ZAP connectivity
            version_res = client.get(f"{base_api}/JSON/core/view/version/", params=params)
            version_res.raise_for_status()
            logger.info(f"Connected to OWASP ZAP daemon (version: {version_res.json().get('version', 'unknown')})")

            # Seed URL tree with target and routes
            client.get(
                f"{base_api}/JSON/core/action/accessUrl/",
                params={**params, "url": target_url}
            )

            if seed_routes:
                for route in seed_routes:
                    sub_url = urllib.parse.urljoin(target_url, route)
                    try:
                        client.get(
                            f"{base_api}/JSON/core/action/accessUrl/",
                            params={**params, "url": sub_url}
                        )
                    except Exception as e:
                        logger.warning(f"Could not seed URL {sub_url}: {e}")

            # Trigger spider scan
            spider_params = {
                **params,
                "url": target_url,
                "maxChildren": "10",
                "recurse": "true"
            }
            spider_res = client.get(f"{base_api}/JSON/spider/action/scan/", params=spider_params)
            scan_id = spider_res.json().get("scan", "0")

            # Poll spider status briefly
            for _ in range(10):
                status_res = client.get(
                    f"{base_api}/JSON/spider/view/status/",
                    params={**params, "scanId": scan_id}
                )
                progress = int(status_res.json().get("status", 100))
                if progress >= 100:
                    break

            # Fetch alerts from ZAP
            alerts_params = {
                **params,
                "baseurl": target_url,
                "start": "0",
                "count": "500"
            }
            alerts_res = client.get(f"{base_api}/JSON/core/view/alerts/", params=alerts_params)
            alerts_res.raise_for_status()

            raw_alerts = alerts_res.json().get("alerts", [])
            logger.info(f"Retrieved {len(raw_alerts)} raw alerts from OWASP ZAP")
            return self.parse_zap_alerts(raw_alerts)

    def run_local_diagnostics(
        self,
        target_url: str,
        seed_routes: Optional[List[str]] = None
    ) -> List[UnifiedFinding]:
        """
        Mode B: Local Verification Mode when ZAP is offline.
        Executes deterministic diagnostic checks against target_url and seed_routes
        for missing security headers, information disclosure, and error reflections.
        """
        logger.info(f"Executing Mode B deterministic DAST diagnostics on {target_url}")
        simulated_alerts: List[Dict[str, Any]] = []

        # Common SQL injection error signatures for response inspection
        sql_error_patterns = [
            re.compile(r'syntax error.*(SQL|sqlite|mysql|postgresql|syntax)', re.IGNORECASE),
            re.compile(r'(sqlite3\.OperationalError|pymysql\.err|psycopg2\.errors)', re.IGNORECASE),
            re.compile(r'unclosed quotation mark after the character string', re.IGNORECASE),
            re.compile(r'You have an error in your SQL syntax', re.IGNORECASE),
        ]

        try:
            with httpx.Client(timeout=5.0, follow_redirects=True) as client:
                # 1. Base URL inspection (Headers, Information Exposure)
                try:
                    res = client.get(target_url)
                    headers = {k.lower(): v for k, v in res.headers.items()}

                    # Missing CSP
                    if "content-security-policy" not in headers:
                        simulated_alerts.append({
                            "pluginId": "10038",
                            "cweid": "693",
                            "alert": "Content Security Policy (CSP) Header Not Set",
                            "risk": "Medium",
                            "confidence": "High",
                            "url": target_url,
                            "method": "GET",
                            "param": None,
                            "attack": None,
                            "evidence": "Header 'Content-Security-Policy' missing from HTTP response",
                            "description": "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.",
                            "solution": "Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header."
                        })

                    # Missing X-Frame-Options (Clickjacking)
                    if "x-frame-options" not in headers:
                        simulated_alerts.append({
                            "pluginId": "10020",
                            "cweid": "693",
                            "alert": "X-Frame-Options Header Missing",
                            "risk": "Medium",
                            "confidence": "High",
                            "url": target_url,
                            "method": "GET",
                            "param": None,
                            "attack": None,
                            "evidence": "Header 'X-Frame-Options' missing from HTTP response",
                            "description": "Clickjacking vulnerability due to missing X-Frame-Options header.",
                            "solution": "Configure 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
                        })

                    # Missing X-Content-Type-Options
                    if "x-content-type-options" not in headers:
                        simulated_alerts.append({
                            "pluginId": "10021",
                            "cweid": "693",
                            "alert": "X-Content-Type-Options Header Missing",
                            "risk": "Low",
                            "confidence": "High",
                            "url": target_url,
                            "method": "GET",
                            "param": None,
                            "attack": None,
                            "evidence": "Header 'X-Content-Type-Options' missing from HTTP response",
                            "description": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'.",
                            "solution": "Ensure that the application/web server sets the Content-Type header and the X-Content-Type-Options: nosniff header."
                        })

                    # Server header disclosure
                    if "server" in headers:
                        simulated_alerts.append({
                            "pluginId": "10037",
                            "cweid": "200",
                            "alert": "Server Leaks Information via 'Server' HTTP Response Header Field",
                            "risk": "Low",
                            "confidence": "High",
                            "url": target_url,
                            "method": "GET",
                            "param": None,
                            "attack": None,
                            "evidence": f"Server: {headers['server']}",
                            "description": "The web/application server leaks its version information through the 'Server' header field.",
                            "solution": "Ensure that the web server does not provide banner information."
                        })

                except Exception as e:
                    logger.warning(f"Mode B could not connect to {target_url}: {e}")

                # 2. Probe seeded routes if provided
                if seed_routes:
                    for route in seed_routes:
                        probe_url = urllib.parse.urljoin(target_url, route)
                        try:
                            # Test SQL injection trigger payload on query param
                            sql_payload = "1' OR '1'='1"
                            test_url = f"{probe_url}?id={urllib.parse.quote(sql_payload)}"
                            test_res = client.get(test_url)

                            for pattern in sql_error_patterns:
                                match = pattern.search(test_res.text)
                                if match:
                                    simulated_alerts.append({
                                        "pluginId": "40018",
                                        "cweid": "89",
                                        "alert": "SQL Injection",
                                        "risk": "High",
                                        "confidence": "High",
                                        "url": probe_url,
                                        "method": "GET",
                                        "param": "id",
                                        "attack": sql_payload,
                                        "evidence": match.group(0),
                                        "description": "A database error or SQL syntax anomaly was observed in the response body.",
                                        "solution": "Use parameterized queries or prepared statements."
                                    })
                                    break
                        except Exception as e:
                            logger.debug(f"Probe on {probe_url} skipped: {e}")

        except Exception as e:
            logger.warning(f"Error during Mode B diagnostics: {e}")

        return self.parse_zap_alerts(simulated_alerts)

    def scan(self, request: DASTScanRequest) -> DASTScanResponse:
        """
        High-level scan dispatcher:
        1. If raw_zap_alerts provided -> Parse directly (Mode B Ingestion).
        2. If live ZAP is accessible -> Run Mode A ZAP scan.
        3. If live ZAP is offline -> Gracefully fallback to Mode B local diagnostics.
        """
        target_url = request.target_url

        # Path 1: Direct JSON report ingestion
        if request.raw_zap_alerts:
            logger.info(f"Ingesting {len(request.raw_zap_alerts)} raw ZAP alerts from request payload")
            findings = self.parse_zap_alerts(request.raw_zap_alerts)
            return DASTScanResponse(
                success=True,
                target_url=target_url,
                total_findings=len(findings),
                findings=findings
            )

        # Path 2: Attempt Mode A (Live OWASP ZAP API)
        zap_api_url = request.zap_api_url or "http://localhost:8090"
        try:
            findings = self.run_zap_scan(
                target_url=target_url,
                seed_routes=request.seed_routes,
                zap_api_url=zap_api_url,
                zap_api_key=request.zap_api_key
            )
            return DASTScanResponse(
                success=True,
                target_url=target_url,
                total_findings=len(findings),
                findings=findings
            )
        except Exception as zap_err:
            logger.info(
                f"OWASP ZAP live daemon not reachable at {zap_api_url} ({zap_err}). "
                f"Falling back to Mode B deterministic runtime diagnostics."
            )
            # Path 3: Fallback to Mode B (Deterministic local runtime diagnostics)
            findings = self.run_local_diagnostics(
                target_url=target_url,
                seed_routes=request.seed_routes
            )
            return DASTScanResponse(
                success=True,
                target_url=target_url,
                total_findings=len(findings),
                findings=findings
            )


_dast_scanner: Optional[DASTScanner] = None


def get_dast_scanner() -> DASTScanner:
    """Singleton accessor for DASTScanner."""
    global _dast_scanner
    if _dast_scanner is None:
        _dast_scanner = DASTScanner()
    return _dast_scanner
