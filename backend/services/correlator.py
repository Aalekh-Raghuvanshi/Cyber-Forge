"""
Correlation & Deduplication Engine.
Fulfills FR-5, FR-6, FR-7, and FR-9:
- FR-5: Correlates SAST code findings with DAST runtime findings based on CWE match,
  route-to-code line boundary match, and parameter boost tie-breakers.
- FR-6: Idempotently merges duplicate findings pointing to the same bug with aggregated evidence.
- FR-7: Exact status labels: 'Confirmed', 'Runtime only', 'Code only'.
- FR-9: Strict priority ranking ('Confirmed' first, then 'Runtime only', then 'Code only',
  sorted descending by risk_score).
"""

import os
import hashlib
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict

from backend.models.schemas import UnifiedFinding, RouteEntry, CorrelatedIssue
from backend.services.cwe_normalizer import normalize_cwe, SEVERITY_ORDER
from backend.services.route_mapper import paths_match, normalize_file_path
from backend.utils.logger import get_logger

logger = get_logger("correlator")


def compute_issue_hash(
    cwe_id: str,
    file: Optional[str],
    line: Optional[int],
    url_path: Optional[str]
) -> str:
    """
    Computes a deterministic SHA-256 hash representing a unique security issue (FR-6).
    Running scans twice on the same bug produces identical issue_hash.
    """
    norm_cwe = (cwe_id or "").strip().upper()
    norm_file = (file or "").replace("\\", "/").strip()
    if norm_file.startswith("./"):
        norm_file = norm_file[2:]

    norm_line = str(line or 0)
    norm_url = (url_path or "").strip()
    if norm_url != "/" and norm_url.endswith("/"):
        norm_url = norm_url[:-1]

    raw_signature = f"{norm_cwe}:{norm_file}:{norm_line}:{norm_url}"
    return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()


def calculate_risk_score(
    severity: str,
    status_label: str,
    has_active_route: bool = False
) -> int:
    """
    FR-9 Risk Score Calculation (0 to 100):
    - Severity base weight: CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10.
    - Exploitability bonus:
      +50 if 'Confirmed' (verified runtime vulnerability in source code)
      +25 if 'Runtime only' (active exploit observed at runtime)
      +10 if 'Code only' on an active exposed route
      +0  if 'Code only' with no route (e.g. backend utility / offline secret)
    """
    severity_weights = {
        "CRITICAL": 40,
        "HIGH": 30,
        "MEDIUM": 20,
        "LOW": 10
    }
    base = severity_weights.get(severity.upper(), 20)

    if status_label == "Confirmed":
        bonus = 50
    elif status_label == "Runtime only":
        bonus = 25
    elif status_label == "Code only":
        bonus = 10 if has_active_route else 0
    else:
        bonus = 0

    return min(100, max(0, base + bonus))


class CorrelationEngine:
    """
    Correlates SAST findings and DAST findings into prioritized, deduplicated issues.
    """

    def __init__(self):
        pass

    def _normalize_path(self, path: Optional[str]) -> str:
        """Standardizes URL paths for comparison."""
        if not path:
            return ""
        p = path.strip()
        if p != "/" and p.endswith("/"):
            p = p[:-1]
        if not p.startswith("/") and p != "":
            p = f"/{p}"
        return p

    def _route_covers_sast(self, route: RouteEntry, sast: UnifiedFinding) -> bool:
        """Checks if a route definition line span encloses a SAST finding in the same file."""
        if not sast.file or sast.line is None:
            return False
        if paths_match(sast.file, route.file):
            return route.start_line <= sast.line <= route.end_line
        return False

    def correlate(
        self,
        sast_findings: List[UnifiedFinding],
        dast_findings: List[UnifiedFinding],
        route_map: List[RouteEntry]
    ) -> List[CorrelatedIssue]:
        """
        Executes FR-5 correlation, FR-6 deduplication, FR-7 labeling, and FR-9 ranking.
        """
        logger.info(
            f"Correlating {len(sast_findings)} SAST findings with {len(dast_findings)} DAST findings "
            f"across {len(route_map)} routes."
        )

        # Index routes by normalized url_path
        routes_by_path: Dict[str, List[RouteEntry]] = defaultdict(list)
        for r in route_map:
            norm_rpath = self._normalize_path(r.url_path)
            routes_by_path[norm_rpath].append(r)

        # Track which findings have been linked
        matched_sast_ids: Set[str] = set()
        matched_dast_ids: Set[str] = set()

        # Intermediate issue buckets keyed by deterministic issue_hash
        issue_buckets: Dict[str, Dict[str, Any]] = {}

        # -------------------------------------------------------------------
        # Step 1: FR-5 Link DAST to SAST Findings
        # -------------------------------------------------------------------
        for dast in dast_findings:
            dast_path = self._normalize_path(dast.url_path)
            candidate_matches: List[Tuple[int, UnifiedFinding, Optional[RouteEntry]]] = []

            for sast in sast_findings:
                # 1. CWE Match
                if sast.cwe_id.upper() != dast.cwe_id.upper():
                    continue

                # 2. Route-to-Code Match
                route_matched = False
                matched_route_entry: Optional[RouteEntry] = None

                # Direct URL path match
                sast_path = self._normalize_path(sast.url_path)
                if sast_path and sast_path == dast_path:
                    route_matched = True

                # Route map line coverage match
                if not route_matched and dast_path in routes_by_path:
                    for r in routes_by_path[dast_path]:
                        if self._route_covers_sast(r, sast):
                            route_matched = True
                            matched_route_entry = r
                            break

                if route_matched:
                    # 3. Parameter Boost (Tie-Breaker)
                    score = 100
                    if dast.parameter:
                        param_str = dast.parameter.lower()
                        code_lower = (sast.code_snippet or "").lower()
                        if param_str in code_lower:
                            score += 50
                        if dast.parameter == sast.parameter:
                            score += 30

                    if dast.http_method and sast.http_method:
                        if dast.http_method.upper() == sast.http_method.upper():
                            score += 10

                    candidate_matches.append((score, sast, matched_route_entry))

            # If candidates found, select the highest-scoring SAST finding
            if candidate_matches:
                candidate_matches.sort(key=lambda x: x[0], reverse=True)
                _, best_sast, best_route = candidate_matches[0]

                matched_dast_ids.add(dast.finding_id)
                matched_sast_ids.add(best_sast.finding_id)

                # Compute deterministic issue_hash for the merged bug
                h = compute_issue_hash(
                    cwe_id=best_sast.cwe_id,
                    file=best_sast.file,
                    line=best_sast.line,
                    url_path=dast.url_path
                )

                route_display = None
                if best_route:
                    route_display = best_route.display
                elif best_sast.url_path:
                    route_display = f"{dast.http_method or 'GET'} {dast.url_path} -> {best_sast.handler_function or 'handler'}(), {best_sast.file or ''}"

                # Severity: highest of both
                combined_sev = "CRITICAL" if ("CRITICAL" in (best_sast.severity, dast.severity)) else (
                    "HIGH" if ("HIGH" in (best_sast.severity, dast.severity)) else (
                        "MEDIUM" if ("MEDIUM" in (best_sast.severity, dast.severity)) else "LOW"
                    )
                )

                if h not in issue_buckets:
                    issue_buckets[h] = {
                        "issue_hash": h,
                        "status_label": "Confirmed",  # FR-7
                        "cwe_id": best_sast.cwe_id,
                        "vulnerability_type": best_sast.vulnerability_type,
                        "severity": combined_sev,
                        "file": best_sast.file,
                        "line": best_sast.line,
                        "end_line": best_sast.end_line or best_sast.line,
                        "handler_function": best_sast.handler_function or (best_route.handler_function if best_route else None),
                        "code_snippet": best_sast.code_snippet,
                        "http_method": dast.http_method,
                        "url_path": dast.url_path,
                        "parameter": dast.parameter or best_sast.parameter,
                        "payload": dast.payload,
                        "evidence": dast.evidence,
                        "description": dast.description or best_sast.description,
                        "fix_suggestion": best_sast.fix_suggestion or dast.fix_suggestion,
                        "fixed_code": best_sast.fixed_code,
                        "matched_route": route_display,
                        "supporting_scanners": ["SAST", "DAST"],
                        "merged_count": 2,
                        "has_route": True
                    }
                else:
                    # FR-6 Merge additional evidence into existing confirmed bug
                    b = issue_buckets[h]
                    b["merged_count"] += 1
                    if "DAST" not in b["supporting_scanners"]:
                        b["supporting_scanners"].append("DAST")
                    if dast.evidence and b["evidence"] and dast.evidence not in b["evidence"]:
                        b["evidence"] = f"{b['evidence']} | {dast.evidence}"
                    elif dast.evidence and not b["evidence"]:
                        b["evidence"] = dast.evidence

                    if dast.payload and not b["payload"]:
                        b["payload"] = dast.payload

        # -------------------------------------------------------------------
        # Step 2: Process Unmatched DAST Findings -> 'Runtime only'
        # -------------------------------------------------------------------
        for dast in dast_findings:
            if dast.finding_id in matched_dast_ids:
                continue

            h = compute_issue_hash(
                cwe_id=dast.cwe_id,
                file=None,
                line=None,
                url_path=dast.url_path
            )

            if h not in issue_buckets:
                issue_buckets[h] = {
                    "issue_hash": h,
                    "status_label": "Runtime only",  # FR-7
                    "cwe_id": dast.cwe_id,
                    "vulnerability_type": dast.vulnerability_type,
                    "severity": dast.severity,
                    "file": None,
                    "line": None,
                    "end_line": None,
                    "handler_function": None,
                    "code_snippet": None,
                    "http_method": dast.http_method,
                    "url_path": dast.url_path,
                    "parameter": dast.parameter,
                    "payload": dast.payload,
                    "evidence": dast.evidence,
                    "description": dast.description,
                    "fix_suggestion": dast.fix_suggestion,
                    "fixed_code": None,
                    "matched_route": None,
                    "supporting_scanners": ["DAST"],
                    "merged_count": 1,
                    "has_route": bool(dast.url_path)
                }
            else:
                b = issue_buckets[h]
                b["merged_count"] += 1
                if dast.evidence and b["evidence"] and dast.evidence not in b["evidence"]:
                    b["evidence"] = f"{b['evidence']} | {dast.evidence}"

        # -------------------------------------------------------------------
        # Step 3: Process Unmatched SAST Findings -> 'Code only'
        # -------------------------------------------------------------------
        for sast in sast_findings:
            if sast.finding_id in matched_sast_ids:
                continue

            h = compute_issue_hash(
                cwe_id=sast.cwe_id,
                file=sast.file,
                line=sast.line,
                url_path=sast.url_path
            )

            has_route = bool(sast.url_path)

            if h not in issue_buckets:
                route_disp = None
                if sast.url_path:
                    route_disp = f"{sast.http_method or 'GET'} {sast.url_path} -> {sast.handler_function or 'handler'}(), {sast.file or ''}"

                issue_buckets[h] = {
                    "issue_hash": h,
                    "status_label": "Code only",  # FR-7
                    "cwe_id": sast.cwe_id,
                    "vulnerability_type": sast.vulnerability_type,
                    "severity": sast.severity,
                    "file": sast.file,
                    "line": sast.line,
                    "end_line": sast.end_line or sast.line,
                    "handler_function": sast.handler_function,
                    "code_snippet": sast.code_snippet,
                    "http_method": sast.http_method,
                    "url_path": sast.url_path,
                    "parameter": sast.parameter,
                    "payload": None,
                    "evidence": None,
                    "description": sast.description,
                    "fix_suggestion": sast.fix_suggestion,
                    "fixed_code": sast.fixed_code,
                    "matched_route": route_disp,
                    "supporting_scanners": ["SAST"],
                    "merged_count": 1,
                    "has_route": has_route
                }
            else:
                b = issue_buckets[h]
                b["merged_count"] += 1
                if not b["code_snippet"] and sast.code_snippet:
                    b["code_snippet"] = sast.code_snippet

        # -------------------------------------------------------------------
        # Step 4: FR-9 Calculate Risk Scores & Strict Priority Sorting
        # -------------------------------------------------------------------
        status_ranks = {
            "Confirmed": 1,
            "Runtime only": 2,
            "Code only": 3
        }

        raw_issues = []
        for b in issue_buckets.values():
            risk_score = calculate_risk_score(
                severity=b["severity"],
                status_label=b["status_label"],
                has_active_route=b["has_route"]
            )
            b["risk_score"] = risk_score
            raw_issues.append(b)

        # Strict sorting: Confirmed (1) -> Runtime only (2) -> Code only (3), then risk_score DESC
        raw_issues.sort(
            key=lambda x: (
                status_ranks.get(x["status_label"], 99),
                -x["risk_score"],
                -SEVERITY_ORDER.get(x["severity"].upper(), 0),
                x["cwe_id"],
                x["file"] or "",
                x["line"] or 0
            )
        )

        # -------------------------------------------------------------------
        # Step 5: Assign Sequential IDs (1-based) & Build Models
        # -------------------------------------------------------------------
        final_issues: List[CorrelatedIssue] = []
        for idx, item in enumerate(raw_issues, 1):
            issue = CorrelatedIssue(
                id=idx,
                issue_hash=item["issue_hash"],
                status_label=item["status_label"],
                priority_rank=idx,
                risk_score=item["risk_score"],
                cwe_id=item["cwe_id"],
                vulnerability_type=item["vulnerability_type"],
                severity=item["severity"],
                file=item["file"],
                line=item["line"],
                end_line=item["end_line"],
                handler_function=item["handler_function"],
                code_snippet=item["code_snippet"],
                http_method=item["http_method"],
                url_path=item["url_path"],
                parameter=item["parameter"],
                payload=item["payload"],
                evidence=item["evidence"],
                fix_suggestion=item.get("fix_suggestion"),
                fixed_code=item.get("fixed_code"),
                description=item.get("description"),
                matched_route=item.get("matched_route"),
                supporting_scanners=sorted(list(set(item["supporting_scanners"]))),
                merged_count=item["merged_count"]
            )
            final_issues.append(issue)

        logger.info(
            f"Correlation complete: {len(final_issues)} total issues "
            f"({sum(1 for i in final_issues if i.status_label == 'Confirmed')} Confirmed, "
            f"{sum(1 for i in final_issues if i.status_label == 'Runtime only')} Runtime only, "
            f"{sum(1 for i in final_issues if i.status_label == 'Code only')} Code only)."
        )

        return final_issues


_correlation_engine: Optional[CorrelationEngine] = None


def get_correlation_engine() -> CorrelationEngine:
    """Singleton provider for CorrelationEngine."""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine()
    return _correlation_engine
