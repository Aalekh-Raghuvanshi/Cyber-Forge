"""
Pydantic models for request/response schemas.
Includes Phase 1 unified models for SAST detection, AST Route Mapping, and Canonical CWEs.
"""

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Phase 1 Models: Unified Findings, Route Mapping & Correlation Schemas
# ---------------------------------------------------------------------------

class RouteEntry(BaseModel):
    """
    FR-4 Route Map Entry representing an HTTP endpoint extracted statically from source code.
    Example: GET /api/orders -> get_orders(), orders.py lines 80 to 95
    """
    http_method: List[str] = Field(..., description="HTTP methods accepted, e.g. ['GET']")
    url_path: str = Field(..., description="Normalized URL route path, e.g. '/api/orders'")
    handler_function: str = Field(..., description="Name of the handler function, e.g. 'get_orders'")
    file: str = Field(..., description="Relative file path of the source file, e.g. 'orders.py'")
    start_line: int = Field(..., description="Starting line number of route definition / handler")
    end_line: int = Field(..., description="Ending line number of handler function")
    display: str = Field(..., description="Human-readable route description per FR-4")


class UnifiedFinding(BaseModel):
    """
    FR-3 Common finding format for both SAST (now) and DAST (Phase 2).
    Includes deterministic dedup_key and canonical CWE mapping.
    """
    finding_id: str = Field(..., description="Unique identifier for finding")
    dedup_key: str = Field(..., description="Deterministic SHA256 hash (scanner_type + file + line + cwe_id)")
    source_scanner: Literal["SAST", "DAST"] = Field(..., description="Scanner that discovered this finding")
    cwe_id: str = Field(..., description="Canonical CWE identifier, e.g. 'CWE-89'")
    vulnerability_type: str = Field(..., description="Canonical vulnerability type name, e.g. 'SQL Injection'")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(..., description="Standardized severity level")
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(default="HIGH", description="Detection confidence")

    # SAST fields (populated by SAST, Optional for DAST)
    file: Optional[str] = Field(default=None, description="Relative path of affected source file")
    line: Optional[int] = Field(default=None, description="Starting line number")
    end_line: Optional[int] = Field(default=None, description="Ending line number")
    code_snippet: Optional[str] = Field(default=None, description="Vulnerable code snippet")
    handler_function: Optional[str] = Field(default=None, description="Enclosing route handler function if mapped")

    # Route / DAST fields (populated by Route Mapper for SAST, or DAST scanner in Phase 2)
    url_path: Optional[str] = Field(default=None, description="Affected URL endpoint path")
    http_method: Optional[str] = Field(default=None, description="HTTP method (e.g. 'GET', 'POST')")
    parameter: Optional[str] = Field(default=None, description="Affected parameter name")
    payload: Optional[str] = Field(default=None, description="Exploit or test payload")
    evidence: Optional[str] = Field(default=None, description="Runtime or static evidence")

    # Default label for SAST-only before correlation
    status_label: Literal["Confirmed", "Code only", "Runtime only"] = Field(
        default="Code only",
        description="FR-7 Issue label (Confirmed, Code only, or Runtime only)"
    )

    # Descriptive and remediation details
    description: Optional[str] = Field(default=None, description="Detailed vulnerability description")
    fix_suggestion: Optional[str] = Field(default=None, description="Recommended remediation steps")
    fixed_code: Optional[str] = Field(default=None, description="Example secure code replacement")


class CorrelatedIssue(BaseModel):
    """
    Correlated security issue model bridging SAST and DAST findings.
    Prepared for FR-5, FR-6, and FR-7.
    """
    issue_id: str = Field(..., description="Unique issue identifier")
    dedup_key: str = Field(..., description="Deterministic merge key for real bug")
    cwe_id: str = Field(..., description="Canonical CWE, e.g. 'CWE-89'")
    vulnerability_type: str = Field(..., description="Standard vulnerability name")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(...)
    status_label: Literal["Confirmed", "Code only", "Runtime only"] = Field(default="Code only")
    risk_score: float = Field(default=0.0, description="Calculated risk score based on severity and exploitability")

    # Findings linked to this issue
    sast_findings: List[UnifiedFinding] = Field(default_factory=list, description="Linked SAST findings")
    dast_findings: List[UnifiedFinding] = Field(default_factory=list, description="Linked DAST findings")

    # Consolidated location and evidence
    file: Optional[str] = Field(default=None, description="Source code file")
    line: Optional[int] = Field(default=None, description="Source line number")
    end_line: Optional[int] = Field(default=None, description="Source end line number")
    code_snippet: Optional[str] = Field(default=None, description="Source code snippet")
    handler_function: Optional[str] = Field(default=None, description="Handler function name")
    url_path: Optional[str] = Field(default=None, description="Runtime URL path")
    http_method: Optional[str] = Field(default=None, description="HTTP method")
    parameter: Optional[str] = Field(default=None, description="Vulnerable parameter")
    payload: Optional[str] = Field(default=None, description="Exploit payload")
    evidence: Optional[str] = Field(default=None, description="Runtime or static proof")
    description: Optional[str] = Field(default=None, description="Issue description")
    fix_suggestion: Optional[str] = Field(default=None, description="Remediation guidance")
    fixed_code: Optional[str] = Field(default=None, description="Secure implementation example")


class SASTScanRequest(BaseModel):
    """Request schema for SAST scan endpoint."""
    source_folder: Optional[str] = Field(default=None, description="Local folder path to scan")
    files: Optional[List[Dict[str, str]]] = Field(
        default=None,
        description="List of files with 'filename'/'filepath' and 'content'"
    )
    generate_fixes: Optional[bool] = Field(
        default=False,
        description="Optionally generate LLM remediation advice (Zero-Hallucination rule respected)"
    )


class SASTScanResponse(BaseModel):
    """Response schema for SAST scan results."""
    success: bool = Field(..., description="Whether the scan completed successfully")
    total_findings: int = Field(..., description="Total count of deterministic findings")
    findings: List[UnifiedFinding] = Field(default_factory=list, description="List of normalized findings")
    route_map: List[RouteEntry] = Field(default_factory=list, description="Extracted AST route map")
    scanned_files_count: int = Field(..., description="Number of files scanned")
    error: Optional[str] = Field(default=None, description="Error message if scan failed")


class DASTScanRequest(BaseModel):
    """Request schema for DAST scan endpoint (FR-2)."""
    target_url: str = Field(..., description="Target web application base URL, e.g. 'http://localhost:5000'")
    zap_api_url: Optional[str] = Field(default="http://localhost:8090", description="OWASP ZAP API daemon URL")
    zap_api_key: Optional[str] = Field(default=None, description="Optional OWASP ZAP API key")
    seed_routes: Optional[List[str]] = Field(default=None, description="List of URL route paths to seed, e.g. ['/api/orders', '/search']")
    raw_zap_alerts: Optional[List[Dict[str, Any]]] = Field(default=None, description="Pre-captured OWASP ZAP alert dicts for offline ingestion")


class DASTScanResponse(BaseModel):
    """Response schema for DAST scan results (FR-2, FR-3)."""
    success: bool = Field(..., description="Whether the DAST scan or report parsing completed successfully")
    target_url: str = Field(..., description="Target application URL scanned")
    total_findings: int = Field(..., description="Total count of unique DAST findings")
    findings: List[UnifiedFinding] = Field(default_factory=list, description="List of normalized DAST findings")
    error: Optional[str] = Field(default=None, description="Error message if scan failed")


# ---------------------------------------------------------------------------
# Legacy Models (Maintained for Backward Compatibility)
# ---------------------------------------------------------------------------

class VulnerabilityDetail(BaseModel):
    """Details of a detected vulnerability."""
    type: str = Field(..., description="Type of vulnerability (e.g., SQL Injection, XSS)")
    severity: str = Field(..., description="Severity level: critical, high, medium, low")
    line_numbers: Optional[List[int]] = Field(default=None, description="Affected line numbers")
    description: str = Field(..., description="Detailed description of the vulnerability")
    vulnerable_code: Optional[str] = Field(default=None, description="The vulnerable code snippet")
    fix_suggestion: str = Field(..., description="How to fix the vulnerability")
    fixed_code: Optional[str] = Field(default=None, description="Example of fixed code")


class AttackSurface(BaseModel):
    """Identified attack surface in the code."""
    name: str = Field(..., description="Name/identifier of the attack surface")
    type: str = Field(..., description="Type of attack surface (e.g., API endpoint, user input)")
    description: str = Field(..., description="Description of the attack surface")
    risk_level: str = Field(..., description="Risk level: high, medium, low")


class TrustBoundary(BaseModel):
    """Identified trust boundary in the code."""
    name: str = Field(..., description="Name of the trust boundary")
    description: str = Field(..., description="Description of what crosses this boundary")
    components: List[str] = Field(default_factory=list, description="Components involved")


class AnalysisRequest(BaseModel):
    """Request schema for code analysis."""
    code: str = Field(..., description="Source code to analyze")
    language: Optional[str] = Field(default="auto", description="Programming language (auto-detect if not specified)")
    context: Optional[str] = Field(default=None, description="Additional context about the code")


class AnalysisResponse(BaseModel):
    """Response schema for code analysis results."""
    success: bool = Field(..., description="Whether analysis completed successfully")
    language: str = Field(..., description="Detected or specified programming language")
    summary: str = Field(..., description="Executive summary of the analysis")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score (0-100)")
    attack_surfaces: List[AttackSurface] = Field(default_factory=list)
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityDetail] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list, description="General security recommendations")
    static_findings: Optional[List[dict]] = Field(default=None, description="Findings from static analysis")
    error: Optional[str] = Field(default=None, description="Error message if analysis failed")


class HealthResponse(BaseModel):
    """Response schema for health check."""
    status: str
    llm_mode: str
    version: str = "1.0.0"


class FileAnalysisResult(BaseModel):
    """Result for a single file in multi-file analysis."""
    filename: str = Field(..., description="Name of the analyzed file")
    filepath: str = Field(..., description="Path of the file")
    analysis: AnalysisResponse = Field(..., description="Analysis result for this file")


class MultiFileAnalysisRequest(BaseModel):
    """Request schema for multi-file analysis."""
    files: List[dict] = Field(..., description="List of files with 'filename', 'content', and optional 'language'")


class MultiFileAnalysisResponse(BaseModel):
    """Response schema for multi-file analysis results."""
    success: bool = Field(..., description="Whether analysis completed successfully")
    total_files: int = Field(..., description="Total number of files analyzed")
    total_vulnerabilities: int = Field(..., description="Total vulnerabilities found across all files")
    overall_risk_score: int = Field(..., ge=0, le=100, description="Overall risk score (0-100)")
    summary: str = Field(..., description="Summary of multi-file analysis")
    results: List[FileAnalysisResult] = Field(default_factory=list, description="Results per file")
    error: Optional[str] = Field(default=None, description="Error message if analysis failed")
