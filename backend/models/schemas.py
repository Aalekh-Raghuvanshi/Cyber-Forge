"""
Pydantic models for request/response schemas.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


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
