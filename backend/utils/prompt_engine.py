"""
Prompt templates for code security analysis and sandboxed remediation.
Includes Phase 3 zero-hallucination remediation prompt.
"""

from typing import Optional, List, Dict, Any


SECURITY_ANALYSIS_PROMPT = """Analyze this code for security issues. Return ONLY valid JSON.

```{language}
{code}
```
{static_findings_section}
Return this exact JSON structure (keep all descriptions under 40 words):

{{
    "language": "language name",
    "summary": "Brief 1-2 sentence summary",
    "risk_score": 0-100,
    "attack_surfaces": [
        {{"name": "name", "type": "type", "description": "short desc", "risk_level": "high|medium|low"}}
    ],
    "trust_boundaries": [
        {{"name": "name", "description": "short desc", "components": ["a", "b"]}}
    ],
    "vulnerabilities": [
        {{
            "type": "vuln type",
            "severity": "critical|high|medium|low",
            "line_numbers": [1],
            "description": "short description",
            "vulnerable_code": "code snippet",
            "fix_suggestion": "how to fix",
            "fixed_code": "corrected code"
        }}
    ],
    "recommendations": ["rec1", "rec2"]
}}

Focus on: SQL Injection, XSS, Command Injection, Hardcoded Secrets, eval(), Insecure Deserialization.
Return ONLY the JSON object, nothing else."""


STATIC_FINDINGS_TEMPLATE = """
## Static Analysis Findings:
The following potential issues were detected by static analysis:
{findings}

Consider these findings in your analysis and validate whether they represent actual vulnerabilities.
"""


def build_analysis_prompt(code: str, language: str = "auto", static_findings: list = None) -> str:
    """Build the complete analysis prompt for legacy analyzer endpoints."""
    static_section = ""
    if static_findings:
        findings_text = "\n".join(
            f"- {f.get('type', 'Vuln')}: {f.get('description', '')} (line {f.get('line', 'N/A')})"
            for f in static_findings
        )
        static_section = STATIC_FINDINGS_TEMPLATE.format(findings=findings_text)

    return SECURITY_ANALYSIS_PROMPT.format(
        language=language if language != "auto" else "",
        code=code,
        static_findings_section=static_section
    )


# ---------------------------------------------------------------------------
# Phase 3: Sandboxed Remediation Prompt (Zero-Hallucination)
# ---------------------------------------------------------------------------

REMEDIATION_PROMPT = """You are a precise security remediation engine.
You are given an already deterministically detected vulnerability.
Your job is STRICTLY to produce a fix explanation and drop-in fixed code.
Do NOT detect new vulnerabilities or modify line numbers.

Vulnerability: {vulnerability_type} ({cwe_id})
File: {file}
Line: {line}
Vulnerable Snippet:
```
{code_snippet}
```
{dast_evidence_section}

Return ONLY valid JSON with this exact schema (no markdown, no other keys):
{{
    "fix_suggestion": "A concise 1-2 sentence explanation of how to remediate the vulnerability.",
    "fixed_code": "The exact drop-in replacement code snippet fixing the vulnerability."
}}"""


def build_remediation_prompt(
    cwe_id: str,
    vulnerability_type: str,
    file: Optional[str] = None,
    line: Optional[int] = None,
    code_snippet: Optional[str] = None,
    payload: Optional[str] = None,
    evidence: Optional[str] = None
) -> str:
    """
    Builds the sandboxed remediation prompt strictly for generating fix_suggestion and fixed_code.
    """
    dast_evidence = ""
    if payload or evidence:
        parts = []
        if payload:
            parts.append(f"Observed Runtime Payload: {payload}")
        if evidence:
            parts.append(f"Observed Runtime Evidence: {evidence}")
        dast_evidence = "\n" + "\n".join(parts) + "\n"

    return REMEDIATION_PROMPT.format(
        vulnerability_type=vulnerability_type or "Security Vulnerability",
        cwe_id=cwe_id or "CWE-Unknown",
        file=file or "target file",
        line=str(line or 1),
        code_snippet=(code_snippet or "# Vulnerable code").strip(),
        dast_evidence_section=dast_evidence
    )
