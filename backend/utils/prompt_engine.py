"""
Prompt templates for LLM-based code security analysis.
"""

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
    """
    Build the complete analysis prompt with code and optional static findings.
    
    Args:
        code: Source code to analyze
        language: Programming language (or "auto" for detection)
        static_findings: Optional list of static analysis findings
    
    Returns:
        Complete prompt string
    """
    static_section = ""
    if static_findings:
        findings_text = "\n".join(f"- {f['type']}: {f['description']} (line {f.get('line', 'N/A')})" 
                                   for f in static_findings)
        static_section = STATIC_FINDINGS_TEMPLATE.format(findings=findings_text)
    
    return SECURITY_ANALYSIS_PROMPT.format(
        language=language if language != "auto" else "",
        code=code,
        static_findings_section=static_section
    )
