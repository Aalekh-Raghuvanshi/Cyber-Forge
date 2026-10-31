"""
Static Analysis module for rule-based vulnerability detection.
Complements LLM analysis with deterministic pattern matching.
"""

import re
import ast
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class StaticFinding:
    """A finding from static analysis."""
    type: str
    severity: str
    line: int
    description: str
    code_snippet: str
    pattern: str


class StaticAnalyzer:
    """Rule-based static analyzer for common vulnerability patterns."""
    
    # Vulnerability patterns for different languages
    PATTERNS = {
        "python": [
            {
                "name": "SQL Injection",
                "pattern": r'(execute|executemany|raw)\s*\([^)]*(%s|%d|\+|\.format|f["\'])',
                "severity": "critical",
                "description": "Potential SQL injection via string formatting or concatenation"
            },
            {
                "name": "SQL Injection",
                "pattern": r'["\']SELECT\s+.*\s+FROM\s+.*["\']\s*\+',
                "severity": "critical",
                "description": "SQL query built using string concatenation"
            },
            {
                "name": "Command Injection",
                "pattern": r'(os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\([^)]*(\+|%|\.format|f["\'])',
                "severity": "critical",
                "description": "Potential command injection via string formatting"
            },
            {
                "name": "Command Injection",
                "pattern": r'(os\.system|os\.popen)\s*\(',
                "severity": "high",
                "description": "Use of os.system/popen - prefer subprocess with shell=False"
            },
            {
                "name": "Dangerous eval()",
                "pattern": r'\beval\s*\(',
                "severity": "critical",
                "description": "Use of eval() can execute arbitrary code"
            },
            {
                "name": "Dangerous exec()",
                "pattern": r'\bexec\s*\(',
                "severity": "critical",
                "description": "Use of exec() can execute arbitrary code"
            },
            {
                "name": "Hardcoded Secret",
                "pattern": r'(password|passwd|secret|api_key|apikey|token|auth)\s*=\s*["\'][^"\']{8,}["\']',
                "severity": "high",
                "description": "Potential hardcoded secret or credential",
                "flags": re.IGNORECASE
            },
            {
                "name": "Insecure Deserialization",
                "pattern": r'pickle\.(loads?|Unpickler)',
                "severity": "high",
                "description": "Pickle deserialization can execute arbitrary code"
            },
            {
                "name": "Insecure YAML Loading",
                "pattern": r'yaml\.load\s*\([^)]*\)',
                "severity": "medium",
                "description": "Use yaml.safe_load() instead of yaml.load()"
            },
            {
                "name": "Path Traversal",
                "pattern": r'open\s*\([^)]*\+',
                "severity": "medium",
                "description": "File path built with concatenation - potential path traversal"
            },
            {
                "name": "Weak Cryptography",
                "pattern": r'(md5|sha1)\s*\(',
                "severity": "medium",
                "description": "MD5/SHA1 are cryptographically weak - use SHA-256 or better"
            },
            {
                "name": "Debug Mode",
                "pattern": r'debug\s*=\s*True',
                "severity": "low",
                "description": "Debug mode enabled - ensure disabled in production",
                "flags": re.IGNORECASE
            },
            {
                "name": "Assert Statement",
                "pattern": r'^(\s*)assert\s+',
                "severity": "low",
                "description": "Assert statements are removed with -O flag"
            }
        ],
        "javascript": [
            {
                "name": "XSS via innerHTML",
                "pattern": r'\.innerHTML\s*=',
                "severity": "high",
                "description": "innerHTML assignment can lead to XSS"
            },
            {
                "name": "XSS via document.write",
                "pattern": r'document\.write\s*\(',
                "severity": "high",
                "description": "document.write can lead to XSS"
            },
            {
                "name": "Dangerous eval()",
                "pattern": r'\beval\s*\(',
                "severity": "critical",
                "description": "eval() can execute arbitrary code"
            },
            {
                "name": "SQL Injection",
                "pattern": r'(query|execute)\s*\([^)]*(\+|`\$\{)',
                "severity": "critical",
                "description": "SQL query with string interpolation"
            },
            {
                "name": "Command Injection",
                "pattern": r'(exec|spawn|execSync)\s*\([^)]*(\+|`\$\{)',
                "severity": "critical",
                "description": "Command execution with string interpolation"
            },
            {
                "name": "Hardcoded Secret",
                "pattern": r'(password|secret|api_key|token)\s*[=:]\s*["\'][^"\']{8,}["\']',
                "severity": "high",
                "description": "Potential hardcoded secret",
                "flags": re.IGNORECASE
            },
            {
                "name": "Insecure Randomness",
                "pattern": r'Math\.random\s*\(\)',
                "severity": "medium",
                "description": "Math.random() is not cryptographically secure"
            }
        ],
        "java": [
            {
                "name": "SQL Injection",
                "pattern": r'(executeQuery|executeUpdate|execute)\s*\([^)]*\+',
                "severity": "critical",
                "description": "SQL query built with concatenation"
            },
            {
                "name": "Command Injection",
                "pattern": r'Runtime\.getRuntime\(\)\.exec\s*\(',
                "severity": "high",
                "description": "Runtime.exec() can be vulnerable to command injection"
            },
            {
                "name": "XXE Vulnerability",
                "pattern": r'DocumentBuilderFactory\.newInstance\(\)',
                "severity": "medium",
                "description": "XML parser may be vulnerable to XXE - disable external entities"
            },
            {
                "name": "Hardcoded Secret",
                "pattern": r'(password|secret|apiKey)\s*=\s*"[^"]{8,}"',
                "severity": "high",
                "description": "Potential hardcoded secret",
                "flags": re.IGNORECASE
            }
        ]
    }
    
    def __init__(self):
        self.findings: List[StaticFinding] = []
    
    def analyze(self, code: str, language: str = "auto") -> List[Dict[str, Any]]:
        """
        Analyze code for common vulnerability patterns.
        
        Args:
            code: Source code to analyze
            language: Programming language (auto-detect if not specified)
            
        Returns:
            List of findings as dictionaries
        """
        self.findings = []
        
        if language == "auto":
            language = self._detect_language(code)
        
        patterns = self.PATTERNS.get(language.lower(), [])
        
        # Also check generic patterns
        patterns.extend(self._get_generic_patterns())
        
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern_def in patterns:
                flags = pattern_def.get('flags', 0)
                if re.search(pattern_def['pattern'], line, flags):
                    self.findings.append(StaticFinding(
                        type=pattern_def['name'],
                        severity=pattern_def['severity'],
                        line=i,
                        description=pattern_def['description'],
                        code_snippet=line.strip(),
                        pattern=pattern_def['pattern']
                    ))
        
        # Remove duplicates (same type on same line)
        unique_findings = {}
        for f in self.findings:
            key = (f.type, f.line)
            if key not in unique_findings:
                unique_findings[key] = f
        
        return [
            {
                "type": f.type,
                "severity": f.severity,
                "line": f.line,
                "description": f.description,
                "code_snippet": f.code_snippet
            }
            for f in unique_findings.values()
        ]
    
    def _detect_language(self, code: str) -> str:
        """Simple language detection based on patterns."""
        if re.search(r'\bdef\s+\w+\s*\(|import\s+\w+|from\s+\w+\s+import', code):
            return "python"
        if re.search(r'\bfunction\s+\w+\s*\(|const\s+\w+\s*=|let\s+\w+\s*=|=>\s*{', code):
            return "javascript"
        if re.search(r'\bpublic\s+class\s+|private\s+\w+\s+\w+\s*\(|System\.out\.', code):
            return "java"
        if re.search(r'#include\s*<|int\s+main\s*\(|printf\s*\(', code):
            return "c"
        if re.search(r'<\?php|\$\w+\s*=', code):
            return "php"
        return "unknown"
    
    def _get_generic_patterns(self) -> List[Dict]:
        """Get language-agnostic vulnerability patterns."""
        return [
            {
                "name": "Hardcoded IP Address",
                "pattern": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                "severity": "low",
                "description": "Hardcoded IP address found"
            },
            {
                "name": "TODO/FIXME Security",
                "pattern": r'(TODO|FIXME|XXX|HACK).*?(security|auth|password|secret|vulnerability)',
                "severity": "low",
                "description": "Security-related TODO/FIXME comment found",
                "flags": re.IGNORECASE
            }
        ]


# Singleton instance
_static_analyzer: Optional[StaticAnalyzer] = None


def get_static_analyzer() -> StaticAnalyzer:
    """Get or create the static analyzer singleton."""
    global _static_analyzer
    if _static_analyzer is None:
        _static_analyzer = StaticAnalyzer()
    return _static_analyzer
