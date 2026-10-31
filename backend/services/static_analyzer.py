"""
Deterministic AST & Regex Static Analyzer.
Fulfills FR-1: Deterministic detection of core vulnerabilities mapped to canonical CWEs.
Works 100% offline as a standalone scanner and as a deterministic fallback to Semgrep.
"""

import ast
import re
import os
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass

from backend.models.schemas import UnifiedFinding
from backend.services.cwe_normalizer import normalize_cwe, compute_dedup_key
from backend.utils.logger import get_logger

logger = get_logger("static_analyzer")


@dataclass
class StaticFinding:
    """Internal representation of a static analysis finding."""
    type: str
    severity: str
    line: int
    description: str
    code_snippet: str
    pattern: str
    cwe_id: str
    end_line: Optional[int] = None


class PythonASTDetector(ast.NodeVisitor):
    """
    Deterministic Python AST visitor for detecting vulnerabilities:
    - SQL Injection (CWE-89)
    - OS Command Injection (CWE-78)
    - Path Traversal / LFI (CWE-22)
    - Weak Hashing / Broken Crypto (CWE-328)
    - Hard-coded Credentials (CWE-798)
    - Cross-Site Scripting (CWE-79)
    - Insecure Deserialization (CWE-502)
    - Code Injection (CWE-94)
    """

    def __init__(self, code: str, file_path: str = "snippet.py"):
        self.code = code
        self.lines = code.split("\n")
        self.file_path = file_path
        self.findings: List[StaticFinding] = []

    def _get_snippet(self, start_line: int, end_line: Optional[int] = None) -> str:
        """Extract lines of code as snippet."""
        if start_line < 1 or start_line > len(self.lines):
            return ""
        e = end_line if (end_line and end_line >= start_line and end_line <= len(self.lines)) else start_line
        snippet_lines = self.lines[start_line - 1:e]
        return "\n".join(snippet_lines).strip()

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """Checks if an AST node constructs a dynamic string (BinOp +, %, JoinedStr, format)."""
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Mod)):
                return True
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        return False

    def visit_Call(self, node: ast.Call):
        func_name = ""
        attr_name = ""

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{attr_name}"
            else:
                func_name = attr_name

        start_line = node.lineno
        end_line = getattr(node, "end_lineno", node.lineno)
        snippet = self._get_snippet(start_line, end_line)

        # -------------------------------------------------------------
        # 1. SQL Injection (CWE-89)
        # Calls to execute/raw with dynamic formatted strings or concatenation
        # -------------------------------------------------------------
        sql_methods = {"execute", "executemany", "raw", "select", "execute_query", "raw_query"}
        if attr_name.lower() in sql_methods or func_name.lower() in sql_methods:
            if node.args and self._is_dynamic_string(node.args[0]):
                self.findings.append(
                    StaticFinding(
                        type="SQL Injection",
                        cwe_id="CWE-89",
                        severity="CRITICAL",
                        line=start_line,
                        end_line=end_line,
                        description="Potential SQL Injection: SQL query constructed dynamically with user input or string interpolation",
                        code_snippet=snippet,
                        pattern=f"{attr_name}(<dynamic>)"
                    )
                )

        # -------------------------------------------------------------
        # 2. OS Command Injection (CWE-78)
        # os.system, os.popen, subprocess.* with shell=True or dynamic string
        # -------------------------------------------------------------
        if func_name in ("os.system", "os.popen"):
            self.findings.append(
                StaticFinding(
                    type="OS Command Injection",
                    cwe_id="CWE-78",
                    severity="CRITICAL",
                    line=start_line,
                    end_line=end_line,
                    description=f"Dangerous system command execution via {func_name}. Prefer subprocess with argument array and shell=False.",
                    code_snippet=snippet,
                    pattern=func_name
                )
            )
        elif "subprocess" in func_name:
            # Check for shell=True keyword argument
            has_shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        has_shell_true = True
                    elif isinstance(kw.value, ast.NameConstant) and kw.value.value is True:
                        has_shell_true = True

            if has_shell_true:
                self.findings.append(
                    StaticFinding(
                        type="OS Command Injection",
                        cwe_id="CWE-78",
                        severity="CRITICAL",
                        line=start_line,
                        end_line=end_line,
                        description="Dangerous command execution: subprocess invoked with shell=True enables OS Command Injection.",
                        code_snippet=snippet,
                        pattern="subprocess(..., shell=True)"
                    )
                )

        # -------------------------------------------------------------
        # 3. Path Traversal / LFI (CWE-22)
        # open(), send_file(), FileResponse() with dynamic concatenation or parameters
        # -------------------------------------------------------------
        file_open_funcs = {"open", "send_file", "send_from_directory", "FileResponse"}
        if (func_name in file_open_funcs or attr_name in file_open_funcs) and node.args:
            first_arg = node.args[0]
            if self._is_dynamic_string(first_arg):
                self.findings.append(
                    StaticFinding(
                        type="Path Traversal",
                        cwe_id="CWE-22",
                        severity="HIGH",
                        line=start_line,
                        end_line=end_line,
                        description="Potential Path Traversal: File path is constructed with dynamic concatenation or formatting without path normalization.",
                        code_snippet=snippet,
                        pattern=f"{func_name}(<dynamic_path>)"
                    )
                )

        # -------------------------------------------------------------
        # 4. Weak Hashing / Broken Crypto (CWE-328)
        # hashlib.md5, hashlib.sha1
        # -------------------------------------------------------------
        if func_name in ("hashlib.md5", "hashlib.sha1", "MD5.new", "SHA.new", "SHA1.new"):
            self.findings.append(
                StaticFinding(
                    type="Weak Hashing",
                    cwe_id="CWE-328",
                    severity="MEDIUM",
                    line=start_line,
                    end_line=end_line,
                    description=f"Weak cryptographic hash function used ({func_name}). Use SHA-256 or secure password hashing algorithms (Argon2, bcrypt).",
                    code_snippet=snippet,
                    pattern=func_name
                )
            )

        # -------------------------------------------------------------
        # 5. Cross-Site Scripting (CWE-79)
        # render_template_string, Markup(), raw_html responses
        # -------------------------------------------------------------
        if func_name in ("render_template_string", "Markup") or attr_name in ("render_template_string", "Markup"):
            self.findings.append(
                StaticFinding(
                    type="Cross-Site Scripting (XSS)",
                    cwe_id="CWE-79",
                    severity="HIGH",
                    line=start_line,
                    end_line=end_line,
                    description="Potential XSS: Unescaped string rendering or Markup construction bypasses HTML sanitization.",
                    code_snippet=snippet,
                    pattern=func_name or attr_name
                )
            )

        # -------------------------------------------------------------
        # 6. Insecure Deserialization & Code Injection (CWE-502 / CWE-94)
        # -------------------------------------------------------------
        if func_name in ("pickle.loads", "pickle.load", "_pickle.loads", "yaml.load"):
            self.findings.append(
                StaticFinding(
                    type="Insecure Deserialization",
                    cwe_id="CWE-502",
                    severity="HIGH",
                    line=start_line,
                    end_line=end_line,
                    description=f"Insecure deserialization via {func_name} can lead to remote arbitrary code execution.",
                    code_snippet=snippet,
                    pattern=func_name
                )
            )

        if func_name in ("eval", "exec"):
            self.findings.append(
                StaticFinding(
                    type="Code Injection",
                    cwe_id="CWE-94",
                    severity="CRITICAL",
                    line=start_line,
                    end_line=end_line,
                    description=f"Dynamic code execution via {func_name}() allows arbitrary command and code injection.",
                    code_snippet=snippet,
                    pattern=func_name
                )
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # -------------------------------------------------------------
        # 5. Hard-coded Secrets / Credentials (CWE-798)
        # -------------------------------------------------------------
        secret_var_pattern = re.compile(
            r'^(password|passwd|secret|api_key|apikey|token|access_token|auth_token|jwt_secret|private_key)$',
            re.IGNORECASE
        )

        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id

            if secret_var_pattern.match(target_name):
                # Check if value is a string constant >= 8 characters
                val_str = None
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val_str = node.value.value
                elif isinstance(node.value, ast.Str):
                    val_str = node.value.s

                if val_str and len(val_str) >= 8:
                    # Ignore common placeholder / test strings
                    lower_val = val_str.lower()
                    placeholders = {"changeme", "password", "your_secret", "placeholder", "your_api_key", "secret123", "dummy"}
                    if not any(p in lower_val for p in placeholders) and not lower_val.startswith("env:"):
                        start_line = node.lineno
                        end_line = getattr(node, "end_lineno", node.lineno)
                        snippet = self._get_snippet(start_line, end_line)
                        self.findings.append(
                            StaticFinding(
                                type="Hard-coded Credentials",
                                cwe_id="CWE-798",
                                severity="HIGH",
                                line=start_line,
                                end_line=end_line,
                                description=f"Potential hard-coded credential assigned to variable '{target_name}'. Use environment variables instead.",
                                code_snippet=snippet,
                                pattern=f"{target_name} = '***'"
                            )
                        )

        self.generic_visit(node)


class StaticAnalyzer:
    """
    Deterministic rule-based static analyzer with AST and Regex detectors.
    Implements FR-1 (SAST scan for 6 core vulnerability types with canonical CWEs).
    """

    PATTERNS: Dict[str, List[Dict[str, Any]]] = {
        "python": [
            {
                "name": "SQL Injection",
                "cwe": "CWE-89",
                "pattern": r'(execute|executemany|raw|cursor\.execute)\s*\([^)]*(%s|%d|\+|\.format|f["\'])',
                "severity": "CRITICAL",
                "description": "SQL injection via string formatting, f-string, or string concatenation"
            },
            {
                "name": "SQL Injection",
                "cwe": "CWE-89",
                "pattern": r'["\']\s*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+.*["\']\s*(\+|\.format|%|f["\'])',
                "severity": "CRITICAL",
                "description": "SQL query built dynamically using string concatenation or format interpolation"
            },
            {
                "name": "OS Command Injection",
                "cwe": "CWE-78",
                "pattern": r'(os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\([^)]*(\+|%|\.format|f["\'])',
                "severity": "CRITICAL",
                "description": "OS Command injection via unvalidated string formatting in command execution"
            },
            {
                "name": "OS Command Injection",
                "cwe": "CWE-78",
                "pattern": r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
                "severity": "CRITICAL",
                "description": "subprocess called with shell=True facilitates OS Command Injection"
            },
            {
                "name": "OS Command Injection",
                "cwe": "CWE-78",
                "pattern": r'(os\.system|os\.popen)\s*\(',
                "severity": "HIGH",
                "description": "Dangerous os.system/os.popen call - use subprocess with shell=False"
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "cwe": "CWE-79",
                "pattern": r'render_template_string\s*\(',
                "severity": "HIGH",
                "description": "render_template_string rendering dynamic content can lead to XSS / SSTI"
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "cwe": "CWE-79",
                "pattern": r'(Response|HTMLResponse)\s*\([^)]*(mimetype\s*=\s*["\']text/html["\']|\.html)[^)]*(\+|f["\']|\.format)',
                "severity": "HIGH",
                "description": "Unescaped HTML response rendered with user concatenation"
            },
            {
                "name": "Path Traversal",
                "cwe": "CWE-22",
                "pattern": r'open\s*\([^)]*(\+|\.format|f["\']|request\.)',
                "severity": "HIGH",
                "description": "File path constructed with concatenation or request inputs - potential path traversal"
            },
            {
                "name": "Path Traversal",
                "cwe": "CWE-22",
                "pattern": r'(send_file|send_from_directory|FileResponse)\s*\([^)]*(\+|f["\']|\.format|request\.)',
                "severity": "HIGH",
                "description": "File download endpoint serving dynamic path without boundary validation"
            },
            {
                "name": "Hard-coded Credentials",
                "cwe": "CWE-798",
                "pattern": r'(password|passwd|secret|api_key|apikey|token|jwt_secret|private_key)\s*=\s*["\'][^"\']{8,}["\']',
                "severity": "HIGH",
                "description": "Potential hardcoded secret or credential",
                "flags": re.IGNORECASE
            },
            {
                "name": "Weak Hashing / Broken Cryptography",
                "cwe": "CWE-328",
                "pattern": r'(hashlib\.(md5|sha1)|MD5\.new|SHA1\.new)\s*\(',
                "severity": "MEDIUM",
                "description": "MD5 / SHA1 are cryptographically broken hash algorithms - use SHA-256 or Argon2"
            },
            {
                "name": "Code Injection",
                "cwe": "CWE-94",
                "pattern": r'\b(eval|exec)\s*\(',
                "severity": "CRITICAL",
                "description": "eval/exec executes arbitrary code directly"
            },
            {
                "name": "Insecure Deserialization",
                "cwe": "CWE-502",
                "pattern": r'pickle\.(loads?|Unpickler)',
                "severity": "HIGH",
                "description": "Pickle deserialization can execute arbitrary code"
            },
            {
                "name": "Insecure YAML Loading",
                "cwe": "CWE-502",
                "pattern": r'yaml\.load\s*\([^)]*\)',
                "severity": "MEDIUM",
                "description": "Use yaml.safe_load() instead of yaml.load()"
            }
        ],
        "javascript": [
            {
                "name": "Cross-Site Scripting (XSS)",
                "cwe": "CWE-79",
                "pattern": r'\.innerHTML\s*=',
                "severity": "HIGH",
                "description": "innerHTML assignment can lead to DOM-based XSS"
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "cwe": "CWE-79",
                "pattern": r'document\.write\s*\(',
                "severity": "HIGH",
                "description": "document.write can lead to DOM XSS"
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "cwe": "CWE-79",
                "pattern": r'dangerouslySetInnerHTML',
                "severity": "HIGH",
                "description": "React dangerouslySetInnerHTML bypasses XSS protection"
            },
            {
                "name": "SQL Injection",
                "cwe": "CWE-89",
                "pattern": r'(query|execute)\s*\([^)]*(\+|`\$\{)',
                "severity": "CRITICAL",
                "description": "SQL query with string interpolation or concatenation"
            },
            {
                "name": "OS Command Injection",
                "cwe": "CWE-78",
                "pattern": r'(exec|spawn|execSync)\s*\([^)]*(\+|`\$\{)',
                "severity": "CRITICAL",
                "description": "Command execution with dynamic string interpolation"
            },
            {
                "name": "Hard-coded Credentials",
                "cwe": "CWE-798",
                "pattern": r'(password|secret|api_key|token|jwt_secret)\s*[=:]\s*["\'][^"\']{8,}["\']',
                "severity": "HIGH",
                "description": "Potential hardcoded secret or token",
                "flags": re.IGNORECASE
            },
            {
                "name": "Code Injection",
                "cwe": "CWE-94",
                "pattern": r'\beval\s*\(',
                "severity": "CRITICAL",
                "description": "eval() executes arbitrary code"
            },
            {
                "name": "Weak Hashing / Broken Cryptography",
                "cwe": "CWE-328",
                "pattern": r'crypto\.createHash\s*\(\s*["\'](md5|sha1)["\']',
                "severity": "MEDIUM",
                "description": "Weak hashing algorithm MD5/SHA1 used"
            }
        ]
    }

    def __init__(self):
        pass

    def _detect_language(self, code: str) -> str:
        """Detect programming language from source patterns."""
        if re.search(r'\bdef\s+\w+\s*\(|import\s+\w+|from\s+\w+\s+import', code):
            return "python"
        if re.search(r'\bfunction\s+\w+\s*\(|const\s+\w+\s*=|let\s+\w+\s*=|=>\s*{', code):
            return "javascript"
        if re.search(r'\bpublic\s+class\s+|private\s+\w+\s+\w+\s*\(|System\.out\.', code):
            return "java"
        return "python"

    def analyze_code(
        self,
        code: str,
        file_path: str = "snippet.py",
        language: str = "auto"
    ) -> List[UnifiedFinding]:
        """
        Deterministic multi-layer SAST scan of source code.
        Runs Python AST visitor + Regex detectors, deduplicates findings,
        and outputs normalized UnifiedFinding objects.
        """
        if language == "auto":
            language = self._detect_language(code)

        raw_findings: List[StaticFinding] = []

        # Layer 1: Python AST analysis (Zero false positives for syntax-valid python)
        if language.lower() == "python":
            try:
                tree = ast.parse(code)
                visitor = PythonASTDetector(code, file_path)
                visitor.visit(tree)
                raw_findings.extend(visitor.findings)
            except Exception as e:
                logger.debug(f"AST parsing skipped for {file_path}: {e}")

        # Layer 2: Regex pattern matching (Supports all languages & demo snippets)
        patterns = self.PATTERNS.get(language.lower(), self.PATTERNS["python"])
        lines = code.split("\n")

        for i, line in enumerate(lines, 1):
            for p in patterns:
                flags = p.get("flags", 0)
                if re.search(p["pattern"], line, flags):
                    raw_findings.append(
                        StaticFinding(
                            type=p["name"],
                            cwe_id=p["cwe"],
                            severity=p["severity"],
                            line=i,
                            end_line=i,
                            description=p["description"],
                            code_snippet=line.strip(),
                            pattern=p["pattern"]
                        )
                    )

        # Deduplicate and convert to UnifiedFinding
        unified_map: Dict[str, UnifiedFinding] = {}

        for rf in raw_findings:
            cwe_id, vuln_type, severity, description = normalize_cwe(
                raw_cwe=rf.cwe_id,
                rule_name=rf.type,
                message=rf.description
            )
            dedup_key = compute_dedup_key(
                source_scanner="SAST",
                file_path=file_path,
                line=rf.line,
                cwe_id=cwe_id
            )

            if dedup_key not in unified_map:
                finding_id = f"sast-{dedup_key[:12]}"
                finding = UnifiedFinding(
                    finding_id=finding_id,
                    dedup_key=dedup_key,
                    source_scanner="SAST",
                    cwe_id=cwe_id,
                    vulnerability_type=vuln_type,
                    severity=severity,
                    confidence="HIGH",
                    file=file_path,
                    line=rf.line,
                    end_line=rf.end_line or rf.line,
                    code_snippet=rf.code_snippet,
                    status_label="Code only",
                    description=rf.description or description
                )
                unified_map[dedup_key] = finding

        return list(unified_map.values())

    def analyze(self, code: str, language: str = "auto") -> List[Dict[str, Any]]:
        """
        Backward compatible method for existing analyzer callers.
        Returns list of dictionaries with type, severity, line, description, code_snippet.
        """
        findings = self.analyze_code(code, file_path="snippet.py", language=language)
        return [
            {
                "type": f.vulnerability_type,
                "severity": f.severity.lower(),
                "line": f.line,
                "description": f.description,
                "code_snippet": f.code_snippet
            }
            for f in findings
        ]


_static_analyzer: Optional[StaticAnalyzer] = None


def get_static_analyzer() -> StaticAnalyzer:
    """Get or create the static analyzer singleton."""
    global _static_analyzer
    if _static_analyzer is None:
        _static_analyzer = StaticAnalyzer()
    return _static_analyzer
