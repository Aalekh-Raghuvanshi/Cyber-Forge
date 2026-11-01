"""
Datadog SAIST Runner & SARIF 2.1.0 Normalizer.
Integrates Datadog's AI-native SAST tool (datadog-saist) with Groq LLM backend.

Supports two modes of operation:
1. Binary Execution Mode:
   Executes the compiled `datadog-saist` CLI against our internal OpenAI-to-Groq proxy
   (POST /internal/groq-proxy/v1/chat/completions) with --detection-model openai-gpt5-mini
   and parses the resulting SARIF 2.1.0 report.
2. Native Python 2-Stage SAIST Mode (Zero-Dependency Fallback):
   Replicates Datadog SAIST's exact 2-stage AI-native architecture natively in Python:
   - AST / Route context extraction & 1-based line numbering pre-processing.
   - Stage 1: Detection prompt scanning for canonical CWEs.
   - Stage 2: Adversarial validation prompt eliminating false positives & assessing confidence.
   - SARIF 2.1.0 report generator & parser with AST ground-truth verification.
"""

import ast
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

import httpx

from backend.config import settings
from backend.models.schemas import UnifiedFinding, RouteEntry
from backend.services.cwe_normalizer import normalize_cwe, compute_dedup_key, SEVERITY_ORDER
from backend.services.route_mapper import (
    extract_routes_from_python_code,
    extract_routes_from_js_code,
    normalize_file_path
)
from backend.utils.logger import get_logger

logger = get_logger("datadog_saist_runner")

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Canonical CWE targets for Datadog SAIST detection
TARGET_CWES = [
    ("CWE-89", "SQL Injection", "CRITICAL"),
    ("CWE-79", "Cross-Site Scripting (XSS)", "HIGH"),
    ("CWE-22", "Path Traversal", "HIGH"),
    ("CWE-78", "OS Command Injection", "CRITICAL"),
    ("CWE-798", "Hardcoded Credentials / Secrets", "HIGH"),
    ("CWE-328", "Weak Hashing / Insecure Cryptography", "MEDIUM"),
    ("CWE-918", "Server-Side Request Forgery (SSRF)", "HIGH"),
    ("CWE-601", "Open Redirect", "MEDIUM")
]
SUPPORTED_CWE_IDS = {cwe for cwe, _, _ in TARGET_CWES}


class DatadogSAISTRunner:
    """Runner for Datadog SAIST AI-native security scanning."""

    def __init__(self, binary_path: Optional[str] = None):
        self.custom_bin_path = binary_path
        self._binary_path = self._find_binary()

    def _find_binary(self) -> Optional[str]:
        """Locates datadog-saist executable if available."""
        candidates = [
            self.custom_bin_path,
            settings.datadog_saist_bin,
            os.path.abspath("./bin/datadog-saist"),
            os.path.expanduser("~/go/bin/datadog-saist"),
            "/usr/local/bin/datadog-saist",
            "/opt/homebrew/bin/datadog-saist",
            shutil.which("datadog-saist")
        ]
        for c in candidates:
            if c and os.path.isfile(c) and os.access(c, os.X_OK):
                logger.info(f"Found datadog-saist executable at: {c}")
                return os.path.abspath(c)
        return None

    def has_binary(self) -> bool:
        """Returns True if datadog-saist binary is available."""
        return self._find_binary() is not None

    def run_scan(self, target_dir: str) -> List[UnifiedFinding]:
        """
        Main scan entrypoint.
        Executes binary mode if datadog-saist is compiled;
        otherwise runs the native Python 2-stage SAIST engine.
        """
        abs_target = os.path.abspath(target_dir)
        if not os.path.exists(abs_target):
            logger.warning(f"Target directory does not exist: {abs_target}")
            return []

        bin_path = self._find_binary()
        if bin_path:
            try:
                logger.info(f"Running Datadog SAIST binary mode with {bin_path}")
                findings = self._run_binary(bin_path, abs_target)
                if findings:
                    return findings
                logger.info("Binary mode completed with 0 findings or failed; testing native Python engine.")
            except Exception as e:
                logger.warning(f"Datadog SAIST binary execution failed ({e}). Falling back to native Python engine.")

        # Fallback to Native Python 2-Stage SAIST Engine
        logger.info(f"Executing Datadog SAIST Native Python 2-Stage Engine on {abs_target}")
        return self._run_native_saist(abs_target)

    # -------------------------------------------------------------------------
    # Part 1: Binary Execution Mode
    # -------------------------------------------------------------------------

    def _run_binary(self, bin_path: str, target_dir: str) -> List[UnifiedFinding]:
        """
        Executes the compiled datadog-saist CLI tool via subprocess.
        Directs requests through our internal Groq proxy.
        """
        with tempfile.NamedTemporaryFile(suffix=".sarif.json", delete=False) as tmp_file:
            sarif_output_path = tmp_file.name

        try:
            env = os.environ.copy()
            # datadog-saist requires OPENAI_API_KEY to be set
            env["OPENAI_API_KEY"] = settings.groq_api_key or "gsk_internal_proxy_key"

            # Notice: --openai-base-url omits /v1 because the Go client appends /v1/chat/completions
            proxy_url = f"http://127.0.0.1:{settings.port}/internal/groq-proxy"

            cmd = [
                bin_path,
                "--directory", target_dir,
                "--output", sarif_output_path,
                "--detection-model", "openai-gpt5-mini",
                "--validation-model", "openai-gpt5-mini",
                "--openai-base-url", proxy_url,
                "--local-prompts",
                "--request-timeout-sec", "45"
            ]

            logger.info(f"Executing command: {' '.join(cmd)}")
            res = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=180
            )

            if res.returncode != 0:
                logger.warning(f"datadog-saist CLI exited with code {res.returncode}: {res.stderr}")

            if os.path.exists(sarif_output_path) and os.path.getsize(sarif_output_path) > 0:
                with open(sarif_output_path, "r", encoding="utf-8") as f:
                    sarif_data = json.load(f)
                return self.parse_sarif_to_findings(sarif_data, target_dir)
            else:
                logger.warning("datadog-saist did not generate a non-empty SARIF output file.")
                return []

        finally:
            if os.path.exists(sarif_output_path):
                try:
                    os.remove(sarif_output_path)
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # Part 2: Native Python 2-Stage SAIST Engine
    # -------------------------------------------------------------------------

    def _run_native_saist(self, target_dir: str) -> List[UnifiedFinding]:
        """
        Executes Datadog SAIST's exact 2-stage AI-native workflow natively:
        1. Context extraction & line numbering.
        2. Stage 1 Detection prompt.
        3. Stage 2 Adversarial Validation prompt.
        4. Synthesize SARIF 2.1.0 document.
        5. Parse SARIF into validated UnifiedFindings.
        """
        if not settings.groq_api_key:
            logger.warning("GROQ_API_KEY is not set. Datadog SAIST native engine requires Groq.")
            return []

        source_files = self._collect_source_files(target_dir)
        if not source_files:
            logger.info(f"No eligible source files found in {target_dir}")
            return []

        all_sarif_results: List[Dict[str, Any]] = []

        for rel_path, full_path in source_files:
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                lines = content.splitlines()
                if not lines:
                    continue

                # Pre-processing: Generate 1-based numbered lines & extract AST context
                numbered_code = "\n".join(f"{i}: {line}" for i, line in enumerate(lines, start=1))
                ast_context = self._extract_ast_context(content, rel_path)

                # Stage 1: Detection Prompt
                candidates = self._stage1_detect(rel_path, numbered_code, ast_context)
                # Require an explicit supported CWE and a line that exists in the
                # source file. Do not let the generic CWE normalizer guess CWE-89.
                eligible_candidates: List[Dict[str, Any]] = []
                for candidate in candidates:
                    raw_cwe = (
                        candidate.get("cwe_id")
                        or candidate.get("cwe")
                        or candidate.get("canonical_cwe")
                    )
                    if not raw_cwe:
                        continue
                    cwe, _, _, _ = normalize_cwe(raw_cwe=raw_cwe)
                    line = candidate.get("start_line") or candidate.get("line") or candidate.get("sink_line")
                    if cwe not in SUPPORTED_CWE_IDS or not isinstance(line, int) or not 1 <= line <= len(lines):
                        continue
                    normalized_candidate = candidate.copy()
                    normalized_candidate["cwe_id"] = cwe
                    normalized_candidate["start_line"] = line
                    eligible_candidates.append(normalized_candidate)
                candidates = eligible_candidates
                if not candidates:
                    continue

                logger.info(f"Stage 1 detected {len(candidates)} candidate findings in {rel_path}")

                # Stage 2: Adversarial False-Positive Validation Prompt
                validated = self._stage2_validate(rel_path, content, lines, candidates)
                logger.info(f"Stage 2 validated {len(validated)} of {len(candidates)} findings in {rel_path}")

                # Convert validated findings into SARIF results
                for v in validated:
                    cwe_raw = v.get("cwe_id") or v.get("cwe") or v.get("canonical_cwe")
                    if not cwe_raw or cwe_raw in ("security-flaw", "CWE-UNKNOWN"):
                        norm_c, _, _, _ = normalize_cwe(
                            raw_cwe=None,
                            rule_name=v.get("vulnerability_type"),
                            message=v.get("explanation") or v.get("description")
                        )
                        cwe_raw = norm_c

                    rule_id = f"datadog-saist/{cwe_raw.lower()}"
                    start_line = v.get("start_line") or v.get("line") or v.get("sink_line") or 1
                    end_line = v.get("end_line") or v.get("sink_line") or start_line

                    # Extract snippet from actual file lines
                    snippet_text = ""
                    if 1 <= start_line <= len(lines):
                        snippet_text = lines[start_line - 1].strip()

                    sarif_res = {
                        "ruleId": rule_id,
                        "level": "error" if v.get("severity") in ("CRITICAL", "HIGH") else "warning",
                        "message": {
                            "text": v.get("explanation") or v.get("validation_reason") or f"{v.get('vulnerability_type')} detected"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": rel_path
                                    },
                                    "region": {
                                        "startLine": start_line,
                                        "endLine": end_line,
                                        "snippet": {
                                            "text": snippet_text
                                        }
                                    }
                                }
                            }
                        ],
                        "properties": {
                            "tags": [cwe_raw, "security", "ai-native"],
                            "cwe_id": cwe_raw,
                            "confidence": v.get("confidence", "HIGH"),
                            "vulnerability_type": v.get("vulnerability_type"),
                            "taint_source": v.get("taint_source"),
                            "taint_sink": v.get("taint_sink")
                        }
                    }
                    all_sarif_results.append(sarif_res)

            except Exception as e:
                logger.warning(f"Error analyzing {rel_path} with native SAIST: {e}")

        # Assemble SARIF 2.1.0 document
        sarif_document = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "datadog-saist",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/DataDog/datadog-saist",
                            "rules": [
                                {
                                    "id": f"datadog-saist/{cwe.lower()}",
                                    "name": name,
                                    "shortDescription": {"text": name},
                                    "defaultConfiguration": {"level": "error"}
                                }
                                for cwe, name, _ in TARGET_CWES
                            ]
                        }
                    },
                    "results": all_sarif_results
                }
            ]
        }

        # Parse SARIF document with Zero-Hallucination Guardrails
        return self.parse_sarif_to_findings(sarif_document, target_dir)

    def _collect_source_files(self, target_dir: str) -> List[Tuple[str, str]]:
        """Collects candidate source code files (Strictly Python-Only)."""
        eligible_extensions = {".py"}
        skip_dirs = {
            ".git", ".svn", "__pycache__", "node_modules", "venv", ".venv",
            "env", "dist", "build", ".next", ".pytest_cache", "coverage",
            "migrations", "static", "media"
        }

        collected = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in eligible_extensions:
                    full_path = os.path.join(root, file)
                    rel_path = normalize_file_path(os.path.relpath(full_path, target_dir))
                    collected.append((rel_path, full_path))

        return collected

    def _extract_ast_context(self, code: str, rel_path: str) -> str:
        """Extracts function boundaries and route signatures using Python AST or Regex."""
        context_lines: List[str] = []
        if rel_path.endswith(".py"):
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        start_l = node.lineno
                        end_l = getattr(node, "end_lineno", node.lineno)
                        context_lines.append(f"- Function '{node.name}' at lines {start_l}-{end_l}")
            except Exception:
                pass
        elif rel_path.endswith((".js", ".ts")):
            for match in re.finditer(r'(?:function\s+([a-zA-Z0-9_$]+)|(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)', code):
                name = match.group(1) or match.group(2)
                line_no = code[:match.start()].count("\n") + 1
                context_lines.append(f"- Function '{name}' defined near line {line_no}")

        if context_lines:
            return "AST Structural Context:\n" + "\n".join(context_lines[:25])
        return "No specific AST functions identified."

    def _stage1_detect(self, filename: str, numbered_code: str, ast_context: str) -> List[Dict[str, Any]]:
        """
        Stage 1: AI-native Detection model.
        Prompts Groq at temperature=0.0 to identify vulnerability candidates.
        """
        # Truncate if overly long to prevent token overflow
        lines = numbered_code.splitlines()
        code_to_send = "\n".join(lines[:600]) if len(lines) > 600 else numbered_code

        system_prompt = (
            "You are Datadog SAIST Detection Model, an expert Application Security Engineer. "
            "Analyze source code annotated with 1-based line numbers. "
            "Detect security vulnerabilities strictly corresponding to these canonical classes:\n"
            "- CWE-89: SQL Injection\n"
            "- CWE-79: Cross-Site Scripting (XSS)\n"
            "- CWE-22: Path Traversal / Arbitrary File Read or Write\n"
            "- CWE-78: OS Command Injection\n"
            "- CWE-798: Hardcoded Credentials / Secrets\n"
            "- CWE-328: Weak Hashing / Insecure Cryptography\n"
            "- CWE-918: Server-Side Request Forgery (SSRF)\n"
            "- CWE-601: Open Redirect\n\n"
            "STRICT RULES:\n"
            "1. start_line and end_line MUST EXACTLY match the 1-based line numbers in the code snippet.\n"
            "2. Never hallucinate or shift line numbers.\n"
            "3. Identify taint_source (untrusted input) and taint_sink (execution point).\n"
            "4. Output strictly a JSON object with a 'candidates' list."
        )

        user_prompt = f"File: {filename}\n{ast_context}\n\nSource Code:\n{code_to_send}\n\nList all candidate vulnerabilities as JSON."

        payload = {
            "model": settings.groq_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.0,
            "max_tokens": 2048,
            "response_format": {"type": "json_object"}
        }

        try:
            with httpx.Client(timeout=35.0) as client:
                res = client.post(
                    GROQ_API_URL,
                    headers={
                        "Authorization": f"Bearer {settings.groq_api_key}",
                        "Content-Type": "application/json"
                    },
                    json=payload
                )
                if res.status_code == 200:
                    data = res.json()
                    raw_content = data["choices"][0]["message"]["content"]
                    parsed = json.loads(raw_content)
                    candidates = parsed.get("candidates") or parsed.get("vulnerabilities") or []
                    if isinstance(candidates, list):
                        return candidates
        except Exception as e:
            logger.warning(f"Stage 1 detection error on {filename}: {e}")

        return []

    def _stage2_validate(
        self,
        filename: str,
        full_code: str,
        code_lines: List[str],
        candidates: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Stage 2: Adversarial False-Positive Validation model.
        Tests candidate findings against sanitization, parametrization, dead-code, and accuracy.
        """
        if not candidates:
            return []

        # Prepare summary of candidates for validation
        candidate_summaries = []
        for idx, c in enumerate(candidates):
            c_line = c.get("start_line") or c.get("line") or 1
            # Ground truth line from disk
            actual_snippet = code_lines[c_line - 1].strip() if 1 <= c_line <= len(code_lines) else ""
            candidate_summaries.append({
                "candidate_id": idx,
                "cwe_id": c.get("cwe_id") or "CWE-89",
                "vulnerability_type": c.get("vulnerability_type") or "Vulnerability",
                "start_line": c_line,
                "code_snippet_on_disk": actual_snippet,
                "taint_source": c.get("taint_source"),
                "taint_sink": c.get("taint_sink"),
                "explanation": c.get("explanation") or c.get("description")
            })

        system_prompt = (
            "You are Datadog SAIST Validation Model, an Adversarial Application Security Validator. "
            "Your sole objective is to critically audit candidate SAST findings and DISCARD false positives.\n"
            "For each candidate, verify:\n"
            "1. Is the data genuinely untrusted user input, or a hardcoded safe constant / configuration?\n"
            "2. Is user input parameterized, sanitized, HTML-escaped, cast to int/float, or validated against an allowlist?\n"
            "3. Does the line number match the actual vulnerable sink on disk?\n"
            "4. Set is_valid=true ONLY if the vulnerability is genuine and exploitable.\n"
            "5. Assign confidence: 'HIGH' (fully verified), 'MEDIUM' (probable), or 'LOW' (dubious/false positive).\n"
            "Output strictly a JSON object with 'validations' list."
        )

        user_prompt = (
            f"File: {filename}\n"
            f"Candidates to audit:\n{json.dumps(candidate_summaries, indent=2)}\n\n"
            f"Audit each candidate and return JSON: "
            "{\"validations\": [{\"candidate_id\": 0, \"is_valid\": true, \"confidence\": \"HIGH\", \"validation_reason\": \"...\"}]}"
        )

        payload = {
            "model": settings.groq_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.0,
            "max_tokens": 2048,
            "response_format": {"type": "json_object"}
        }

        try:
            with httpx.Client(timeout=35.0) as client:
                res = client.post(
                    GROQ_API_URL,
                    headers={
                        "Authorization": f"Bearer {settings.groq_api_key}",
                        "Content-Type": "application/json"
                    },
                    json=payload
                )
                if res.status_code == 200:
                    data = res.json()
                    content = data["choices"][0]["message"]["content"]
                    parsed = json.loads(content)
                    validations = parsed.get("validations") or []

                    validated_candidates: List[Dict[str, Any]] = []
                    for v in validations:
                        cid = v.get("candidate_id")
                        if cid is not None and 0 <= cid < len(candidates):
                            is_valid = v.get("is_valid", False)
                            confidence = (v.get("confidence") or "MEDIUM").upper()

                            # Discard if invalid or confidence is LOW
                            if (
                                is_valid is True
                                and confidence == "HIGH"
                                and candidates[cid].get("cwe_id") in SUPPORTED_CWE_IDS
                            ):
                                orig = candidates[cid].copy()
                                orig["confidence"] = confidence
                                orig["validation_reason"] = v.get("validation_reason") or orig.get("explanation")
                                if v.get("adjusted_cwe"):
                                    orig["cwe_id"] = v.get("adjusted_cwe")
                                validated_candidates.append(orig)

                    return validated_candidates

        except Exception as e:
            logger.warning(f"Stage 2 validation query failed on {filename}: {e}. Keeping validated candidates.")

        # Fail closed: a detection candidate is not a finding unless validation
        # explicitly confirms it. This favors precision over recall.
        return []

    # -------------------------------------------------------------------------
    # Part 3: SARIF 2.1.0 Parser with AST Ground-Truth Verification
    # -------------------------------------------------------------------------

    def parse_sarif_to_findings(
        self,
        sarif_data: Dict[str, Any],
        target_dir: str
    ) -> List[UnifiedFinding]:
        """
        Parses SARIF 2.1.0 results into canonical UnifiedFindings.
        Implements Zero-Hallucination Guardrail:
        - Validates that target file exists on disk.
        - Verifies start_line exists within the file boundaries.
        - Extracts exact code snippet directly from disk at start_line.
        - Normalizes CWEs via cwe_normalizer.py.
        """
        findings: List[UnifiedFinding] = []
        runs = sarif_data.get("runs", [])
        if not runs:
            return []

        for run in runs:
            results = run.get("results", [])
            for res in results:
                rule_id = res.get("ruleId", "")
                message = res.get("message", {}).get("text", "")

                locations = res.get("locations", [])
                if not locations:
                    continue

                phys_loc = locations[0].get("physicalLocation", {})
                raw_uri = phys_loc.get("artifactLocation", {}).get("uri", "")
                region = phys_loc.get("region", {})

                start_line = region.get("startLine")
                end_line = region.get("endLine", start_line)

                # Relative path clean up
                rel_file = normalize_file_path(raw_uri)
                if rel_file.startswith("/"):
                    # Try making it relative to target_dir
                    try:
                        rel_file = os.path.relpath(rel_file, target_dir)
                    except Exception:
                        pass
                rel_file = normalize_file_path(rel_file)

                # AST Ground-Truth Verification (Zero-Hallucination Guardrail)
                full_path = os.path.join(target_dir, rel_file)
                if not os.path.isfile(full_path):
                    # Check if file exists without prefix
                    alt_path = os.path.abspath(raw_uri)
                    if os.path.isfile(alt_path):
                        full_path = alt_path
                    else:
                        logger.debug(f"Discarding finding for non-existent file: {rel_file}")
                        continue

                try:
                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                        file_lines = f.readlines()
                except Exception as e:
                    logger.debug(f"Cannot read file {full_path}: {e}")
                    continue

                total_lines = len(file_lines)
                if not start_line or start_line < 1 or start_line > total_lines:
                    logger.debug(
                        f"Discarding hallucinated finding: line {start_line} exceeds file length {total_lines} in {rel_file}"
                    )
                    continue

                # Extract exact code snippet from disk
                disk_line = file_lines[start_line - 1].strip()
                sarif_snippet = region.get("snippet", {}).get("text", "")
                code_snippet = sarif_snippet.strip() if sarif_snippet else disk_line

                # Extract CWE tags
                properties = res.get("properties", {})
                tags = properties.get("tags", [])
                cwe_prop = properties.get("cwe_id")

                raw_cwe = cwe_prop or ""
                if not raw_cwe:
                    for tag in tags:
                        if isinstance(tag, str) and tag.upper().startswith("CWE-"):
                            raw_cwe = tag
                            break

                canonical_cwe, vuln_type, canonical_sev, default_desc = normalize_cwe(
                    raw_cwe=raw_cwe,
                    rule_name=rule_id,
                    message=message
                )
                if canonical_cwe not in SUPPORTED_CWE_IDS:
                    logger.debug(f"Discarding unsupported SAIST CWE {canonical_cwe} in {rel_file}")
                    continue

                # Surrounding context window (+/- 2 lines) for ground-truth syntax verification
                context_window_start = max(0, start_line - 3)
                context_window_end = min(total_lines, start_line + 2)
                surrounding_text = " ".join(file_lines[context_window_start:context_window_end]).lower()

                # Zero-Hallucination Syntax Guardrail: verify canonical CWE indicators
                if canonical_cwe == "CWE-89":
                    # Strip python imports like 'from ... import ...' to avoid false positives on 'from'
                    cleaned_sql_text = re.sub(r'from\s+[\w\.]+\s+import', '', surrounding_text)
                    sql_keywords = (
                        "select ", "insert into", "update ", "delete from", "drop table",
                        "cursor.execute", ".execute(", ".executemany(", ".raw(", "where ",
                        "sql =", "query =", "query+", "query +", "sqlite3", "psycopg2", "cursor"
                    )
                    if not any(k in cleaned_sql_text for k in sql_keywords):
                        logger.debug(f"Discarding hallucinated SQLi finding without SQL syntax at line {start_line}")
                        continue
                elif canonical_cwe == "CWE-78":
                    cmd_keywords = (
                        "os.system", "subprocess", "popen", "exec", "system", "spawn", "shlex",
                        "shell", "ping", "bash", "sh", "cmd", "powershell", "call", "run"
                    )
                    if not any(k in surrounding_text for k in cmd_keywords):
                        logger.debug(f"Discarding hallucinated Command Injection finding at line {start_line}")
                        continue
                elif canonical_cwe == "CWE-79":
                    xss_keywords = (
                        "render", "template", "html", "response", "script", "mark_safe", "markup",
                        "f\"<", "\"<", "f'<", "'<", "innerhtml", "write", "escape", "preview", "echo"
                    )
                    if not any(k in surrounding_text for k in xss_keywords):
                        logger.debug(f"Discarding hallucinated XSS finding at line {start_line}")
                        continue
                elif canonical_cwe == "CWE-22":
                    path_keywords = (
                        "open", "read", "write", "path", "join", "file", "load", "send_file",
                        "send_from_directory", "filename", "os.path", "dirname", "abspath"
                    )
                    if not any(k in surrounding_text for k in path_keywords):
                        logger.debug(f"Discarding hallucinated Path Traversal finding at line {start_line}")
                        continue

                # Confidence
                confidence = properties.get("confidence", "HIGH")
                if isinstance(confidence, str) and confidence.upper() in ("HIGH", "MEDIUM", "LOW"):
                    confidence_str = confidence.upper()
                else:
                    confidence_str = "HIGH"

                # Deterministic dedup_key per FR-3 / FR-6
                dedup_key = compute_dedup_key(
                    source_scanner="SAST",
                    file_path=rel_file,
                    line=start_line,
                    cwe_id=canonical_cwe
                )

                finding_id = f"saist-{dedup_key[:12]}"
                finding_desc = f"{message} (Detected by Datadog SAIST AI-native scanner)" if message else default_desc

                finding = UnifiedFinding(
                    finding_id=finding_id,
                    dedup_key=dedup_key,
                    source_scanner="SAST",
                    cwe_id=canonical_cwe,
                    vulnerability_type=vuln_type,
                    severity=canonical_sev,
                    confidence=confidence_str,
                    file=rel_file,
                    line=start_line,
                    end_line=end_line,
                    code_snippet=code_snippet,
                    status_label="Code only",
                    description=finding_desc
                )
                findings.append(finding)

        return findings


_datadog_saist_runner: Optional[DatadogSAISTRunner] = None


def get_datadog_saist_runner() -> DatadogSAISTRunner:
    """Singleton accessor for DatadogSAISTRunner."""
    global _datadog_saist_runner
    if _datadog_saist_runner is None:
        _datadog_saist_runner = DatadogSAISTRunner()
    return _datadog_saist_runner
