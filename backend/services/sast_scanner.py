"""
SAST Scanner Service.
Fulfills FR-1, FR-3, and FR-4:
- Deterministic SAST detection via Semgrep CLI + Static AST/Regex Fallback.
- 6 Core vulnerability types mapped to canonical CWEs.
- Deduplication via deterministic dedup_key (SHA256 of scanner+file+line+cwe).
- Route map extraction and route enrichment on findings.
- Zero-Hallucination rule: Zero LLM dependency for detection/line numbers/CWEs.
"""

import os
import json
import shutil
import subprocess
import tempfile
from typing import List, Dict, Any, Optional, Tuple

from backend.models.schemas import UnifiedFinding, RouteEntry, SASTScanResponse
from backend.services.cwe_normalizer import normalize_cwe, compute_dedup_key, SEVERITY_ORDER
from backend.services.route_mapper import (
    extract_routes_from_folder,
    extract_routes_from_python_code,
    extract_routes_from_js_code,
    enrich_finding_with_route,
    normalize_file_path
)
from backend.services.static_analyzer import get_static_analyzer
from backend.utils.logger import get_logger

logger = get_logger("sast_scanner")


class SASTScannerService:
    """Orchestrates deterministic Semgrep CLI and AST/Regex SAST analysis."""

    def __init__(self):
        self.static_analyzer = get_static_analyzer()
        self.semgrep_bin = shutil.which("semgrep")

    def _find_semgrep_binary(self) -> Optional[str]:
        """Check for semgrep binary in PATH or common brew/pip install locations."""
        if self.semgrep_bin and os.path.isfile(self.semgrep_bin) and os.access(self.semgrep_bin, os.X_OK):
            return self.semgrep_bin

        candidates = [
            "/opt/homebrew/bin/semgrep",
            "/usr/local/bin/semgrep",
            os.path.expanduser("~/.local/bin/semgrep")
        ]
        for c in candidates:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                self.semgrep_bin = c
                return c
        return None

    def _run_semgrep_cli(self, target_dir: str) -> List[UnifiedFinding]:
        """
        Executes Semgrep CLI: semgrep scan --config=auto --json.
        Gracefully handles offline mode, exit codes, and fallback.
        """
        semgrep_path = self._find_semgrep_binary()
        if not semgrep_path:
            logger.info("Semgrep CLI not detected. Using deterministic AST/Regex fallback scanner.")
            return []

        cmd = [
            semgrep_path,
            "scan",
            "--config=auto",
            "--json",
            target_dir
        ]

        logger.info(f"Running Semgrep CLI scan on {target_dir}")
        try:
            # Semgrep may exit with code 0 (no findings), 1, or 2 (findings/errors)
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            raw_stdout = res.stdout.strip()

            # Locate JSON payload in stdout
            json_start = raw_stdout.find("{")
            json_end = raw_stdout.rfind("}")
            if json_start == -1 or json_end == -1:
                logger.warning("Semgrep did not return valid JSON output; falling back to AST/Regex.")
                return []

            data = json.loads(raw_stdout[json_start:json_end + 1])
            raw_results = data.get("results", [])
            logger.info(f"Semgrep CLI returned {len(raw_results)} raw results")

            findings: List[UnifiedFinding] = []
            for item in raw_results:
                raw_path = item.get("path", "")
                # Normalize path relative to target_dir
                try:
                    rel_path = os.path.relpath(raw_path, target_dir)
                except Exception:
                    rel_path = raw_path
                rel_path = normalize_file_path(rel_path)

                start = item.get("start", {})
                end = item.get("end", {})
                line = start.get("line", 1)
                end_line = end.get("line", line)

                extra = item.get("extra", {})
                message = extra.get("message", "")
                code_snippet = extra.get("lines", "").strip()

                # If Semgrep OSS returns 'requires login' for lines, extract directly from source
                if (not code_snippet or code_snippet == "requires login") and os.path.isfile(raw_path):
                    try:
                        with open(raw_path, "r", encoding="utf-8", errors="replace") as sf:
                            sf_lines = sf.readlines()
                            if 1 <= line <= len(sf_lines):
                                end_idx = min(len(sf_lines), max(line, end_line))
                                code_snippet = "".join(sf_lines[line - 1:end_idx]).strip()
                    except Exception:
                        pass

                metadata = extra.get("metadata", {})
                raw_cwe = metadata.get("cwe")
                check_id = item.get("check_id", "")

                cwe_id, vuln_type, severity, default_desc = normalize_cwe(
                    raw_cwe=raw_cwe,
                    rule_name=check_id,
                    message=message
                )

                dedup_key = compute_dedup_key(
                    source_scanner="SAST",
                    file_path=rel_path,
                    line=line,
                    cwe_id=cwe_id
                )
                finding_id = f"sast-{dedup_key[:12]}"

                findings.append(
                    UnifiedFinding(
                        finding_id=finding_id,
                        dedup_key=dedup_key,
                        source_scanner="SAST",
                        cwe_id=cwe_id,
                        vulnerability_type=vuln_type,
                        severity=severity,
                        confidence="HIGH",
                        file=rel_path,
                        line=line,
                        end_line=end_line,
                        code_snippet=code_snippet,
                        status_label="Code only",
                        description=message or default_desc
                    )
                )

            return findings

        except subprocess.TimeoutExpired:
            logger.warning("Semgrep scan timed out. Proceeding with deterministic static fallback.")
            return []
        except Exception as e:
            logger.warning(f"Semgrep execution failed ({e}). Proceeding with deterministic static fallback.")
            return []

    def _run_static_fallback(self, target_dir: str) -> List[UnifiedFinding]:
        """
        Scans all files in target_dir using the deterministic AST & Regex static analyzer.
        Fulfills FR-1 offline support and zero-hallucination requirement.
        """
        findings: List[UnifiedFinding] = []
        skip_dirs = {
            ".git", ".svn", "__pycache__", "node_modules", "venv", ".venv",
            "env", "dist", "build", ".next", ".pytest_cache"
        }

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in (".py", ".js", ".ts", ".java", ".go", ".php"):
                    full_path = os.path.join(root, file)
                    rel_path = normalize_file_path(os.path.relpath(full_path, target_dir))

                    try:
                        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                        file_findings = self.static_analyzer.analyze_code(
                            code=content,
                            file_path=rel_path
                        )
                        findings.extend(file_findings)
                    except Exception as e:
                        logger.warning(f"Static fallback scan error on {full_path}: {e}")

        return findings

    def scan_folder(
        self,
        folder_path: str,
        generate_fixes: bool = False
    ) -> SASTScanResponse:
        """
        Executes complete Phase 1 SAST scan workflow:
        1. Extract AST Route Map (FR-4).
        2. Run Semgrep CLI (Primary deterministic scanner).
        3. Run AST & Regex static fallback scanner (Deterministic offline scanner).
        4. Deduplicate findings via deterministic SHA256 dedup_key (FR-3 / FR-6).
        5. Enrich each finding with its enclosing Route Map entry (FR-4).
        6. Return unified findings and route map.
        """
        abs_folder = os.path.abspath(folder_path)
        if not os.path.exists(abs_folder):
            return SASTScanResponse(
                success=False,
                total_findings=0,
                findings=[],
                route_map=[],
                scanned_files_count=0,
                error=f"Source folder not found: {folder_path}"
            )

        logger.info(f"Starting SAST scan on {abs_folder}")

        # 1. Extract Route Map (FR-4)
        routes: List[RouteEntry] = extract_routes_from_folder(abs_folder)
        logger.info(f"Extracted {len(routes)} routes from {abs_folder}")

        # 2. Run Semgrep CLI
        semgrep_findings = self._run_semgrep_cli(abs_folder)

        # 3. Run Static AST/Regex Fallback
        static_findings = self._run_static_fallback(abs_folder)

        # 4. Deterministic Deduplication (FR-3 & FR-6 preparation)
        # Using hash of scanner_type + file + line + cwe_id
        unified_findings_map: Dict[str, UnifiedFinding] = {}

        # First add Semgrep findings
        for f in semgrep_findings:
            unified_findings_map[f.dedup_key] = f

        # Merge Static Analyzer findings (merge duplicates on same file:line:cwe)
        for f in static_findings:
            if f.dedup_key not in unified_findings_map:
                unified_findings_map[f.dedup_key] = f
            else:
                existing = unified_findings_map[f.dedup_key]
                # If existing finding lacks snippet or description, enrich it
                if not existing.code_snippet and f.code_snippet:
                    existing.code_snippet = f.code_snippet
                if not existing.description and f.description:
                    existing.description = f.description

        # 5. Enrich findings with Enclosing Route (FR-4)
        # If finding.file == route.file and route.start_line <= finding.line <= route.end_line
        final_findings: List[UnifiedFinding] = []
        for finding in unified_findings_map.values():
            enriched = enrich_finding_with_route(finding, routes)
            final_findings.append(enriched)

        # Sort findings: Highest severity first, then by file, line
        final_findings.sort(
            key=lambda f: (-SEVERITY_ORDER.get(f.severity.upper(), 0), f.file or "", f.line or 0)
        )

        # Count scanned files
        scanned_count = 0
        skip_dirs = {".git", ".svn", "__pycache__", "node_modules", "venv", ".venv", "env", "dist", "build"}
        for root, dirs, files in os.walk(abs_folder):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in (".py", ".js", ".ts", ".java", ".go", ".php", ".html"):
                    scanned_count += 1

        logger.info(f"SAST scan completed: {len(final_findings)} findings across {scanned_count} files.")

        return SASTScanResponse(
            success=True,
            total_findings=len(final_findings),
            findings=final_findings,
            route_map=routes,
            scanned_files_count=scanned_count,
            error=None
        )

    def scan_files(
        self,
        files: List[Dict[str, str]],
        generate_fixes: bool = False
    ) -> SASTScanResponse:
        """
        Scans a list of in-memory files (e.g. from file upload or API payload).
        Writes them to a secure temporary directory, executes scan_folder, and cleans up.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            for item in files:
                rel_path = item.get("filename") or item.get("filepath") or "file.py"
                rel_path = normalize_file_path(rel_path)
                content = item.get("content", "")

                target_file_path = os.path.join(temp_dir, rel_path)
                os.makedirs(os.path.dirname(target_file_path), exist_ok=True)
                with open(target_file_path, "w", encoding="utf-8") as f:
                    f.write(content)

            return self.scan_folder(temp_dir, generate_fixes=generate_fixes)


_sast_scanner: Optional[SASTScannerService] = None


def get_sast_scanner_service() -> SASTScannerService:
    """Singleton provider for SASTScannerService."""
    global _sast_scanner
    if _sast_scanner is None:
        _sast_scanner = SASTScannerService()
    return _sast_scanner
