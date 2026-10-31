"""
SQLite Persistence Layer for Scans and Deduplicated Issues.
Fulfills FR-6 and FR-10:
- Idempotent storage with SQLite ON CONFLICT(issue_hash) DO UPDATE.
- Running a scan twice updates existing findings instead of creating duplicate records.
- Sequential issue ID assignment (1, 2, ...) enabling GET /issues/7.
- Strict FR-9 priority ordering retrieval.
"""

import os
import json
import sqlite3
from datetime import datetime
from typing import List, Optional, Dict, Any

from backend.models.schemas import CorrelatedIssue, RouteEntry
from backend.utils.logger import get_logger

logger = get_logger("store")

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "analyzer.db"
)


class IssueStore:
    """SQLite-backed persistent store for scans and correlated issues."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Creates scans and issues tables with indexes."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Scans Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source_folder TEXT,
                    target_url TEXT,
                    total_issues INTEGER NOT NULL DEFAULT 0,
                    confirmed_count INTEGER NOT NULL DEFAULT 0,
                    runtime_only_count INTEGER NOT NULL DEFAULT 0,
                    code_only_count INTEGER NOT NULL DEFAULT 0,
                    route_map_json TEXT
                )
            """)

            # Issues Table (FR-6: UNIQUE constraint on issue_hash for idempotency)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS issues (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    issue_hash TEXT UNIQUE NOT NULL,
                    scan_id TEXT NOT NULL,
                    status_label TEXT NOT NULL,
                    priority_rank INTEGER NOT NULL,
                    risk_score INTEGER NOT NULL,
                    cwe_id TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    file TEXT,
                    line INTEGER,
                    end_line INTEGER,
                    handler_function TEXT,
                    code_snippet TEXT,
                    http_method TEXT,
                    url_path TEXT,
                    parameter TEXT,
                    payload TEXT,
                    evidence TEXT,
                    fix_suggestion TEXT,
                    fixed_code TEXT,
                    description TEXT,
                    matched_route TEXT,
                    supporting_scanners TEXT,
                    merged_count INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_status ON issues(status_label);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_cwe ON issues(cwe_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_hash ON issues(issue_hash);")
            conn.commit()

    def save_scan(
        self,
        scan_id: str,
        source_folder: Optional[str],
        target_url: Optional[str],
        issues: List[CorrelatedIssue],
        route_map: List[RouteEntry]
    ) -> List[CorrelatedIssue]:
        """
        Idempotently persists scan metadata and issues (FR-6 / FR-10).
        Uses SQLite ON CONFLICT(issue_hash) DO UPDATE so running scans repeatedly never duplicates issues.
        Returns the updated CorrelatedIssue list with persisted database IDs.
        """
        now_iso = datetime.utcnow().isoformat()
        route_map_json = json.dumps([r.model_dump() for r in route_map])

        confirmed_cnt = sum(1 for i in issues if i.status_label == "Confirmed")
        runtime_cnt = sum(1 for i in issues if i.status_label == "Runtime only")
        code_cnt = sum(1 for i in issues if i.status_label == "Code only")

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Insert Scan metadata
            cursor.execute("""
                INSERT OR REPLACE INTO scans (
                    scan_id, created_at, source_folder, target_url,
                    total_issues, confirmed_count, runtime_only_count, code_only_count,
                    route_map_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, now_iso, source_folder, target_url,
                len(issues), confirmed_cnt, runtime_cnt, code_cnt,
                route_map_json
            ))

            # 2. Upsert each issue
            for issue in issues:
                scanners_json = json.dumps(issue.supporting_scanners)
                cursor.execute("""
                    INSERT INTO issues (
                        issue_hash, scan_id, status_label, priority_rank, risk_score,
                        cwe_id, vulnerability_type, severity, file, line, end_line,
                        handler_function, code_snippet, http_method, url_path, parameter,
                        payload, evidence, fix_suggestion, fixed_code, description,
                        matched_route, supporting_scanners, merged_count, created_at, updated_at
                    ) VALUES (
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?
                    )
                    ON CONFLICT(issue_hash) DO UPDATE SET
                        scan_id = excluded.scan_id,
                        status_label = excluded.status_label,
                        priority_rank = excluded.priority_rank,
                        risk_score = excluded.risk_score,
                        severity = excluded.severity,
                        file = COALESCE(excluded.file, issues.file),
                        line = COALESCE(excluded.line, issues.line),
                        end_line = COALESCE(excluded.end_line, issues.end_line),
                        handler_function = COALESCE(excluded.handler_function, issues.handler_function),
                        code_snippet = COALESCE(excluded.code_snippet, issues.code_snippet),
                        http_method = COALESCE(excluded.http_method, issues.http_method),
                        url_path = COALESCE(excluded.url_path, issues.url_path),
                        parameter = COALESCE(excluded.parameter, issues.parameter),
                        payload = COALESCE(excluded.payload, issues.payload),
                        evidence = COALESCE(excluded.evidence, issues.evidence),
                        fix_suggestion = COALESCE(excluded.fix_suggestion, issues.fix_suggestion),
                        fixed_code = COALESCE(excluded.fixed_code, issues.fixed_code),
                        description = COALESCE(excluded.description, issues.description),
                        matched_route = COALESCE(excluded.matched_route, issues.matched_route),
                        supporting_scanners = excluded.supporting_scanners,
                        merged_count = issues.merged_count + excluded.merged_count,
                        updated_at = excluded.updated_at
                """, (
                    issue.issue_hash, scan_id, issue.status_label, issue.priority_rank, issue.risk_score,
                    issue.cwe_id, issue.vulnerability_type, issue.severity, issue.file, issue.line, issue.end_line,
                    issue.handler_function, issue.code_snippet, issue.http_method, issue.url_path, issue.parameter,
                    issue.payload, issue.evidence, issue.fix_suggestion, issue.fixed_code, issue.description,
                    issue.matched_route, scanners_json, issue.merged_count, now_iso, now_iso
                ))

                # Retrieve persisted row ID
                cursor.execute("SELECT id FROM issues WHERE issue_hash = ?", (issue.issue_hash,))
                row = cursor.fetchone()
                if row:
                    issue.id = row["id"]

            conn.commit()

        # Re-fetch issues for this specific scan sorted strictly per FR-9
        return self.get_issues(scan_id=scan_id)

    def _row_to_issue(self, row: sqlite3.Row) -> CorrelatedIssue:
        """Helper to convert a SQLite row into a CorrelatedIssue model."""
        scanners = []
        if row["supporting_scanners"]:
            try:
                scanners = json.loads(row["supporting_scanners"])
            except Exception:
                scanners = ["SAST"]

        return CorrelatedIssue(
            id=row["id"],
            issue_hash=row["issue_hash"],
            status_label=row["status_label"],
            priority_rank=row["priority_rank"],
            risk_score=row["risk_score"],
            cwe_id=row["cwe_id"],
            vulnerability_type=row["vulnerability_type"],
            severity=row["severity"],
            file=row["file"],
            line=row["line"],
            end_line=row["end_line"],
            handler_function=row["handler_function"],
            code_snippet=row["code_snippet"],
            http_method=row["http_method"],
            url_path=row["url_path"],
            parameter=row["parameter"],
            payload=row["payload"],
            evidence=row["evidence"],
            fix_suggestion=row["fix_suggestion"],
            fixed_code=row["fixed_code"],
            description=row["description"],
            matched_route=row["matched_route"],
            supporting_scanners=scanners,
            merged_count=row["merged_count"]
        )

    def get_issues(
        self,
        scan_id: Optional[str] = None,
        status_label: Optional[str] = None,
        cwe_id: Optional[str] = None
    ) -> List[CorrelatedIssue]:
        """
        Retrieves all issues ordered strictly per FR-9:
        Confirmed (1) -> Runtime only (2) -> Code only (3), then risk_score DESC.
        Supports optional filtering by scan_id, status_label, and cwe_id.
        """
        query = """
            SELECT * FROM issues
            WHERE 1=1
        """
        params = []

        if scan_id:
            clean_scan = scan_id.strip()
            if clean_scan.lower() == "latest":
                with self._get_connection() as conn:
                    c = conn.cursor()
                    c.execute("SELECT scan_id FROM scans ORDER BY created_at DESC LIMIT 1;")
                    r = c.fetchone()
                    if r:
                        query += " AND scan_id = ?"
                        params.append(r["scan_id"])
            else:
                query += " AND scan_id = ?"
                params.append(clean_scan)

        if status_label:
            query += " AND status_label = ?"
            params.append(status_label.strip())

        if cwe_id:
            query += " AND UPPER(cwe_id) = UPPER(?)"
            params.append(cwe_id.strip())

        # FR-9 strict ordering: Confirmed first, then Runtime only, then Code only, then by risk_score DESC
        query += """
            ORDER BY 
                CASE status_label
                    WHEN 'Confirmed' THEN 1
                    WHEN 'Runtime only' THEN 2
                    WHEN 'Code only' THEN 3
                    ELSE 4
                END ASC,
                risk_score DESC,
                id ASC
        """

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            issues = [self._row_to_issue(r) for r in rows]

            # Re-index priority rank strictly 1..N
            for rank, issue in enumerate(issues, 1):
                issue.priority_rank = rank

            return issues

    def get_issue_by_id(self, issue_id: int) -> Optional[CorrelatedIssue]:
        """Fetches a single issue by its sequential integer ID (FR-10)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM issues WHERE id = ?", (issue_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_issue(row)

    def clear(self):
        """Clears all issues and scans for testing resets."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM issues;")
            cursor.execute("DELETE FROM scans;")
            conn.commit()


_store_instance: Optional[IssueStore] = None


def get_issue_store() -> IssueStore:
    """Singleton provider for IssueStore."""
    global _store_instance
    if _store_instance is None:
        _store_instance = IssueStore()
    return _store_instance
