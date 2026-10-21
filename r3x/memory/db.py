"""
R3X SQLite Persistent Database Engine
Stores projects, targets, scans, findings, evidence, agent logs, and API consumption.
"""
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from r3x.core.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    status TEXT DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    url TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER DEFAULT 443,
    is_in_scope INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    allowed_patterns TEXT,
    excluded_patterns TEXT,
    allow_subdomains INTEGER DEFAULT 1,
    max_rate_per_sec INTEGER DEFAULT 5,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    summary_json TEXT,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    cwe TEXT,
    cvss REAL,
    status TEXT NOT NULL,
    confidence_score REAL,
    technical_explanation TEXT,
    remediation TEXT,
    evidence_hash TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    scan_id TEXT NOT NULL,
    request_raw TEXT,
    response_raw TEXT,
    headers_json TEXT,
    timestamp TEXT NOT NULL,
    hash_sha256 TEXT NOT NULL,
    is_sanitized INTEGER DEFAULT 1,
    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    agent_name TEXT NOT NULL,
    decision_reason TEXT,
    input_summary TEXT,
    output_summary TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    latency_ms REAL DEFAULT 0.0,
    estimated_cost REAL DEFAULT 0.0,
    timestamp TEXT NOT NULL
);
"""

class Database:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or settings.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript(SCHEMA)

    # ------------------ Projects ------------------
    def create_project(self, project_id: str, name: str, description: str = "") -> Dict[str, Any]:
        created_at = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO projects (id, name, description, created_at, status) VALUES (?, ?, ?, ?, 'ACTIVE')",
                (project_id, name, description, created_at)
            )
        return {"id": project_id, "name": name, "description": description, "created_at": created_at}

    def get_project(self, project_id_or_name: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM projects WHERE id = ? OR name = ?",
                (project_id_or_name, project_id_or_name)
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def list_projects(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM projects ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]

    # ------------------ Targets & Scopes ------------------
    def add_target(self, target_id: str, project_id: str, url: str, hostname: str, port: int = 443) -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO targets (id, project_id, url, hostname, port, is_in_scope, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
                (target_id, project_id, url, hostname, port, created_at)
            )

    def get_targets(self, project_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM targets WHERE project_id = ?", (project_id,))
            return [dict(r) for r in cur.fetchall()]

    def set_scope(self, scope_id: str, project_id: str, domain: str, allowed: List[str], excluded: List[str], allow_subdomains: bool = True, max_rate: int = 5) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scopes 
                (id, project_id, target_domain, allowed_patterns, excluded_patterns, allow_subdomains, max_rate_per_sec) 
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scope_id, project_id, domain, json.dumps(allowed), json.dumps(excluded), 1 if allow_subdomains else 0, max_rate)
            )

    def get_scope(self, project_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM scopes WHERE project_id = ?", (project_id,))
            row = cur.fetchone()
            if row:
                d = dict(row)
                d["allowed_patterns"] = json.loads(d["allowed_patterns"] or "[]")
                d["excluded_patterns"] = json.loads(d["excluded_patterns"] or "[]")
                return d
            return None

    # ------------------ Scans ------------------
    def create_scan(self, scan_id: str, project_id: str, scan_type: str) -> None:
        start_time = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO scans (id, project_id, scan_type, status, start_time) VALUES (?, ?, ?, 'RUNNING', ?)",
                (scan_id, project_id, scan_type, start_time)
            )

    def update_scan_status(self, scan_id: str, status: str, summary: Optional[Dict[str, Any]] = None) -> None:
        end_time = datetime.now(timezone.utc).isoformat() if status in ["COMPLETED", "FAILED"] else None
        summary_str = json.dumps(summary) if summary else None
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE scans SET status = ?, end_time = coalesce(?, end_time), summary_json = coalesce(?, summary_json) WHERE id = ?",
                (status, end_time, summary_str, scan_id)
            )

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_scans(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            if project_id:
                cur = conn.execute("SELECT * FROM scans WHERE project_id = ? ORDER BY start_time DESC", (project_id,))
            else:
                cur = conn.execute("SELECT * FROM scans ORDER BY start_time DESC")
            return [dict(r) for r in cur.fetchall()]

    # ------------------ Findings & Evidence ------------------
    def add_finding(self, finding: Dict[str, Any]) -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """INSERT INTO findings 
                (id, scan_id, project_id, title, severity, endpoint, cwe, cvss, status, confidence_score, technical_explanation, remediation, evidence_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding["id"], finding["scan_id"], finding["project_id"], finding["title"],
                    finding["severity"], finding["endpoint"], finding.get("cwe"), finding.get("cvss", 0.0),
                    finding["status"], finding.get("confidence_score", 1.0),
                    finding.get("technical_explanation", ""), finding.get("remediation", ""),
                    finding.get("evidence_hash", ""), created_at
                )
            )

    def add_evidence(self, ev: Dict[str, Any]) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """INSERT INTO evidence 
                (id, finding_id, scan_id, request_raw, response_raw, headers_json, timestamp, hash_sha256, is_sanitized)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ev["id"], ev.get("finding_id"), ev["scan_id"],
                    ev.get("request_raw"), ev.get("response_raw"),
                    json.dumps(ev.get("headers", {})), timestamp,
                    ev["hash_sha256"], 1 if ev.get("is_sanitized", True) else 0
                )
            )

    def list_findings(self, project_id: Optional[str] = None, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            query = "SELECT * FROM findings WHERE 1=1"
            params = []
            if project_id:
                query += " AND project_id = ?"
                params.append(project_id)
            if scan_id:
                query += " AND scan_id = ?"
                params.append(scan_id)
            query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END"
            cur = conn.execute(query, params)
            return [dict(r) for r in cur.fetchall()]

    def list_evidence(self, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            if scan_id:
                cur = conn.execute("SELECT * FROM evidence WHERE scan_id = ?", (scan_id,))
            else:
                cur = conn.execute("SELECT * FROM evidence ORDER BY timestamp DESC")
            return [dict(r) for r in cur.fetchall()]

    # ------------------ Agent Logs & API Usage ------------------
    def log_agent_action(
        self,
        scan_id: Optional[str],
        agent_name: str,
        decision: str = "",
        input_summary: str = "",
        output_summary: str = "",
        decision_reason: Optional[str] = None,
        in_sum: Optional[str] = None,
        out_sum: Optional[str] = None
    ) -> None:
        dec = decision_reason or decision
        i_sum = in_sum or input_summary
        o_sum = out_sum or output_summary
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO agent_logs (scan_id, agent_name, decision_reason, input_summary, output_summary, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, agent_name, dec, i_sum, o_sum, timestamp)
            )

    def log_api_usage(self, provider: str, model: str, prompt_tokens: int, completion_tokens: int, latency_ms: float, cost: float) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO api_usage (provider, model, prompt_tokens, completion_tokens, latency_ms, estimated_cost, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (provider, model, prompt_tokens, completion_tokens, latency_ms, cost, timestamp)
            )

    def get_api_usage_summary(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT SUM(prompt_tokens) as p, SUM(completion_tokens) as c, SUM(estimated_cost) as cost, COUNT(*) as count FROM api_usage")
            row = cur.fetchone()
            return {
                "total_calls": row["count"] or 0,
                "total_prompt_tokens": row["p"] or 0,
                "total_completion_tokens": row["c"] or 0,
                "total_cost_usd": round(row["cost"] or 0.0, 5)
            }

db = Database()
