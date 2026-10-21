"""
R3X Base Security Scanner
Provides shared lifecycle, scope validation, and evidence packaging.
"""
import uuid
from typing import Dict, Any, List, Optional
from r3x.security.scope_guardian import scope_guardian
from r3x.core.logger import logger, audit_log
from r3x.evidence.sanitizer import sanitize_evidence
from r3x.evidence.hashing import compute_sha256

class BaseScanner:
    def __init__(self, target_url: str, project_id: Optional[str] = None):
        self.target_url = target_url.strip()
        self.project_id = project_id
        # Strict pre-execution scope verification
        scope_guardian.validate_target(self.target_url, project_id=self.project_id)

    def record_finding(
        self,
        scan_id: str,
        title: str,
        severity: str,
        endpoint: str,
        technical_explanation: str,
        remediation: str,
        cwe: Optional[str] = None,
        cvss: float = 0.0,
        status: str = "CONFIRMED",
        confidence_score: float = 1.0,
        request_raw: Optional[str] = None,
        response_raw: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Package a security finding with sanitized evidence and cryptographic hash.
        """
        finding_id = str(uuid.uuid4())[:8]
        evidence_id = str(uuid.uuid4())[:8]

        # Automatic secrets redaction
        clean_req = sanitize_evidence(request_raw or "")
        clean_resp = sanitize_evidence(response_raw or "")
        clean_hdrs = {k: sanitize_evidence(v) for k, v in (headers or {}).items()}

        combined_trace = f"{clean_req}\n---\n{clean_resp}\n---\n{clean_hdrs}"
        ev_hash = compute_sha256(combined_trace)

        finding = {
            "id": finding_id,
            "scan_id": scan_id,
            "project_id": self.project_id or "default",
            "title": title,
            "severity": severity.upper(),
            "endpoint": endpoint,
            "cwe": cwe,
            "cvss": cvss,
            "status": status,
            "confidence_score": confidence_score,
            "technical_explanation": technical_explanation,
            "remediation": remediation,
            "evidence_hash": ev_hash
        }

        evidence = {
            "id": evidence_id,
            "finding_id": finding_id,
            "scan_id": scan_id,
            "request_raw": clean_req,
            "response_raw": clean_resp,
            "headers": clean_hdrs,
            "hash_sha256": ev_hash,
            "is_sanitized": True
        }

        audit_log("FINDING_RECORDED", endpoint, self.__class__.__name__, f"{severity}: {title}")
        return {"finding": finding, "evidence": evidence}
