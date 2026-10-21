import os
import tempfile
from pathlib import Path

from r3x.evidence.hashing import compute_sha256
from r3x.evidence.sanitizer import sanitize_evidence
from r3x.memory.db import Database


def test_sanitizer():
    dirty_input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThis\npassword: supersecret123\nconnect.sid=s%3Aabcdef1234567890"
    cleaned = sanitize_evidence(dirty_input)
    assert "supersecret123" not in cleaned
    assert "[REDACTED_PASSWORD]" in cleaned or "[REDACTED_CREDENTIAL]" in cleaned
    assert "doNotLeakThis" not in cleaned
    assert "[REDACTED_SESSION_ID]" in cleaned

def test_sha256_hash():
    h = compute_sha256("test-data")
    assert len(h) == 64
    assert h == compute_sha256("test-data")

def test_database_persistence():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        db_path = Path(tf.name)

    try:
        mem_db = Database(db_path=db_path)
        p = mem_db.create_project("test-p1", "Test Project", "Desc")
        assert p["name"] == "Test Project"

        mem_db.create_scan("scan-t1", "test-p1", "quick")
        mem_db.add_finding({
            "id": "f-1",
            "scan_id": "scan-t1",
            "project_id": "test-p1",
            "title": "Missing HSTS",
            "severity": "MEDIUM",
            "endpoint": "https://test.local",
            "status": "CONFIRMED",
            "cvss": 5.3,
            "confidence_score": 1.0,
            "evidence_hash": "dummyhash"
        })

        findings = mem_db.list_findings(project_id="test-p1")
        assert len(findings) == 1
        assert findings[0]["title"] == "Missing HSTS"
    finally:
        if db_path.exists():
            os.remove(db_path)
