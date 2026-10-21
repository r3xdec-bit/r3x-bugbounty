import pytest
import os
from pathlib import Path
from tests.mock_target_server import MockTargetServer
from r3x.memory.db import db
from r3x.agents.hermes_master import hermes_master
from r3x.reports.generator import report_generator

@pytest.fixture(scope="module")
def mock_server():
    server = MockTargetServer(port=8999)
    server.start()
    yield server
    server.stop()

def test_full_end_to_end_assessment_pipeline(mock_server):
    target_url = "http://127.0.0.1:8999"
    project_name = "e2e-audit-project"

    # 1. Project & Scope Setup
    proj = db.create_project("proj-e2e-1", project_name, "End to End Pipeline Verification")
    db.add_target("target-e2e-1", proj["id"], target_url, "127.0.0.1", port=8999)
    db.set_scope(
        scope_id="scope-e2e-1",
        project_id=proj["id"],
        domain="127.0.0.1",
        allowed=["127.0.0.1"],
        excluded=["*.gov", "logout"]
    )

    # 2. Run Complete Multi-Agent Scan
    context = hermes_master.execute_scan(
        target_url=target_url,
        project_name=project_name,
        scan_type="full"
    )

    findings = context.get("findings", [])
    assert len(findings) > 0

    # Verify specific vulnerabilities were correctly identified
    titles = [f["finding"]["title"] for f in findings]

    # Check headers / cookies / tech fingerprinting
    assert any("Server Version Disclosure" in t for t in titles)
    assert any("X-Powered-By" in t for t in titles)
    assert any("HttpOnly" in t for t in titles)

    # 3. Verify SQLite Persistence & Evidence Hashing
    db_findings = db.list_findings(project_id=proj["id"])
    assert len(db_findings) >= len(findings)
    for df in db_findings:
        assert len(df["evidence_hash"]) == 64  # SHA-256 length

    # 4. Verify Multi-Format Report Generation
    html_report = report_generator.create_report(project_id=proj["id"], scan_id=context["scan_id"], format_type="html")
    md_report = report_generator.create_report(project_id=proj["id"], scan_id=context["scan_id"], format_type="md")

    assert os.path.exists(html_report)
    assert os.path.exists(md_report)

    html_text = Path(html_report).read_text(encoding="utf-8")
    assert "R3X-BugBounty Security Assessment Report" in html_text
    assert "127.0.0.1" in html_text

def test_scan_pause_and_resume(mock_server):
    # Test resume command functionality
    scans = db.list_scans()
    assert len(scans) > 0
    latest_scan_id = scans[0]["id"]

    # Resume the scan
    hermes_master.resume_scan(latest_scan_id)
    scan_record = db.get_scan(latest_scan_id)
    assert scan_record["status"] in ["COMPLETED", "RUNNING"]
