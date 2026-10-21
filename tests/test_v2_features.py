import tempfile
import uuid
from pathlib import Path

import pytest

from r3x.cli.dashboard import render_dashboard
from r3x.core.exceptions import R3XError
from r3x.core.graph import AttackSurfaceGraph
from r3x.core.neural_brain import NeuralBrain
from r3x.core.optimizer import ScanOptimizer
from r3x.core.self_healing import SelfHealingEngine
from r3x.evidence.validator import AIEvidenceValidator
from r3x.memory.db import db
from r3x.memory.knowledge import KnowledgeMemoryEngine
from r3x.mixer.debate import MultiAgentDebateEngine
from r3x.plugins.manager import PluginManager
from r3x.reports.intelligence import AIReportIntelligence


def test_neural_brain_correlation():
    brain = NeuralBrain()
    findings = [
        {
            "finding": {
                "title": "CORS Misconfiguration Allowed Arbitrary Origin",
                "endpoint": "http://127.0.0.1:8999/api/user",
                "severity": "HIGH"
            }
        },
        {
            "finding": {
                "title": "Hardcoded API Token Leaked in JavaScript",
                "endpoint": "http://127.0.0.1:8999/app.js",
                "severity": "CRITICAL"
            }
        },
        {
            "finding": {
                "title": "Server Version Disclosure Header",
                "endpoint": "http://127.0.0.1:8999/",
                "severity": "LOW"
            }
        }
    ]

    analysis = brain.correlate_attack_surface(scan_id="test-scan-corr", findings=findings)
    assert analysis["scan_id"] == "test-scan-corr"
    assert analysis["total_findings"] == 3
    assert len(analysis["attack_chains"]) >= 1
    chain_names = [c["name"] for c in analysis["attack_chains"]]
    assert any("Cross-Origin" in name or "Targeted Component" in name for name in chain_names)
    assert "strategic_synthesis" in analysis


def test_multi_agent_debate_engine():
    debate = MultiAgentDebateEngine()
    result = debate.run_debate(
        finding_title="Missing Content-Security-Policy",
        endpoint="http://example.com/",
        severity="LOW",
        evidence_trace="GET / HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nServer: Apache"
    )

    assert "verdict" in result
    assert result["verdict"] in ["CONFIRMED", "POTENTIAL", "FALSE_POSITIVE"]
    assert 0.0 <= result["confidence_score"] <= 1.0
    assert "agent_a_prosecution" in result
    assert "agent_b_defense" in result
    assert "judge_rationale" in result


def test_attack_surface_graph():
    run_id = uuid.uuid4().hex[:6]
    project_id = f"proj-graph-{run_id}"
    project_name = f"Graph Project {run_id}"

    db.create_project(project_id, project_name, "Testing graph")
    db.add_target(f"target-g-{run_id}", project_id, "http://api.target.local", "api.target.local", port=80)
    db.create_scan(f"scan-g-{run_id}", project_id, "quick")
    db.add_finding({
        "id": f"find-g-{run_id}",
        "scan_id": f"scan-g-{run_id}",
        "project_id": project_id,
        "title": "CORS Wildcard",
        "severity": "MEDIUM",
        "endpoint": "http://api.target.local/v1/users",
        "status": "CONFIRMED",
        "cvss": 5.0,
        "confidence_score": 0.9,
        "evidence_hash": "testhash123"
    })

    graph_engine = AttackSurfaceGraph()
    g = graph_engine.build_from_project(project_id)

    assert len(g.nodes) >= 3
    # Verify nodes
    node_types = [d.get("type") for _, d in g.nodes(data=True)]
    assert "PROJECT" in node_types
    assert "HOST" in node_types
    assert "ENDPOINT" in node_types
    assert "FINDING" in node_types

    # Render terminal without error
    graph_engine.render_terminal(project_id)


def test_knowledge_memory_engine():
    engine = KnowledgeMemoryEngine()

    sig1 = engine.compute_pattern_signature("Missing HSTS", "CWE-319", "Nginx")
    sig2 = engine.compute_pattern_signature("Missing HSTS", "CWE-319", "Nginx")
    sig3 = engine.compute_pattern_signature("SQL Injection", "CWE-89", "MySQL")

    assert sig1 == sig2
    assert sig1 != sig3
    assert len(sig1) == 16

    remediation = engine.get_abstract_remediation("hsts_missing")
    assert remediation is not None
    assert "Strict-Transport-Security" in remediation["recommendation"]
    assert remediation["historical_success_rate"] > 0.90

    # Test context compression
    findings = [
        {"title": "Open Port", "severity": "INFO", "endpoint": "127.0.0.1:80", "status": "CONFIRMED"},
        {"title": "Missing CSP", "severity": "LOW", "endpoint": "127.0.0.1:80", "status": "CONFIRMED"},
    ]
    compressed = engine.compress_context(findings, max_items=2)
    assert "#1 [INFO] Open Port" in compressed
    assert "#2 [LOW] Missing CSP" in compressed


def test_self_healing_engine():
    healer = SelfHealingEngine()

    # Test diagnoses
    diag_missing = healer.diagnose_failure("nonexistent_scanner_xyz", "command not found: nonexistent_scanner_xyz")
    assert diag_missing["root_cause"] == "MISSING_BINARY"
    assert not diag_missing["is_recoverable"]

    diag_rate = healer.diagnose_failure("nuclei", "HTTP 429 Too Many Requests: Rate limit exceeded")
    assert diag_rate["root_cause"] == "RATE_LIMIT_EXCEEDED"
    assert diag_rate["is_recoverable"]
    assert diag_rate["retry_delay_seconds"] > 0

    diag_timeout = healer.diagnose_failure("httpx", "Connection timed out after 10000ms")
    assert diag_timeout["root_cause"] == "NETWORK_TIMEOUT"
    assert diag_timeout["is_recoverable"]

    # Test execute_with_self_healing retry logic
    attempts = 0

    def flaky_action():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("Request 429 Too Many Requests")
        return "SUCCESS_DATA"

    # Temporarily monkeypatch sleep to make test instant
    import time
    orig_sleep = time.sleep
    time.sleep = lambda s: None
    try:
        result = healer.execute_with_self_healing("api_caller", flaky_action, max_retries=2)
        assert result == "SUCCESS_DATA"
        assert attempts == 2
    finally:
        time.sleep = orig_sleep


def test_scan_optimizer():
    optimizer = ScanOptimizer()

    # Plain HTTP target should skip TLS
    plan_http = optimizer.optimize_scan_plan("http://test.local:8080/app", scan_type="quick")
    assert not plan_http["run_tls"]
    assert plan_http["run_headers"]
    assert not plan_http["run_api_schemas"]

    # HTTPS target should run TLS
    plan_https = optimizer.optimize_scan_plan("https://secure.target.com", scan_type="full")
    assert plan_https["run_tls"]
    assert plan_https["run_api_schemas"]
    assert plan_https["run_js_analysis"]

    # Response cache test
    optimizer.set_cached_response("key1", {"status": 200})
    assert optimizer.get_cached_response("key1") == {"status": 200}
    assert optimizer.get_cached_response("key_none") is None


def test_ai_evidence_validator():
    validator = AIEvidenceValidator()

    # Test with valid evidence
    finding = {
        "title": "Exposed Git Configuration",
        "endpoint": "http://127.0.0.1:8999/.git/config"
    }
    evidence = {
        "request_raw": "GET /.git/config HTTP/1.1\nHost: 127.0.0.1:8999",
        "response_raw": "HTTP/1.1 200 OK\n[core]\nrepositoryformatversion = 0",
        "headers": {"Content-Type": "text/plain"},
        "hash_sha256": "dummyhashabc123"
    }

    result = validator.validate_evidence(finding, evidence)
    assert result["is_valid"]
    assert result["hash_matches"]
    assert result["zero_leakage_guaranteed"]
    assert result["reproducibility_score"] == 1.0

    # Test with unredacted sensitive token (leakage detection)
    leaky_evidence = {
        "request_raw": "GET /api HTTP/1.1\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.supersecret",
        "response_raw": "HTTP/1.1 200 OK",
        "headers": {},
        "hash_sha256": "dummyhash456"
    }
    result_leak = validator.validate_evidence(finding, leaky_evidence)
    assert not result_leak["zero_leakage_guaranteed"]
    assert not result_leak["is_valid"]


def test_plugin_manager():
    with tempfile.TemporaryDirectory() as tmp_dir:
        mgr = PluginManager(plugin_dir=Path(tmp_dir))
        plugins = mgr.list_plugins()
        assert len(plugins) >= 3

        # Test enable / disable
        assert mgr.enable_plugin("jwt_security_auditor")
        updated = next(p for p in mgr.list_plugins() if p["name"] == "jwt_security_auditor")
        assert updated["is_enabled"]

        assert mgr.disable_plugin("jwt_security_auditor")
        updated2 = next(p for p in mgr.list_plugins() if p["name"] == "jwt_security_auditor")
        assert not updated2["is_enabled"]

        # Test privilege enforcement: disallowed permission rejected
        bad_manifest = {
            "name": "dangerous_exploit_module",
            "version": "1.0.0",
            "author": "malicious",
            "description": "Attempts root escalation",
            "permissions": ["system:root"]
        }
        with pytest.raises(R3XError):
            mgr.install_plugin_manifest(bad_manifest)


def test_ai_report_intelligence():
    run_id = uuid.uuid4().hex[:6]
    project_id = f"proj-rep-{run_id}"
    scan_id = f"scan-rep-{run_id}"
    finding_id = f"find-rep-{run_id}"

    db.create_project(project_id, f"Report Project {run_id}", "Testing bug bounty report export")
    db.create_scan(scan_id, project_id, "full")
    db.add_finding({
        "id": finding_id,
        "scan_id": scan_id,
        "project_id": project_id,
        "title": "CORS Origin Reflection",
        "severity": "HIGH",
        "endpoint": "http://127.0.0.1:8999/api/account",
        "status": "CONFIRMED",
        "cvss": 7.5,
        "cwe": "CWE-942",
        "confidence_score": 0.95,
        "evidence_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "technical_explanation": "Server reflects arbitrary Origin headers in Access-Control-Allow-Origin with credentials flag enabled.",
        "impact": "Enables malicious websites to read sensitive user account data via victim's browser.",
        "remediation": "Validate Origin against an allowlist of trusted origins before echoing."
    })
    db.add_evidence({
        "id": f"ev-rep-{run_id}",
        "finding_id": finding_id,
        "scan_id": scan_id,
        "request_raw": "GET /api/account HTTP/1.1\nHost: 127.0.0.1:8999\nOrigin: https://attacker.com",
        "response_raw": "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://attacker.com\nAccess-Control-Allow-Credentials: true",
        "headers": {"Access-Control-Allow-Origin": "https://attacker.com"},
        "hash_sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "is_sanitized": True
    })

    intel = AIReportIntelligence()
    report = intel.export_bug_bounty_submission(finding_id)

    assert "# Vulnerability Report: CORS Origin Reflection" in report
    assert "CWE-942" in report
    assert "7.5" in report
    assert "https://attacker.com" in report
    assert "Enables malicious websites" in report


def test_dashboard_render():
    # Verify render_dashboard runs without unhandled exceptions
    render_dashboard()
