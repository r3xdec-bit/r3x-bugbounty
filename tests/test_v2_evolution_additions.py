import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from r3x.core.exceptions import ScopeViolationError
from r3x.core.tool_manager import ToolManager
from r3x.notifications.webhook import NotificationDispatcher
from r3x.scanners.auth_differential import AuthDifferentialScanner


def test_tool_manager_status():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tm = ToolManager(bin_dir=Path(tmp_dir))
        assert tm.is_installed("nmap")
        assert not tm.is_installed("non_existent_binary_12345")
        assert tm.get_tool_path("non_existent_binary_12345") is None


def test_tool_manager_consent_rejection():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tm = ToolManager(bin_dir=Path(tmp_dir))
        # Non-interactive mode should safely reject installation
        approved = tm.request_installation_consent("nuclei", interactive=False)
        assert not approved

        # Interactive rejection
        with patch("r3x.core.tool_manager.Confirm.ask", return_value=False):
            assert not tm.request_installation_consent("nuclei", interactive=True)

        # Interactive approval
        with patch("r3x.core.tool_manager.Confirm.ask", return_value=True):
            assert tm.request_installation_consent("nuclei", interactive=True)


def test_tool_manager_scope_enforcement():
    tm = ToolManager()
    with pytest.raises(ScopeViolationError):
        # Excluded government target violates ScopeGuardian rules
        tm.execute_safe("nmap", ["-sV"], target_url="https://agency.gov")


def test_auth_differential_anonymous_exposure():
    scanner = AuthDifferentialScanner("http://127.0.0.1:8999")
    
    mock_resp_priv = MagicMock()
    mock_resp_priv.status_code = 200
    mock_resp_priv.content = b'{"admin_data": "secret_records", "id": 100}'
    mock_resp_priv.text = '{"admin_data": "secret_records", "id": 100}'
    mock_resp_priv.headers = {"Content-Type": "application/json"}

    mock_resp_anon = MagicMock()
    mock_resp_anon.status_code = 200
    mock_resp_anon.content = b'{"admin_data": "secret_records", "id": 100}'
    mock_resp_anon.text = '{"admin_data": "secret_records", "id": 100}'
    mock_resp_anon.headers = {"Content-Type": "application/json"}

    with patch("httpx.Client.get", side_effect=[mock_resp_priv, mock_resp_anon]):
        findings = scanner.audit_endpoint_access(
            endpoint_url="http://127.0.0.1:8999/api/admin/reports",
            privileged_headers={"Authorization": "Bearer admin-token-123"}
        )
        assert len(findings) == 1
        finding_data = findings[0]["finding"]
        assert "Broken Authentication" in finding_data["title"]
        assert finding_data["severity"] == "HIGH"
        assert finding_data["cwe"] == "CWE-306"


def test_auth_differential_cross_role_disparity():
    scanner = AuthDifferentialScanner("http://127.0.0.1:8999")

    mock_resp_priv = MagicMock()
    mock_resp_priv.status_code = 200
    mock_resp_priv.content = b'{"admin_metrics": [1, 2, 3]}'
    mock_resp_priv.text = '{"admin_metrics": [1, 2, 3]}'
    mock_resp_priv.headers = {"Content-Type": "application/json"}

    mock_resp_anon = MagicMock()
    mock_resp_anon.status_code = 401
    mock_resp_anon.content = b'Unauthorized'
    mock_resp_anon.text = 'Unauthorized'
    mock_resp_anon.headers = {}

    mock_resp_low = MagicMock()
    mock_resp_low.status_code = 200
    mock_resp_low.content = b'{"admin_metrics": [1, 2, 3]}'
    mock_resp_low.text = '{"admin_metrics": [1, 2, 3]}'
    mock_resp_low.headers = {"Content-Type": "application/json"}

    with patch("httpx.Client.get", side_effect=[mock_resp_priv, mock_resp_anon, mock_resp_low]):
        findings = scanner.audit_endpoint_access(
            endpoint_url="http://127.0.0.1:8999/api/admin/metrics",
            privileged_headers={"Authorization": "Bearer admin-token"},
            unprivileged_headers={"Authorization": "Bearer low-user-token"}
        )
        assert len(findings) == 1
        finding_data = findings[0]["finding"]
        assert "BOLA/BFLA" in finding_data["title"]
        assert finding_data["severity"] == "CRITICAL"
        assert finding_data["cwe"] == "CWE-639"


def test_notification_dispatcher():
    dispatcher = NotificationDispatcher()
    finding = {
        "title": "CORS Reflection with Bearer eyJhbGciOiJIUzI1NiJ9.leaktoken12345678",
        "severity": "HIGH",
        "endpoint": "http://127.0.0.1:8999/api/account",
        "cvss": 7.5,
        "cwe": "CWE-942",
        "technical_explanation": "Arbitrary origin reflected with credentials password=supersecret."
    }

    # Test Slack format
    slack_payload = dispatcher.format_finding_payload(finding, channel="slack")
    assert "attachments" in slack_payload
    assert "leaktoken" not in str(slack_payload)  # Secrets redacted
    assert "supersecret" not in str(slack_payload)

    # Test Discord format
    discord_payload = dispatcher.format_finding_payload(finding, channel="discord")
    assert "embeds" in discord_payload
    assert discord_payload["embeds"][0]["color"] == 14753096

    # Test Telegram format
    tg_payload = dispatcher.format_finding_payload(finding, channel="telegram")
    assert "parse_mode" in tg_payload
    assert "CWE-942" in tg_payload["text"]

    # Test Webhook Dispatch
    mock_resp = httpx.Response(200, json={"ok": True})
    with patch("httpx.Client.post", return_value=mock_resp):
        success = dispatcher.send_webhook_alert("https://discord.com/api/webhooks/mock", finding, channel="discord")
        assert success
