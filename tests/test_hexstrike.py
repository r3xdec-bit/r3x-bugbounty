import pytest

from r3x.core.exceptions import AdapterError, ToolExecutionError
from r3x.integrations.hexstrike_adapter import HexStrikeAdapter


def test_hexstrike_offline_handling():
    adapter = HexStrikeAdapter(endpoint="http://127.0.0.1:9998")  # Non-existent endpoint
    is_conn, msg = adapter.check_connection()
    assert is_conn is False
    assert "unreachable" in msg

def test_hexstrike_tool_execution_guards():
    adapter = HexStrikeAdapter(endpoint="http://127.0.0.1:9998")
    with pytest.raises((ToolExecutionError, AdapterError)):
        adapter.execute_tool("unregistered_tool", {})
