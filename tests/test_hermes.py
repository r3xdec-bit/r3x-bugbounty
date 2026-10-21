from r3x.integrations.hermes_adapter import HermesAdapter

def test_hermes_adapter_status():
    adapter = HermesAdapter(endpoint="http://127.0.0.1:9999")  # Non-existent endpoint
    is_online, details = adapter.check_status()
    assert is_online is False
    assert "Hermes" in details

def test_hermes_planning_fallback():
    adapter = HermesAdapter(endpoint="http://127.0.0.1:9999")
    plan = adapter.create_security_plan(
        target_url="https://test.local",
        scope_rules={"target_domain": "test.local"},
        scan_type="quick"
    )
    assert "stages" in plan
    assert len(plan["stages"]) > 0
    assert "recommended_agents" in plan
