from unittest.mock import AsyncMock, patch

import httpx
import pytest

from r3x.core.exceptions import ProviderError
from r3x.mixer.budget_guard import BudgetExceededError, BudgetGuard
from r3x.mixer.models import TaskRole
from r3x.mixer.providers import ProviderClient
from r3x.mixer.scoring import ModelScoringEngine


@pytest.mark.asyncio
async def test_provider_edge_case_invalid_key_401():
    client = ProviderClient(timeout=2.0)
    mock_resp = httpx.Response(401, json={"error": {"message": "Invalid API key provided"}})

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        with pytest.raises(ProviderError) as exc_info:
            await client.chat_completion(
                provider_name="openai",
                api_key="sk-test-secret-123",
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "hello"}],
                retries=1
            )
        assert "401" in str(exc_info.value)
        # Ensure secret API key is NOT leaked into the error string
        assert "sk-test-secret-123" not in str(exc_info.value)

@pytest.mark.asyncio
async def test_provider_edge_case_timeout():
    client = ProviderClient(timeout=1.0)
    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Read timed out")):
        with pytest.raises(ProviderError) as exc_info:
            await client.chat_completion(
                provider_name="nvidia",
                api_key="nvapi-test",
                model="meta/llama-3.1-8b-instruct",
                messages=[{"role": "user", "content": "ping"}],
                retries=2
            )
        assert "Exhausted 2 retries" in str(exc_info.value)

@pytest.mark.asyncio
async def test_provider_edge_case_rate_limit_and_recover():
    client = ProviderClient(timeout=2.0)
    rate_limit_resp = httpx.Response(429, json={"error": {"message": "Rate limit reached"}})
    success_resp = httpx.Response(200, json={
        "choices": [{"message": {"content": "Hello after backoff"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5}
    })

    # First call returns 429, second call returns 200
    with (
        patch("httpx.AsyncClient.post", side_effect=[rate_limit_resp, success_resp]),
        patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
    ):
        res = await client.chat_completion(
            provider_name="gemini",
            api_key="AIzaSy-test",
            model="gemini-1.5-flash",
            messages=[{"role": "user", "content": "test"}],
            retries=2
        )
        assert res["content"] == "Hello after backoff"
        assert mock_sleep.called

@pytest.mark.asyncio
async def test_provider_edge_case_malformed_json():
    client = ProviderClient(timeout=2.0)
    bad_json_resp = httpx.Response(200, text="<HTML>502 Bad Gateway</HTML>")

    with (
        patch("httpx.AsyncClient.post", return_value=bad_json_resp),
        pytest.raises(ProviderError),
    ):
        await client.chat_completion(
            provider_name="openrouter",
            api_key="sk-or-test",
            model="anthropic/claude-3.5-sonnet",
            messages=[{"role": "user", "content": "test"}],
            retries=1
        )

def test_budget_guard_enforcement():
    bg = BudgetGuard(max_cost_limit_usd=1.0)
    bg.set_budget(0.005)

    with patch("r3x.memory.db.db.get_api_usage_summary", return_value={"total_cost_usd": 0.006}):
        with pytest.raises(BudgetExceededError) as exc_info:
            bg.check_can_spend(estimated_next_cost=0.001)
        assert "Budget Guard Alert" in str(exc_info.value)

def test_dynamic_model_scoring_engine():
    engine = ModelScoringEngine()
    # Fast classification role should score lightweight models higher
    score_fast = engine.compute_fitness("nvidia", "meta/llama-3.1-8b-instruct", TaskRole.CLASSIFICATION, recent_latency_ms=100.0)
    score_heavy = engine.compute_fitness("nvidia", "meta/llama-3.3-70b-instruct", TaskRole.CLASSIFICATION, recent_latency_ms=800.0)
    assert score_fast > score_heavy

    # Deep reasoning role should favor heavy models
    score_deep_heavy = engine.compute_fitness("openai", "gpt-4o", TaskRole.DEEP_REASONING, recent_latency_ms=300.0)
    score_deep_mini = engine.compute_fitness("openai", "gpt-4o-mini", TaskRole.DEEP_REASONING, recent_latency_ms=300.0)
    assert score_deep_heavy > score_deep_mini
