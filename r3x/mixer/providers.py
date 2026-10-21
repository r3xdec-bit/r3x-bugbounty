"""
R3X Provider HTTP Client Implementation
Communicates with OpenAI-compatible inference endpoints.
"""
import asyncio
import time
from typing import Any

import httpx

from r3x.core.exceptions import ProviderError
from r3x.core.logger import logger, redact_secrets
from r3x.mixer.models import DEFAULT_PROVIDERS


class ProviderClient:
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    async def chat_completion(
        self,
        provider_name: str,
        api_key: str,
        model: str,
        messages: list[dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 2048,
        retries: int = 3
    ) -> dict[str, Any]:
        """
        Execute OpenAI-compatible chat completion with exponential backoff.
        Returns: {
            "content": str,
            "prompt_tokens": int,
            "completion_tokens": int,
            "latency_ms": float,
            "model": str,
            "provider": str
        }
        """
        cfg = DEFAULT_PROVIDERS.get(provider_name.lower())
        if not cfg:
            raise ProviderError(f"Unsupported provider: {provider_name}")

        url = f"{cfg.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}" if api_key else ""
        }
        if provider_name.lower() == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/r3xdec/r3x-bugbounty"
            headers["X-Title"] = "R3X-BugBounty"

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        start_time = time.time()
        last_exception = None

        for attempt in range(1, retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, headers=headers, json=payload)

                    if resp.status_code == 429:
                        wait_sec = 2 ** attempt
                        logger.warning(f"Rate limit hit on {provider_name} (429). Retrying in {wait_sec}s...")
                        await asyncio.sleep(wait_sec)
                        continue

                    if resp.status_code != 200:
                        err_text = redact_secrets(resp.text)
                        raise ProviderError(f"Provider {provider_name} HTTP {resp.status_code}: {err_text}")

                    data = resp.json()
                    elapsed_ms = (time.time() - start_time) * 1000.0

                    choices = data.get("choices", [])
                    if not choices:
                        raise ProviderError(f"Provider {provider_name} returned empty choices")

                    content = choices[0].get("message", {}).get("content", "")
                    usage = data.get("usage", {})
                    p_tok = usage.get("prompt_tokens", len(str(messages)) // 4)
                    c_tok = usage.get("completion_tokens", len(content) // 4)

                    return {
                        "content": content,
                        "prompt_tokens": p_tok,
                        "completion_tokens": c_tok,
                        "latency_ms": elapsed_ms,
                        "model": model,
                        "provider": provider_name
                    }

            except (httpx.TimeoutException, httpx.NetworkError) as e:
                last_exception = e
                wait_sec = 1.5 ** attempt
                logger.warning(f"Network error on {provider_name}: {e}. Retrying in {wait_sec:.1f}s...")
                await asyncio.sleep(wait_sec)
            except ProviderError:
                raise
            except Exception as e:
                raise ProviderError(f"Unexpected error communicating with {provider_name}: {e}")

        raise ProviderError(f"Exhausted {retries} retries on {provider_name}: {last_exception}")

    async def ping_provider(self, provider_name: str, api_key: str) -> tuple[bool, str]:
        """Test health by sending a minimal token query."""
        try:
            cfg = DEFAULT_PROVIDERS[provider_name.lower()]
            res = await self.chat_completion(
                provider_name=provider_name,
                api_key=api_key,
                model=cfg.default_model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5,
                retries=1
            )
            return True, f"Success ({res['latency_ms']:.0f}ms)"
        except Exception as e:
            return False, redact_secrets(str(e))

provider_client = ProviderClient()
