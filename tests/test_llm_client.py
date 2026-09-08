"""Provider-agnostic LLM client. No real network calls are made."""

from __future__ import annotations

import httpx
import pytest

import llm
from llm import (
    AnthropicClient,
    LLMConfig,
    LLMProvider,
    LLMResponseError,
    LLMTransportError,
    OpenAIClient,
    build_llm_client,
)


def _client(handler, provider=LLMProvider.ANTHROPIC, **cfg_kw):
    cfg = LLMConfig(
        provider=provider,
        model=cfg_kw.pop("model", "test-model"),
        api_key="test-key",
        base_url="https://api.example.com",
        max_attempts=cfg_kw.pop("max_attempts", 2),
        timeout_seconds=cfg_kw.pop("timeout_seconds", 5.0),
    )
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=cfg.base_url)
    cls = AnthropicClient if provider is LLMProvider.ANTHROPIC else OpenAIClient
    return cls(cfg, http), http


@pytest.mark.asyncio
async def test_anthropic_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/messages"
        assert request.headers["x-api-key"] == "test-key"
        return httpx.Response(
            200,
            json={
                "model": "anthropic-model-x",
                "content": [{"type": "text", "text": "PATCHED CODE"}],
                "usage": {"input_tokens": 12, "output_tokens": 5},
            },
        )

    client, http = _client(handler)
    try:
        out = await client.complete(system="s", user="u")
        assert out.text == "PATCHED CODE"
        assert out.model == "anthropic-model-x"
        assert out.input_tokens == 12
    finally:
        await http.aclose()


@pytest.mark.asyncio
async def test_openai_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer test-key"
        return httpx.Response(
            200,
            json={"model": "gpt-x", "choices": [{"message": {"content": "FIXED"}}], "usage": {}},
        )

    client, http = _client(handler, provider=LLMProvider.OPENAI)
    try:
        out = await client.complete(system="s", user="u")
        assert out.text == "FIXED"
        assert out.provider is LLMProvider.OPENAI
    finally:
        await http.aclose()


@pytest.mark.asyncio
async def test_malformed_response_raises() -> None:
    client, http = _client(lambda r: httpx.Response(200, json={"unexpected": True}))
    try:
        with pytest.raises(LLMResponseError):
            await client.complete(system="s", user="u")
    finally:
        await http.aclose()


@pytest.mark.asyncio
async def test_empty_text_raises() -> None:
    client, http = _client(lambda r: httpx.Response(200, json={"content": [], "model": "m"}))
    try:
        with pytest.raises(LLMResponseError):
            await client.complete(system="s", user="u")
    finally:
        await http.aclose()


@pytest.mark.asyncio
async def test_terminal_4xx_not_retried() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(400, text="bad request")

    client, http = _client(handler, max_attempts=3)
    try:
        with pytest.raises(LLMResponseError):
            await client.complete(system="s", user="u")
        assert calls == 1
    finally:
        await http.aclose()


@pytest.mark.asyncio
async def test_retryable_5xx_then_success(monkeypatch) -> None:
    monkeypatch.setattr(llm.asyncio, "sleep", _noop_sleep)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, text="try later")
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}], "model": "m"})

    client, http = _client(handler, max_attempts=3)
    try:
        out = await client.complete(system="s", user="u")
        assert out.text == "ok"
        assert calls == 2
    finally:
        await http.aclose()


@pytest.mark.asyncio
async def test_retry_exhaustion_raises_transport_error(monkeypatch) -> None:
    monkeypatch.setattr(llm.asyncio, "sleep", _noop_sleep)

    client, http = _client(lambda r: httpx.Response(503), max_attempts=2)
    try:
        with pytest.raises(LLMTransportError):
            await client.complete(system="s", user="u")
    finally:
        await http.aclose()


@pytest.mark.asyncio
async def test_timeout_is_retried_then_raises(monkeypatch) -> None:
    monkeypatch.setattr(llm.asyncio, "sleep", _noop_sleep)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow")

    client, http = _client(handler, max_attempts=2)
    try:
        with pytest.raises(LLMTransportError):
            await client.complete(system="s", user="u")
    finally:
        await http.aclose()


@pytest.mark.asyncio
async def test_output_is_truncated(monkeypatch) -> None:
    huge = "x" * 40_000
    client, http = _client(
        lambda r: httpx.Response(200, json={"content": [{"type": "text", "text": huge}], "model": "m"})
    )
    try:
        out = await client.complete(system="s", user="u")
        assert len(out.text) < len(huge)
    finally:
        await http.aclose()


def test_provider_selection_from_env() -> None:
    cfg = LLMConfig.from_env({"DEVSECOPS_LLM_PROVIDER": "openai", "OPENAI_API_KEY": "k"})
    assert cfg.provider is LLMProvider.OPENAI and cfg.is_live is True


def test_unknown_provider_falls_back_to_null() -> None:
    cfg = LLMConfig.from_env({"DEVSECOPS_LLM_PROVIDER": "gemini"})
    assert cfg.provider is LLMProvider.NULL
    assert cfg.is_live is False


def test_missing_api_key_disables_live_client() -> None:
    cfg = LLMConfig.from_env({"DEVSECOPS_LLM_PROVIDER": "anthropic"})
    assert cfg.is_live is False
    assert build_llm_client(cfg) is None


def test_strip_code_fences() -> None:
    assert llm.strip_code_fences("```python\nx = 1\n```") == "x = 1"
    assert llm.strip_code_fences("no fences here") == "no fences here"


async def _noop_sleep(_seconds: float) -> None:
    return None
