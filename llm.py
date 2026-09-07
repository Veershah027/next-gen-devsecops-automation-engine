"""Provider-agnostic asynchronous LLM client for on-the-fly remediation.

The engine treats "generate a secure patch" as a call to an *upstream model
pipeline*. This module is the seam:

* ``LLMConfig``     — 12-factor configuration resolved from the environment.
* ``LLMClient``     — abstract async contract (``complete``) with transport
                      retry / backoff baked in.
* ``AnthropicClient`` / ``OpenAIClient`` — concrete providers speaking raw HTTP
                      (no vendor SDK, so the dependency surface stays tiny and
                      auditable).
* ``build_llm_client`` — factory returning a live client, or ``None`` when no
                      credentials are configured so the caller can fall back to
                      the deterministic template engine.

Security posture
----------------
* API keys are read from the environment only and never logged.
* TLS verification is always on; redirects are disabled.
* Only the single configured provider ``base_url`` is ever contacted.
* Callers are expected to redact secrets from any code they send upstream
  (``main.mask_secrets`` does this before a prompt is built).
"""

from __future__ import annotations

import abc
import asyncio
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Final

import httpx

logger = logging.getLogger("devsecops-automation-engine.llm")

_USER_AGENT: Final[str] = "devsecops-automation-engine/1.1 (+https://github.com)"
_ANTHROPIC_VERSION: Final[str] = "2023-06-01"
_MAX_RESPONSE_CHARS: Final[int] = 24_000
_RETRYABLE_STATUS: Final[frozenset[int]] = frozenset({408, 409, 425, 429, 500, 502, 503, 504})


class LLMProvider(str, Enum):
    """Selectable upstream model providers."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    NULL = "null"  # explicit "no live model configured"


class LLMError(RuntimeError):
    """Base class for every failure originating in this module."""


class LLMUnavailable(LLMError):
    """No live client is configured (missing key / provider disabled)."""


class LLMTransportError(LLMError):
    """Network failure or retryable status persisted past the retry budget."""


class LLMResponseError(LLMError):
    """The provider returned a terminal error or an unparseable body."""


class _RetryableStatus(LLMError):
    def __init__(self, status_code: int, retry_after: float | None = None) -> None:
        super().__init__(f"retryable HTTP status {status_code}")
        self.status_code = status_code
        self.retry_after = retry_after


_PROVIDER_DEFAULTS: Final[dict[LLMProvider, tuple[str, str, str]]] = {
    #                      base_url                       default model          native key var
    LLMProvider.ANTHROPIC: ("https://api.anthropic.com", "claude-sonnet-5", "ANTHROPIC_API_KEY"),
    LLMProvider.OPENAI: ("https://api.openai.com", "gpt-4o-mini", "OPENAI_API_KEY"),
    LLMProvider.NULL: ("", "", ""),
}


@dataclass(frozen=True, slots=True)
class LLMConfig:
    """Immutable LLM configuration."""

    provider: LLMProvider
    model: str
    api_key: str | None
    base_url: str
    timeout_seconds: float = 25.0
    max_output_tokens: int = 1_024
    max_attempts: int = 2

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> LLMConfig:
        env = os.environ if env is None else env
        raw_provider = env.get("DEVSECOPS_LLM_PROVIDER", "null").strip().lower()
        try:
            provider = LLMProvider(raw_provider)
        except ValueError:
            logger.warning("unknown DEVSECOPS_LLM_PROVIDER=%r; falling back to 'null'", raw_provider)
            provider = LLMProvider.NULL

        base_default, model_default, native_key_var = _PROVIDER_DEFAULTS[provider]
        api_key = env.get("DEVSECOPS_LLM_API_KEY") or (env.get(native_key_var) if native_key_var else None)
        return cls(
            provider=provider,
            model=env.get("DEVSECOPS_LLM_MODEL", "").strip() or model_default,
            api_key=(api_key or "").strip() or None,
            base_url=(env.get("DEVSECOPS_LLM_BASE_URL", "").strip() or base_default).rstrip("/"),
            timeout_seconds=_env_float(env, "DEVSECOPS_LLM_TIMEOUT_SECONDS", 25.0, lo=1.0, hi=120.0),
            max_output_tokens=_env_int(env, "DEVSECOPS_LLM_MAX_OUTPUT_TOKENS", 1_024, lo=64, hi=8_192),
            max_attempts=_env_int(env, "DEVSECOPS_LLM_MAX_ATTEMPTS", 2, lo=1, hi=5),
        )

    @property
    def is_live(self) -> bool:
        return (
            self.provider is not LLMProvider.NULL
            and bool(self.api_key)
            and self.base_url.startswith("https://")
        )

    def describe(self) -> str:
        return (
            f"provider={self.provider.value} model={self.model} "
            f"base_url={self.base_url or '-'} key={'set' if self.api_key else 'unset'}"
        )


def _env_float(env: Mapping[str, str], key: str, default: float, *, lo: float, hi: float) -> float:
    try:
        return min(hi, max(lo, float(env.get(key, default))))
    except (TypeError, ValueError):
        return default


def _env_int(env: Mapping[str, str], key: str, default: int, *, lo: int, hi: int) -> int:
    try:
        return min(hi, max(lo, int(env.get(key, default))))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True, slots=True)
class LLMCompletion:
    """A single successful model response."""

    text: str
    model: str
    provider: LLMProvider
    input_tokens: int | None = None
    output_tokens: int | None = None


class LLMClient(abc.ABC):
    """Abstract async client. Subclasses implement one HTTP round-trip."""

    def __init__(self, config: LLMConfig, http: httpx.AsyncClient) -> None:
        self._config = config
        self._http = http

    @property
    def config(self) -> LLMConfig:
        return self._config

    async def complete(self, *, system: str, user: str) -> LLMCompletion:
        """Call the provider with bounded exponential-backoff retries."""

        last_error: Exception | None = None
        for attempt in range(1, self._config.max_attempts + 1):
            try:
                completion = await self._request(system, user)
                if len(completion.text) > _MAX_RESPONSE_CHARS:
                    completion = LLMCompletion(
                        text=completion.text[:_MAX_RESPONSE_CHARS],
                        model=completion.model,
                        provider=completion.provider,
                        input_tokens=completion.input_tokens,
                        output_tokens=completion.output_tokens,
                    )
                return completion
            except LLMResponseError:
                raise  # terminal - do not retry
            except (_RetryableStatus, httpx.TransportError, httpx.TimeoutException) as exc:
                last_error = exc
                retry_after = getattr(exc, "retry_after", None)
                delay = retry_after if retry_after is not None else min(2.0 ** (attempt - 1), 8.0)
                logger.warning(
                    "llm call attempt %d/%d failed (%s); retrying in %.1fs",
                    attempt,
                    self._config.max_attempts,
                    type(exc).__name__,
                    delay,
                )
                if attempt < self._config.max_attempts:
                    await asyncio.sleep(delay)
        raise LLMTransportError(f"LLM call failed after {self._config.max_attempts} attempt(s): {last_error}")

    @abc.abstractmethod
    async def _request(self, system: str, user: str) -> LLMCompletion:
        raise NotImplementedError


class AnthropicClient(LLMClient):
    """Anthropic Messages API (``POST /v1/messages``)."""

    async def _request(self, system: str, user: str) -> LLMCompletion:
        response = await self._http.post(
            f"{self._config.base_url}/v1/messages",
            headers={
                "x-api-key": self._config.api_key or "",
                "anthropic-version": _ANTHROPIC_VERSION,
                "content-type": "application/json",
                "user-agent": _USER_AGENT,
            },
            json={
                "model": self._config.model,
                "max_tokens": self._config.max_output_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        _raise_for_status(response)
        try:
            body = response.json()
            blocks = body["content"]
            text = "".join(block.get("text", "") for block in blocks if block.get("type") == "text").strip()
            usage = body.get("usage") or {}
        except (ValueError, KeyError, TypeError) as exc:
            raise LLMResponseError(f"unexpected Anthropic response shape: {exc}") from exc
        if not text:
            raise LLMResponseError("Anthropic response contained no text content")
        return LLMCompletion(
            text=text,
            model=str(body.get("model", self._config.model)),
            provider=LLMProvider.ANTHROPIC,
            input_tokens=usage.get("input_tokens"),
            output_tokens=usage.get("output_tokens"),
        )


class OpenAIClient(LLMClient):
    """OpenAI Chat Completions API (``POST /v1/chat/completions``)."""

    async def _request(self, system: str, user: str) -> LLMCompletion:
        response = await self._http.post(
            f"{self._config.base_url}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {self._config.api_key or ''}",
                "content-type": "application/json",
                "user-agent": _USER_AGENT,
            },
            json={
                "model": self._config.model,
                "max_tokens": self._config.max_output_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        _raise_for_status(response)
        try:
            body = response.json()
            text = str(body["choices"][0]["message"]["content"]).strip()
            usage = body.get("usage") or {}
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMResponseError(f"unexpected OpenAI response shape: {exc}") from exc
        if not text:
            raise LLMResponseError("OpenAI response contained no message content")
        return LLMCompletion(
            text=text,
            model=str(body.get("model", self._config.model)),
            provider=LLMProvider.OPENAI,
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
        )


def _raise_for_status(response: httpx.Response) -> None:
    if response.status_code < 400:
        return
    if response.status_code in _RETRYABLE_STATUS:
        header = response.headers.get("retry-after", "")
        retry_after: float | None = None
        if header.replace(".", "", 1).isdigit():
            retry_after = min(30.0, float(header))
        raise _RetryableStatus(response.status_code, retry_after)
    snippet = response.text[:200].replace("\n", " ")
    raise LLMResponseError(f"provider returned HTTP {response.status_code}: {snippet}")


def build_http_client(config: LLMConfig) -> httpx.AsyncClient:
    """An ``httpx`` client hardened for talking to exactly one provider."""

    return httpx.AsyncClient(
        base_url=config.base_url,
        timeout=httpx.Timeout(config.timeout_seconds, connect=min(10.0, config.timeout_seconds)),
        follow_redirects=False,
        headers={"user-agent": _USER_AGENT},
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    )


def build_llm_client(config: LLMConfig, *, http: httpx.AsyncClient | None = None) -> LLMClient | None:
    """Return a concrete client, or ``None`` when no live model is configured."""

    if not config.is_live:
        logger.info("live LLM disabled; using deterministic fallback (%s)", config.describe())
        return None
    http = http or build_http_client(config)
    if config.provider is LLMProvider.ANTHROPIC:
        client: LLMClient = AnthropicClient(config, http)
    elif config.provider is LLMProvider.OPENAI:
        client = OpenAIClient(config, http)
    else:  # pragma: no cover - guarded by is_live
        return None
    logger.info("live LLM enabled (%s)", config.describe())
    return client


def strip_code_fences(text: str) -> str:
    """Remove a single ```lang ... ``` wrapper a model may add around code."""

    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if len(lines) >= 2 and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1]).strip()
    return stripped.removeprefix("```").strip()
