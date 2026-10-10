"""
providers.py — LLM provider adapters for the evaluator.

Anything with `.complete(attack) -> LLMResponse` can be audited. Three
implementations ship here, selected by environment variables:

  LLM_PROVIDER=mock       (default) seeded MockLLM, no network, no API key
  LLM_PROVIDER=anthropic  Anthropic Messages API   (needs ANTHROPIC_API_KEY)
  LLM_PROVIDER=openai     OpenAI-compatible chat completions API
                          (needs OPENAI_API_KEY and LLM_MODEL; OPENAI_BASE_URL
                          points it at any compatible server)

  LLM_MODEL               model name; defaults to DEFAULT_ANTHROPIC_MODEL for
                          the anthropic provider

The `anthropic` / `openai` SDKs are optional and imported only when that
provider is selected.
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping
from typing import Any, Protocol

from .attack_library import AttackPrompt
from .mock_llm import LLMResponse, MockLLM

DEFAULT_ANTHROPIC_MODEL = "claude-haiku-5-5"
DEFAULT_MAX_TOKENS = 1024


class LLMProvider(Protocol):
    """What the evaluator needs from a model under audit."""

    def complete(self, attack: AttackPrompt) -> LLMResponse: ...


class ProviderConfigError(ValueError):
    """The selected provider cannot be built from the current configuration."""


class ProviderError(RuntimeError):
    """The provider call failed (network, auth, rate limit, bad response)."""


def _elapsed_ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


class AnthropicProvider:
    """Sends each attack prompt as a single user message to the Messages API."""

    def __init__(
        self,
        model: str = DEFAULT_ANTHROPIC_MODEL,
        client: Any = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ):
        if client is None:  # pragma: no cover - needs the optional SDK
            try:
                import anthropic
            except ImportError as e:
                raise ProviderConfigError(
                    "LLM_PROVIDER=anthropic needs the SDK: pip install anthropic"
                ) from e
            client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
        self._client = client
        self._model = model
        self._max_tokens = max_tokens

    def complete(self, attack: AttackPrompt) -> LLMResponse:
        t0 = time.perf_counter()
        try:
            message = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                messages=[{"role": "user", "content": attack.template}],
            )
            text = "".join(
                block.text
                for block in message.content
                if getattr(block, "type", None) == "text"
            )
            tokens = message.usage.input_tokens + message.usage.output_tokens
        except Exception as e:
            raise ProviderError(f"Anthropic request failed: {e}") from e
        return LLMResponse(
            prompt=attack.template,
            response_text=text,
            is_simulated_failure=False,
            model_name=self._model,
            latency_ms=_elapsed_ms(t0),
            tokens_used=tokens,
        )


class OpenAICompatibleProvider:
    """Sends each attack prompt to a chat-completions endpoint."""

    def __init__(
        self,
        model: str,
        client: Any = None,
        base_url: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ):
        if client is None:  # pragma: no cover - needs the optional SDK
            try:
                import openai
            except ImportError as e:
                raise ProviderConfigError(
                    "LLM_PROVIDER=openai needs the SDK: pip install openai"
                ) from e
            client = openai.OpenAI(base_url=base_url)  # reads OPENAI_API_KEY
        self._client = client
        self._model = model
        self._max_tokens = max_tokens

    def complete(self, attack: AttackPrompt) -> LLMResponse:
        t0 = time.perf_counter()
        try:
            completion = self._client.chat.completions.create(
                model=self._model,
                max_tokens=self._max_tokens,
                messages=[{"role": "user", "content": attack.template}],
            )
            text = completion.choices[0].message.content or ""
            usage = completion.usage
            tokens = usage.total_tokens if usage else 0
        except Exception as e:
            raise ProviderError(f"OpenAI-compatible request failed: {e}") from e
        return LLMResponse(
            prompt=attack.template,
            response_text=text,
            is_simulated_failure=False,
            model_name=self._model,
            latency_ms=_elapsed_ms(t0),
            tokens_used=tokens,
        )


def build_provider(
    seed: int = 42,
    env: Mapping[str, str] | None = None,
    client: Any = None,
) -> LLMProvider:
    """
    Build the provider selected by LLM_PROVIDER (default: seeded mock).

    `seed` only affects the mock. `client` injects a pre-built SDK client
    (used by tests); when omitted the SDK builds one from the environment.
    """
    env = os.environ if env is None else env
    name = (env.get("LLM_PROVIDER") or "mock").strip().lower()
    model = (env.get("LLM_MODEL") or "").strip()

    if name == "mock":
        return MockLLM(global_seed=seed)

    if name == "anthropic":
        if not env.get("ANTHROPIC_API_KEY"):
            raise ProviderConfigError(
                "LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set"
            )
        return AnthropicProvider(model=model or DEFAULT_ANTHROPIC_MODEL, client=client)

    if name == "openai":
        if not env.get("OPENAI_API_KEY"):
            raise ProviderConfigError(
                "LLM_PROVIDER=openai but OPENAI_API_KEY is not set"
            )
        if not model:
            raise ProviderConfigError("LLM_PROVIDER=openai requires LLM_MODEL")
        return OpenAICompatibleProvider(
            model=model, client=client, base_url=env.get("OPENAI_BASE_URL") or None
        )

    raise ProviderConfigError(
        f"Unknown LLM_PROVIDER '{name}' (expected mock, anthropic or openai)"
    )
