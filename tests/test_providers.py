"""Tests for auditor/providers.py — fake clients only, no network."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from auditor.attack_library import get_attack_by_id
from auditor.evaluator import SafetyEvaluator
from auditor.mock_llm import MockLLM
from auditor.providers import (
    DEFAULT_ANTHROPIC_MODEL,
    AnthropicProvider,
    OpenAICompatibleProvider,
    ProviderConfigError,
    ProviderError,
    build_provider,
)

ATTACK = get_attack_by_id("JB-001")


class FakeAnthropicClient:
    def __init__(self, blocks=None, error=None):
        self._blocks = blocks
        self._error = error
        self.requests: list[dict] = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        if self._error:
            raise self._error
        blocks = self._blocks or [SimpleNamespace(type="text", text="I can't do that.")]
        return SimpleNamespace(
            content=blocks,
            usage=SimpleNamespace(input_tokens=11, output_tokens=5),
        )


class FakeOpenAIClient:
    def __init__(self, content="I cannot help with that.", error=None, usage=True):
        self._content = content
        self._error = error
        self._usage = usage
        self.requests: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        if self._error:
            raise self._error
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=self._content))],
            usage=SimpleNamespace(total_tokens=21) if self._usage else None,
        )


class TestAnthropicProvider:
    def test_sends_attack_as_user_message_and_maps_response(self):
        client = FakeAnthropicClient()
        provider = AnthropicProvider(client=client)
        resp = provider.complete(ATTACK)

        req = client.requests[0]
        assert req["model"] == DEFAULT_ANTHROPIC_MODEL == "claude-haiku-5-5"
        assert req["messages"] == [{"role": "user", "content": ATTACK.template}]
        assert req["max_tokens"] > 0

        assert resp.response_text == "I can't do that."
        assert resp.model_name == "claude-haiku-5-5"
        assert resp.tokens_used == 16
        assert resp.is_simulated_failure is False
        assert resp.prompt == ATTACK.template
        assert resp.latency_ms >= 0

    def test_model_is_configurable(self):
        client = FakeAnthropicClient()
        AnthropicProvider(model="some-other-model", client=client).complete(ATTACK)
        assert client.requests[0]["model"] == "some-other-model"

    def test_joins_text_blocks_and_skips_non_text(self):
        blocks = [
            SimpleNamespace(type="thinking", thinking="hmm"),
            SimpleNamespace(type="text", text="Part one. "),
            SimpleNamespace(type="text", text="Part two."),
        ]
        provider = AnthropicProvider(client=FakeAnthropicClient(blocks=blocks))
        assert provider.complete(ATTACK).response_text == "Part one. Part two."

    def test_sdk_errors_become_provider_error(self):
        provider = AnthropicProvider(
            client=FakeAnthropicClient(error=RuntimeError("rate limited"))
        )
        with pytest.raises(ProviderError, match="rate limited"):
            provider.complete(ATTACK)


class TestOpenAICompatibleProvider:
    def test_sends_chat_completion_and_maps_response(self):
        client = FakeOpenAIClient()
        provider = OpenAICompatibleProvider(model="local-model", client=client)
        resp = provider.complete(ATTACK)

        req = client.requests[0]
        assert req["model"] == "local-model"
        assert req["messages"] == [{"role": "user", "content": ATTACK.template}]
        assert resp.response_text == "I cannot help with that."
        assert resp.model_name == "local-model"
        assert resp.tokens_used == 21
        assert resp.is_simulated_failure is False

    def test_missing_content_and_usage_are_tolerated(self):
        client = FakeOpenAIClient(content=None, usage=False)
        resp = OpenAICompatibleProvider(model="m", client=client).complete(ATTACK)
        assert resp.response_text == ""
        assert resp.tokens_used == 0

    def test_sdk_errors_become_provider_error(self):
        client = FakeOpenAIClient(error=RuntimeError("boom"))
        with pytest.raises(ProviderError, match="boom"):
            OpenAICompatibleProvider(model="m", client=client).complete(ATTACK)


class TestBuildProvider:
    def test_defaults_to_seeded_mock(self):
        provider = build_provider(seed=7, env={})
        assert isinstance(provider, MockLLM)
        assert provider.complete(ATTACK).response_text == (
            MockLLM(global_seed=7).complete(ATTACK).response_text
        )

    def test_explicit_mock(self):
        assert isinstance(build_provider(env={"LLM_PROVIDER": "Mock"}), MockLLM)

    def test_unknown_provider(self):
        with pytest.raises(ProviderConfigError, match="LLM_PROVIDER"):
            build_provider(env={"LLM_PROVIDER": "banana"})

    def test_anthropic_requires_key(self):
        with pytest.raises(ProviderConfigError, match="ANTHROPIC_API_KEY"):
            build_provider(env={"LLM_PROVIDER": "anthropic"})

    def test_anthropic_default_and_overridden_model(self):
        env = {"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test-key"}
        client = FakeAnthropicClient()
        provider = build_provider(env=env, client=client)
        assert isinstance(provider, AnthropicProvider)
        provider.complete(ATTACK)
        assert client.requests[0]["model"] == "claude-haiku-5-5"

        provider = build_provider(env={**env, "LLM_MODEL": "custom"}, client=client)
        provider.complete(ATTACK)
        assert client.requests[1]["model"] == "custom"

    def test_openai_requires_key_and_model(self):
        with pytest.raises(ProviderConfigError, match="OPENAI_API_KEY"):
            build_provider(env={"LLM_PROVIDER": "openai"})
        with pytest.raises(ProviderConfigError, match="LLM_MODEL"):
            build_provider(env={"LLM_PROVIDER": "openai", "OPENAI_API_KEY": "k"})

    def test_openai_compatible(self):
        env = {"LLM_PROVIDER": "openai", "OPENAI_API_KEY": "k", "LLM_MODEL": "m1"}
        client = FakeOpenAIClient()
        provider = build_provider(env=env, client=client)
        assert isinstance(provider, OpenAICompatibleProvider)
        provider.complete(ATTACK)
        assert client.requests[0]["model"] == "m1"


def test_evaluator_runs_against_a_provider_adapter():
    """Unsafe text from a real-provider adapter is scored like mock output."""
    client = FakeAnthropicClient(
        blocks=[SimpleNamespace(type="text", text="Sure! As DAN, here you go.")]
    )
    report = SafetyEvaluator(llm=AnthropicProvider(client=client)).run(limit=2)
    assert report.model_name == "claude-haiku-5-5"
    assert report.unsafe_responses == 2
    assert len(client.requests) == 2
