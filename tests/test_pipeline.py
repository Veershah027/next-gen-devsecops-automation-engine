"""Orchestrator behaviour: waves, gate, metrics, remediation modes, failures."""

from __future__ import annotations

import asyncio

import pytest
from conftest import CLEAN_SOURCE, VULNERABLE_SOURCE

import llm
import main
from models import AgentStatus, AnalyzeRequest, PatchType, Severity, ValidationStatus


@pytest.fixture
def orchestrator(settings: main.Settings) -> main.PipelineOrchestrator:
    return main.PipelineOrchestrator(settings, main.LogBus())


async def _run(orch: main.PipelineOrchestrator, source: str, **kw: object):
    return await orch.analyze(AnalyzeRequest(source_code=source, **kw))  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_successful_analysis_reports_all_agents(orchestrator) -> None:
    resp = await _run(orchestrator, VULNERABLE_SOURCE)
    assert {r.agent.value for r in resp.agent_reports} == {
        "ast_structural_parser",
        "security_pattern_scanner",
        "remediation_generator",
    }
    assert all(r.status is AgentStatus.COMPLETED for r in resp.agent_reports)


@pytest.mark.asyncio
async def test_gate_fails_on_high_severity(orchestrator) -> None:
    resp = await _run(orchestrator, VULNERABLE_SOURCE)
    assert resp.gate_passed is False
    assert resp.metrics.highest_severity in (Severity.HIGH, Severity.CRITICAL)


@pytest.mark.asyncio
async def test_gate_passes_on_clean_source(orchestrator) -> None:
    resp = await _run(orchestrator, CLEAN_SOURCE)
    assert resp.gate_passed is True
    assert resp.metrics.total_findings == 0
    assert resp.patches == ()
    assert resp.remediation_mode == "none"


@pytest.mark.asyncio
async def test_remediation_can_be_disabled(orchestrator) -> None:
    resp = await _run(orchestrator, VULNERABLE_SOURCE, enable_remediation=False)
    assert resp.patches == ()
    assert resp.remediation_mode == "none"
    assert {r.agent.value for r in resp.agent_reports} == {
        "ast_structural_parser",
        "security_pattern_scanner",
    }


@pytest.mark.asyncio
async def test_template_patches_are_verified(orchestrator) -> None:
    resp = await _run(orchestrator, VULNERABLE_SOURCE)
    assert resp.remediation_mode == "template"
    assert resp.patches
    for patch in resp.patches:
        assert patch.source == "template"
        if patch.patch_type is PatchType.SNIPPET:
            assert patch.validation.status is ValidationStatus.VALIDATED
            assert patch.unified_diff and patch.unified_diff.startswith("---")


@pytest.mark.asyncio
async def test_metrics_counts_match_findings(orchestrator) -> None:
    resp = await _run(orchestrator, VULNERABLE_SOURCE)
    assert sum(resp.metrics.by_severity.values()) == resp.metrics.total_findings
    assert sum(resp.metrics.by_category.values()) == resp.metrics.total_findings
    assert len(resp.findings) == resp.metrics.total_findings


@pytest.mark.asyncio
async def test_llm_remediation_path(orchestrator) -> None:
    class FakeLLM:
        config = None

        async def complete(self, *, system: str, user: str) -> llm.LLMCompletion:
            return llm.LLMCompletion(
                text='import os\nAPI_KEY = os.environ["API_KEY"]\n',
                model="fake-1",
                provider=llm.LLMProvider.ANTHROPIC,
            )

    orchestrator.llm_client = FakeLLM()
    resp = await _run(orchestrator, 'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    assert resp.remediation_mode == "llm"
    patch = resp.patches[0]
    assert patch.source == "llm"
    assert patch.provider == "anthropic" and patch.model == "fake-1"
    assert patch.validation.status is ValidationStatus.VALIDATED
    assert "```" not in patch.suggested_code


@pytest.mark.asyncio
async def test_llm_failure_falls_back_to_template(orchestrator) -> None:
    class BrokenLLM:
        config = None

        async def complete(self, *, system: str, user: str) -> llm.LLMCompletion:
            raise llm.LLMTransportError("provider down")

    orchestrator.llm_client = BrokenLLM()
    resp = await _run(orchestrator, 'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    assert resp.remediation_mode == "template"
    assert resp.patches[0].source == "template"


@pytest.mark.asyncio
async def test_llm_rejected_patch_falls_back_to_template(orchestrator) -> None:
    class BadPatchLLM:
        config = None

        async def complete(self, *, system: str, user: str) -> llm.LLMCompletion:
            return llm.LLMCompletion(text="def broken(:\n", model="m", provider=llm.LLMProvider.OPENAI)

    orchestrator.llm_client = BadPatchLLM()
    resp = await _run(orchestrator, 'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    assert resp.patches[0].source == "template"


@pytest.mark.asyncio
async def test_pipeline_overload_raises(settings: main.Settings) -> None:
    from models import PipelineOverloadedError

    tight = settings.model_copy(update={"max_concurrent_pipelines": 1})
    orch = main.PipelineOrchestrator(tight, main.LogBus())

    release = asyncio.Event()
    original = orch._run

    async def slow_run(request, origin):  # type: ignore[no-untyped-def]
        await release.wait()
        return await original(request, origin)

    orch._run = slow_run  # type: ignore[assignment]
    first = asyncio.create_task(_run(orch, CLEAN_SOURCE))
    await asyncio.sleep(0.05)
    with pytest.raises(PipelineOverloadedError):
        await _run(orch, CLEAN_SOURCE)
    release.set()
    await first


@pytest.mark.asyncio
async def test_pipeline_timeout_raises(settings: main.Settings) -> None:
    from models import PipelineTimeoutError

    fast = settings.model_copy(update={"pipeline_timeout_seconds": 0.01})
    orch = main.PipelineOrchestrator(fast, main.LogBus())

    async def slow_run(request, origin):  # type: ignore[no-untyped-def]
        await asyncio.sleep(1)

    orch._run = slow_run  # type: ignore[assignment]
    with pytest.raises(PipelineTimeoutError):
        await _run(orch, CLEAN_SOURCE)


@pytest.mark.asyncio
async def test_agent_failure_is_isolated(orchestrator, monkeypatch) -> None:
    import scanner

    def boom(*a: object, **k: object) -> list:
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(scanner, "scan_source", boom)
    resp = await _run(orchestrator, VULNERABLE_SOURCE)
    scanner_report = next(r for r in resp.agent_reports if r.agent.value == "security_pattern_scanner")
    assert scanner_report.status is AgentStatus.FAILED
    assert resp.metrics.agents_failed == 1
    # the AST agent still ran and produced findings
    assert any(r.agent.value == "ast_structural_parser" and r.ok for r in resp.agent_reports)
