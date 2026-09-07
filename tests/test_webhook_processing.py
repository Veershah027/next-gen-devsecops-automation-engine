"""WebhookProcessor: fetch changed files from a mocked GitHub and run the pipeline."""

from __future__ import annotations

import httpx
import pytest
from conftest import VULNERABLE_SOURCE

import main
from main import PipelineOrchestrator, WebhookPlan, WebhookProcessor


@pytest.fixture
def orchestrator(settings: main.Settings) -> PipelineOrchestrator:
    return PipelineOrchestrator(settings, main.LogBus())


def _processor(settings: main.Settings, orch: PipelineOrchestrator, handler) -> WebhookProcessor:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return WebhookProcessor(settings, orch, main.LogBus(), http)


@pytest.mark.asyncio
async def test_push_files_are_fetched_and_analyzed(settings, orchestrator) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "raw.githubusercontent.com"
        assert request.url.path.endswith("app.py")
        return httpx.Response(200, content=VULNERABLE_SOURCE.encode())

    proc = _processor(settings, orchestrator, handler)
    plan = WebhookPlan("push", "octo/demo", "refs/heads/main", "a" * 40, None, ("src/app.py",), ())
    try:
        await proc.process("delivery-1", plan)
    finally:
        await proc._http.aclose()

    assert len(proc.deliveries) == 1
    record = proc.deliveries[0]
    assert record.files[0].analyzed is True
    assert record.files[0].total_findings > 0
    assert record.gate_passed is False  # the vulnerable sample fails the gate


@pytest.mark.asyncio
async def test_upstream_404_is_recorded_as_skipped(settings, orchestrator) -> None:
    proc = _processor(settings, orchestrator, lambda r: httpx.Response(404))
    plan = WebhookPlan("push", "octo/demo", "main", "b" * 40, None, ("missing.py",), ())
    try:
        await proc.process("delivery-2", plan)
    finally:
        await proc._http.aclose()

    result = proc.deliveries[0].files[0]
    assert result.analyzed is False
    assert result.error and "not found" in result.error


@pytest.mark.asyncio
async def test_oversized_upstream_file_is_skipped(settings, orchestrator) -> None:
    big = b"# comment\n" * 200_000  # ~1.9 MB, over the 512 KiB cap

    proc = _processor(settings, orchestrator, lambda r: httpx.Response(200, content=big))
    plan = WebhookPlan("push", "o/r", "main", "c" * 40, None, ("huge.py",), ())
    try:
        await proc.process("delivery-3", plan)
    finally:
        await proc._http.aclose()

    result = proc.deliveries[0].files[0]
    assert result.analyzed is False
    assert result.error and "exceeds" in result.error


@pytest.mark.asyncio
async def test_pull_request_file_list_resolved_from_api(settings, orchestrator) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            return httpx.Response(
                200,
                json=[
                    {"filename": "src/changed.py", "status": "modified"},
                    {"filename": "docs/readme.md", "status": "added"},
                    {"filename": "src/gone.py", "status": "removed"},
                ],
            )
        return httpx.Response(200, content=b"x = 1\n")

    proc = _processor(settings, orchestrator, handler)
    plan = WebhookPlan("pull_request", "octo/demo", "feature", "d" * 40, 42, (), ())
    try:
        await proc.process("delivery-4", plan)
    finally:
        await proc._http.aclose()

    analyzed_names = {f.filename for f in proc.deliveries[0].files}
    assert analyzed_names == {"src/changed.py"}  # .md skipped, removed file skipped


@pytest.mark.asyncio
async def test_processor_never_raises_on_transport_error(settings, orchestrator) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network down")

    proc = _processor(settings, orchestrator, handler)
    plan = WebhookPlan("push", "o/r", "main", "e" * 40, None, ("a.py",), ())
    try:
        await proc.process("delivery-5", plan)  # must not raise
    finally:
        await proc._http.aclose()
    assert proc.deliveries[0].files[0].analyzed is False
