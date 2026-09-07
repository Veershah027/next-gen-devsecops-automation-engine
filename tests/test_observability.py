"""LogBus pub/sub fan-out (the mechanism behind the SSE telemetry endpoint)."""

from __future__ import annotations

import asyncio

import pytest

from main import LogBus, LogEvent, PipelineLogger


@pytest.mark.asyncio
async def test_subscriber_receives_published_event() -> None:
    bus = LogBus()
    async with bus.subscribe() as queue:
        await bus.publish(LogEvent(message="hello", agent="test"))
        event = await asyncio.wait_for(queue.get(), timeout=1)
        assert event.message == "hello"
        assert event.agent == "test"


@pytest.mark.asyncio
async def test_fan_out_to_multiple_subscribers() -> None:
    bus = LogBus()
    async with bus.subscribe() as a, bus.subscribe() as b:
        assert bus.subscriber_count == 2
        await bus.publish(LogEvent(message="broadcast"))
        assert (await asyncio.wait_for(a.get(), 1)).message == "broadcast"
        assert (await asyncio.wait_for(b.get(), 1)).message == "broadcast"
    assert bus.subscriber_count == 0


@pytest.mark.asyncio
async def test_slow_consumer_drops_oldest_and_never_blocks() -> None:
    bus = LogBus(per_subscriber_buffer=4)
    async with bus.subscribe() as queue:
        for i in range(20):
            await asyncio.wait_for(bus.publish(LogEvent(message=str(i))), timeout=1)
        assert queue.qsize() == 4
        newest = [(await queue.get()).message for _ in range(4)]
        assert newest == ["16", "17", "18", "19"]


@pytest.mark.asyncio
async def test_pipeline_logger_binds_analysis_id() -> None:
    bus = LogBus()
    async with bus.subscribe() as queue:
        await PipelineLogger(bus, "abc123").emit("step done", agent="agent-x", level="WARNING")
        event = await asyncio.wait_for(queue.get(), 1)
        assert event.analysis_id == "abc123"
        assert event.level == "WARNING"
        assert "step done" in event.to_sse_data()


@pytest.mark.asyncio
async def test_publish_with_no_subscribers_is_safe() -> None:
    await LogBus().publish(LogEvent(message="into the void"))
