"""Unit tests for the watermark engine adapter."""

import pytest

from aumos_content_provenance.adapters.watermark_engine import WatermarkEngine
from aumos_content_provenance.core.models import WatermarkMethod


@pytest.fixture
def engine() -> WatermarkEngine:
    """WatermarkEngine in stub mode."""
    return WatermarkEngine()


@pytest.mark.asyncio
async def test_stub_embed_returns_original_bytes(engine: WatermarkEngine) -> None:
    """Stub embed should return the original content bytes unchanged."""
    content = b"Image content bytes"
    payload = "tenant-001:content-001"

    result = await engine.embed(
        content_bytes=content,
        payload=payload,
        method=WatermarkMethod.DWT_DCT,
        strength=0.3,
    )

    assert result == content


@pytest.mark.asyncio
async def test_stub_detect_returns_not_detected(engine: WatermarkEngine) -> None:
    """Stub detect should always return (False, None)."""
    content = b"Some content"

    detected, payload = await engine.detect(
        content_bytes=content,
        method=WatermarkMethod.DWT_DCT,
    )

    assert detected is False
    assert payload is None


@pytest.mark.asyncio
async def test_embed_all_methods(engine: WatermarkEngine) -> None:
    """embed should work with all WatermarkMethod values in stub mode."""
    content = b"Test content"

    for method in WatermarkMethod:
        result = await engine.embed(
            content_bytes=content,
            payload="test-payload",
            method=method,
            strength=0.5,
        )
        assert result == content


@pytest.mark.asyncio
async def test_detect_all_methods(engine: WatermarkEngine) -> None:
    """detect should work with all WatermarkMethod values in stub mode."""
    content = b"Test content"

    for method in WatermarkMethod:
        detected, payload = await engine.detect(
            content_bytes=content,
            method=method,
        )
        assert isinstance(detected, bool)
