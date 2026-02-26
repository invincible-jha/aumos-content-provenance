"""Unit tests for the C2PA client adapter."""

import hashlib

import pytest

from aumos_content_provenance.adapters.c2pa_client import C2PAClient


@pytest.fixture
def client() -> C2PAClient:
    """C2PAClient in stub mode (no SDK required)."""
    return C2PAClient(signing_key_path="", cert_chain_path="")


@pytest.mark.asyncio
async def test_stub_sign_returns_manifest(client: C2PAClient) -> None:
    """Stub sign should return a well-formed manifest dict."""
    content = b"test content for C2PA signing"

    manifest = await client.sign_content(
        content_bytes=content,
        content_type="text/plain",
        claim_generator="AumOS/1.0",
        assertions=[{"label": "test", "data": {}}],
    )

    assert manifest["schema"] == "c2pa_manifest_v2"
    assert manifest["stub_mode"] is True
    assert "content_hash" in manifest
    assert manifest["content_hash"]["alg"] == "sha256"
    assert manifest["content_hash"]["value"] == hashlib.sha256(content).hexdigest()


@pytest.mark.asyncio
async def test_stub_sign_includes_claim_generator(client: C2PAClient) -> None:
    """Stub manifest should include the claim_generator."""
    manifest = await client.sign_content(
        content_bytes=b"content",
        content_type="image/jpeg",
        claim_generator="AumOS/1.0 (tenant:test)",
        assertions=[],
    )

    assert manifest["claim_generator"] == "AumOS/1.0 (tenant:test)"


@pytest.mark.asyncio
async def test_verify_stub_manifest_with_matching_content(client: C2PAClient) -> None:
    """Stub manifest should verify successfully when content hash matches."""
    content = b"original content"
    manifest = await client.sign_content(
        content_bytes=content,
        content_type="text/plain",
        claim_generator="AumOS/1.0",
        assertions=[],
    )

    is_valid, reason = await client.verify_manifest(manifest=manifest, content_bytes=content)

    assert is_valid is True
    assert "verified" in reason.lower() or "stub" in reason.lower()


@pytest.mark.asyncio
async def test_verify_returns_false_on_hash_mismatch(client: C2PAClient) -> None:
    """Verification should fail when content does not match stored hash."""
    original_content = b"original content"
    tampered_content = b"tampered content"

    manifest = await client.sign_content(
        content_bytes=original_content,
        content_type="text/plain",
        claim_generator="AumOS/1.0",
        assertions=[],
    )

    is_valid, reason = await client.verify_manifest(manifest=manifest, content_bytes=tampered_content)

    assert is_valid is False
    assert "hash mismatch" in reason.lower()


@pytest.mark.asyncio
async def test_stub_sign_produces_unique_manifest_ids(client: C2PAClient) -> None:
    """Each stub signing should produce a unique manifest_id."""
    content = b"content"

    manifest1 = await client.sign_content(
        content_bytes=content,
        content_type="text/plain",
        claim_generator="AumOS/1.0",
        assertions=[],
    )
    manifest2 = await client.sign_content(
        content_bytes=content,
        content_type="text/plain",
        claim_generator="AumOS/1.0",
        assertions=[],
    )

    assert manifest1["manifest_id"] != manifest2["manifest_id"]
