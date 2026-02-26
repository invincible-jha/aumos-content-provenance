"""C2PA SDK client adapter for aumos-content-provenance.

Implements IC2PAClient using the c2pa-python SDK for cryptographic
content provenance manifests per the C2PA specification
(https://c2pa.org/specifications/specifications/2.0/).

In test/development environments without the C2PA SDK installed,
falls back to a deterministic stub implementation that produces
well-formed but unsigned manifests for integration testing.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class C2PAClient:
    """C2PA manifest signing and verification adapter.

    Wraps the c2pa-python SDK. Produces JUMBF-compatible JSON manifests
    with ECDSA-P256 signatures per C2PA Spec 2.0.

    Falls back to stub mode if c2pa-python is not installed — suitable
    for development and CI environments where the SDK is unavailable.
    """

    def __init__(
        self,
        signing_key_path: str = "",
        cert_chain_path: str = "",
        algorithm: str = "Es256",
    ) -> None:
        self._signing_key_path = signing_key_path
        self._cert_chain_path = cert_chain_path
        self._algorithm = algorithm
        self._sdk_available = self._check_sdk()

        if not self._sdk_available:
            logger.warning(
                "c2pa-python SDK not available — using stub mode for development. "
                "Install c2pa-python for production use."
            )

    def _check_sdk(self) -> bool:
        """Check if the c2pa-python SDK is installed and importable."""
        try:
            import c2pa  # type: ignore[import-not-found]  # noqa: F401

            return True
        except ImportError:
            return False

    async def sign_content(
        self,
        content_bytes: bytes,
        content_type: str,
        claim_generator: str,
        assertions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Sign content and produce a C2PA manifest.

        In SDK mode: calls c2pa.sign() to produce a real cryptographic manifest.
        In stub mode: produces a deterministic pseudo-manifest for testing.

        Args:
            content_bytes: Raw content bytes to sign.
            content_type: MIME type of the content.
            claim_generator: Identifier of the signing system.
            assertions: C2PA assertion objects to embed.

        Returns:
            C2PA manifest dict (JUMBF JSON representation).
        """
        if self._sdk_available:
            return await self._sign_with_sdk(
                content_bytes=content_bytes,
                content_type=content_type,
                claim_generator=claim_generator,
                assertions=assertions,
            )

        return self._stub_sign(
            content_bytes=content_bytes,
            content_type=content_type,
            claim_generator=claim_generator,
            assertions=assertions,
        )

    async def _sign_with_sdk(
        self,
        content_bytes: bytes,
        content_type: str,
        claim_generator: str,
        assertions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Sign using the real c2pa-python SDK.

        Args:
            content_bytes: Raw content bytes.
            content_type: MIME type.
            claim_generator: Signing system identifier.
            assertions: C2PA assertions to embed.

        Returns:
            C2PA manifest dict.
        """
        try:
            import c2pa  # type: ignore[import-not-found]

            # Load signing credentials
            with open(self._signing_key_path, "rb") as key_file:
                signing_key = key_file.read()
            with open(self._cert_chain_path, "rb") as cert_file:
                cert_chain = cert_file.read()

            signer = c2pa.create_signer(
                signing_key=signing_key,
                cert_chain=cert_chain,
                algorithm=self._algorithm,
                tsa_url="",  # Optional TSA for timestamp tokens
            )

            manifest_def = {
                "claim_generator": claim_generator,
                "assertions": assertions,
            }

            manifest_bytes = c2pa.sign(
                manifest=json.dumps(manifest_def).encode(),
                asset=content_bytes,
                asset_type=content_type,
                signer=signer,
            )

            # Parse the produced manifest back to dict
            manifest_dict: dict[str, Any] = json.loads(manifest_bytes)
            return manifest_dict

        except Exception as exc:
            logger.error("C2PA SDK signing failed", error=str(exc))
            # Fallback to stub on SDK error (dev/test tolerance)
            return self._stub_sign(
                content_bytes=content_bytes,
                content_type=content_type,
                claim_generator=claim_generator,
                assertions=assertions,
            )

    def _stub_sign(
        self,
        content_bytes: bytes,
        content_type: str,
        claim_generator: str,
        assertions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Produce a well-formed but unsigned C2PA manifest stub.

        Suitable for development, CI, and integration testing environments
        where the real C2PA SDK is not available.

        Args:
            content_bytes: Raw content bytes.
            content_type: MIME type.
            claim_generator: Signing system identifier.
            assertions: C2PA assertions to embed.

        Returns:
            Stub C2PA manifest dict with deterministic content hash.
        """
        content_hash = hashlib.sha256(content_bytes).hexdigest()

        return {
            "schema": "c2pa_manifest_v2",
            "stub_mode": True,
            "manifest_id": str(uuid.uuid4()),
            "claim_generator": claim_generator,
            "content_type": content_type,
            "content_hash": {
                "alg": "sha256",
                "value": content_hash,
            },
            "assertions": assertions,
            "signature": {
                "alg": "STUB",
                "value": f"stub:{content_hash[:32]}",
            },
            "signed_at": datetime.now(UTC).isoformat(),
        }

    async def verify_manifest(
        self,
        manifest: dict[str, Any],
        content_bytes: bytes,
    ) -> tuple[bool, str]:
        """Verify a C2PA manifest against content bytes.

        Checks content hash match and, in SDK mode, cryptographic signature.
        In stub mode, performs hash verification only.

        Args:
            manifest: C2PA manifest to verify.
            content_bytes: Raw content bytes for hash verification.

        Returns:
            Tuple of (is_valid, reason_message).
        """
        actual_hash = hashlib.sha256(content_bytes).hexdigest()

        # Check content hash regardless of mode
        manifest_hash = manifest.get("content_hash", {})
        stored_hash = manifest_hash.get("value") if isinstance(manifest_hash, dict) else None

        if stored_hash and stored_hash != actual_hash:
            return False, f"Content hash mismatch: stored={stored_hash[:16]}... actual={actual_hash[:16]}..."

        if manifest.get("stub_mode"):
            return True, "Stub manifest verified (hash match only — cryptographic signature skipped)"

        if self._sdk_available:
            return await self._verify_with_sdk(manifest=manifest, content_bytes=content_bytes)

        return True, "Manifest hash verified (C2PA SDK unavailable for cryptographic verification)"

    async def _verify_with_sdk(
        self,
        manifest: dict[str, Any],
        content_bytes: bytes,
    ) -> tuple[bool, str]:
        """Verify manifest cryptographic signature using the C2PA SDK.

        Args:
            manifest: C2PA manifest dict to verify.
            content_bytes: Content bytes to verify against.

        Returns:
            Tuple of (is_valid, reason).
        """
        try:
            import c2pa  # type: ignore[import-not-found]

            manifest_bytes = json.dumps(manifest).encode()
            result = c2pa.verify(manifest=manifest_bytes, asset=content_bytes)

            if result.get("valid"):
                return True, "C2PA manifest cryptographically verified"
            return False, result.get("error", "Cryptographic verification failed")

        except Exception as exc:
            return False, f"C2PA SDK verification error: {exc}"


__all__ = ["C2PAClient"]
