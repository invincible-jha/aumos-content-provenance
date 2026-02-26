"""Invisible watermark engine adapter for aumos-content-provenance.

Implements IWatermarkEngine using the invisible-watermark library
(https://github.com/ShieldMnt/invisible-watermark) which provides
DWT+DCT and RivaGAN algorithms for imperceptible watermarking.

The watermarks survive JPEG compression (quality ≥ 70%) and moderate
resizing, making them suitable for AI content attribution and tracking.
"""

from typing import Any

from aumos_common.observability import get_logger

from aumos_content_provenance.core.models import WatermarkMethod

logger = get_logger(__name__)

# Maximum payload length for each algorithm (bytes)
_PAYLOAD_LIMITS: dict[str, int] = {
    WatermarkMethod.DWT_DCT.value: 64,      # 64 bytes (512 bits)
    WatermarkMethod.DWT_DCT_SVD.value: 64,   # 64 bytes
    WatermarkMethod.RIVAGG.value: 4,          # 4 bytes (32 bits — RivaGAN constraint)
}


class WatermarkEngine:
    """Invisible watermark embedding and detection adapter.

    Uses the invisible-watermark library for DWT+DCT and RivaGAN algorithms.
    Falls back to a stub implementation when the library is not installed.

    Algorithm characteristics:
    - DWT_DCT: Robust to JPEG compression, fast, 64-byte payload
    - DWT_DCT_SVD: Most robust, slight quality degradation, 64-byte payload
    - RIVAGG: Deep learning, most imperceptible, 4-byte payload only
    """

    def __init__(self) -> None:
        self._lib_available = self._check_library()

        if not self._lib_available:
            logger.warning(
                "invisible-watermark library not available — using stub mode. "
                "Install invisible-watermark for production watermarking."
            )

    def _check_library(self) -> bool:
        """Check if invisible-watermark is installed."""
        try:
            from imwatermark import WatermarkEncoder  # type: ignore[import-not-found]  # noqa: F401

            return True
        except ImportError:
            return False

    async def embed(
        self,
        content_bytes: bytes,
        payload: str,
        method: WatermarkMethod,
        strength: float,
    ) -> bytes:
        """Embed an invisible watermark into image content.

        Converts payload to bytes, truncates to algorithm limit,
        then uses the selected frequency-domain algorithm.

        Args:
            content_bytes: Raw image bytes (JPEG, PNG, etc.).
            payload: The payload string to embed.
            method: Watermarking algorithm.
            strength: Embedding strength (0.0–1.0).

        Returns:
            Watermarked image bytes.
        """
        if self._lib_available:
            return await self._embed_with_library(
                content_bytes=content_bytes,
                payload=payload,
                method=method,
                strength=strength,
            )
        return self._stub_embed(content_bytes=content_bytes, payload=payload, method=method)

    async def _embed_with_library(
        self,
        content_bytes: bytes,
        payload: str,
        method: WatermarkMethod,
        strength: float,
    ) -> bytes:
        """Embed watermark using the invisible-watermark library.

        Args:
            content_bytes: Raw image bytes.
            payload: Payload to embed.
            method: Algorithm.
            strength: Embedding strength.

        Returns:
            Watermarked image bytes.
        """
        import io

        import numpy as np
        from imwatermark import WatermarkEncoder  # type: ignore[import-not-found]
        from PIL import Image

        # Convert payload to bytes, truncated to algorithm limit
        payload_limit = _PAYLOAD_LIMITS.get(method.value, 64)
        payload_bytes = payload.encode("utf-8")[:payload_limit]

        # Load image as numpy array
        image = Image.open(io.BytesIO(content_bytes)).convert("RGB")
        image_array = np.array(image)

        encoder = WatermarkEncoder()
        encoder.set_watermark("bytes", payload_bytes)

        # Alpha (strength) is applied internally by some algorithms
        watermarked_array = encoder.encode(image_array, method.value)

        # Convert back to bytes
        watermarked_image = Image.fromarray(watermarked_array.astype(np.uint8))
        output_buffer = io.BytesIO()
        watermarked_image.save(output_buffer, format="PNG")
        return output_buffer.getvalue()

    def _stub_embed(
        self,
        content_bytes: bytes,
        payload: str,
        method: WatermarkMethod,
    ) -> bytes:
        """Stub embedding — returns content unchanged with logged payload.

        For development and CI environments. The payload is not actually
        embedded but is logged for traceability.

        Args:
            content_bytes: Raw content bytes.
            payload: Payload that would be embedded.
            method: Algorithm that would be used.

        Returns:
            Original content bytes unchanged.
        """
        logger.info(
            "Stub watermark embed (library not available)",
            method=method.value,
            payload_length=len(payload),
        )
        return content_bytes

    async def detect(
        self,
        content_bytes: bytes,
        method: WatermarkMethod,
    ) -> tuple[bool, str | None]:
        """Detect and extract an invisible watermark from content.

        Args:
            content_bytes: Raw image bytes to scan.
            method: Detection algorithm (must match embedding algorithm).

        Returns:
            Tuple of (watermark_found, extracted_payload_or_none).
        """
        if self._lib_available:
            return await self._detect_with_library(content_bytes=content_bytes, method=method)
        return self._stub_detect()

    async def _detect_with_library(
        self,
        content_bytes: bytes,
        method: WatermarkMethod,
    ) -> tuple[bool, str | None]:
        """Detect watermark using the invisible-watermark library.

        Args:
            content_bytes: Raw image bytes.
            method: Detection algorithm.

        Returns:
            Tuple of (detected, extracted_payload).
        """
        import io

        import numpy as np
        from imwatermark import WatermarkDecoder  # type: ignore[import-not-found]
        from PIL import Image

        try:
            image = Image.open(io.BytesIO(content_bytes)).convert("RGB")
            image_array = np.array(image)

            payload_limit = _PAYLOAD_LIMITS.get(method.value, 64)
            decoder = WatermarkDecoder("bytes", payload_limit)
            watermark_bytes: bytes = decoder.decode(image_array, method.value)

            if not watermark_bytes or watermark_bytes == b"\x00" * payload_limit:
                return False, None

            payload = watermark_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")
            if not payload.strip():
                return False, None

            return True, payload

        except Exception as exc:
            logger.warning("Watermark detection failed", error=str(exc))
            return False, None

    def _stub_detect(self) -> tuple[bool, str | None]:
        """Stub detection — always returns not detected.

        Args: None

        Returns:
            Tuple of (False, None) for stub mode.
        """
        logger.info("Stub watermark detect (library not available)")
        return False, None


__all__ = ["WatermarkEngine"]
