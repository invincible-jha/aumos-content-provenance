"""Audio watermark adapter for inaudible watermarking of audio content.

Implements IAudioWatermarkAdapter using the audiowatermark library when available,
with a stub fallback for development and testing environments.
"""

import hashlib

from aumos_common.observability import get_logger

from aumos_content_provenance.core.interfaces import IAudioWatermarkAdapter

logger = get_logger(__name__)

try:
    import audiowatermark  # type: ignore[import-untyped]

    _AUDIOWATERMARK_AVAILABLE = True
except ImportError:
    _AUDIOWATERMARK_AVAILABLE = False
    logger.warning("audiowatermark not installed — using stub audio watermark adapter")


class AudioWatermarkAdapter(IAudioWatermarkAdapter):
    """Inaudible audio watermark embedding and detection.

    Uses the audiowatermark library for production use. Falls back to a
    stub implementation that returns identity bytes when the library is
    not installed.

    Args:
        sample_rate: Target sample rate in Hz for watermarking (default 44100).
        stub_mode: Force stub mode even if audiowatermark is installed.
    """

    def __init__(
        self,
        sample_rate: int = 44100,
        stub_mode: bool = False,
    ) -> None:
        self._sample_rate = sample_rate
        self._stub_mode = stub_mode or not _AUDIOWATERMARK_AVAILABLE

    async def embed(
        self,
        audio_bytes: bytes,
        payload: str,
        strength: float,
    ) -> bytes:
        """Embed an inaudible watermark into audio content.

        Args:
            audio_bytes: Raw PCM/WAV/MP3 bytes to watermark.
            payload: Payload string to embed (max 32 bytes when encoded).
            strength: Embedding strength (0.0 = minimal, 1.0 = maximum robustness).

        Returns:
            Watermarked audio bytes (same format as input in production;
            identical to input in stub mode).
        """
        if self._stub_mode:
            logger.debug(
                "audio_watermark_stub_embed",
                payload_len=len(payload),
                audio_bytes_len=len(audio_bytes),
            )
            return audio_bytes

        logger.info(
            "audio_watermark_embed",
            audio_bytes_len=len(audio_bytes),
            strength=strength,
        )

        # Production: use audiowatermark library
        watermarked: bytes = audiowatermark.embed(  # type: ignore[attr-defined]
            audio_bytes=audio_bytes,
            payload=payload.encode("utf-8"),
            strength=strength,
            sample_rate=self._sample_rate,
        )
        return watermarked

    async def detect(
        self,
        audio_bytes: bytes,
    ) -> tuple[bool, str | None]:
        """Detect an inaudible watermark in audio content.

        Args:
            audio_bytes: Raw audio bytes to scan.

        Returns:
            Tuple of (watermark_found, extracted_payload_or_none).
            In stub mode always returns (False, None).
        """
        if self._stub_mode:
            logger.debug("audio_watermark_stub_detect")
            return False, None

        logger.info("audio_watermark_detect", audio_bytes_len=len(audio_bytes))

        # Production: use audiowatermark library
        result = audiowatermark.detect(  # type: ignore[attr-defined]
            audio_bytes=audio_bytes,
            sample_rate=self._sample_rate,
        )
        if result is None:
            return False, None
        return True, result.decode("utf-8", errors="replace")
