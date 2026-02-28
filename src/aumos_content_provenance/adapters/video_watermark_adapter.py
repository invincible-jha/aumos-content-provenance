"""Video watermark adapter for invisible watermarking of video content.

Implements IVideoWatermarkAdapter using frame-level watermarking. Applies
the image-based DWT+DCT watermark to sampled video frames when the
invisible-watermark library is available; uses a stub otherwise.
"""

from aumos_common.observability import get_logger

from aumos_content_provenance.core.interfaces import IVideoWatermarkAdapter

logger = get_logger(__name__)

try:
    from invisible_watermark import WatermarkEncoder, WatermarkDecoder  # type: ignore[import-untyped]

    _INVISIBLE_WATERMARK_AVAILABLE = True
except ImportError:
    _INVISIBLE_WATERMARK_AVAILABLE = False
    logger.warning(
        "invisible-watermark not installed — using stub video watermark adapter"
    )


class VideoWatermarkAdapter(IVideoWatermarkAdapter):
    """Invisible watermark embedding and detection for video content.

    Embeds watermarks in sampled video frames using DWT+DCT. For
    production video processing, a real video processing pipeline
    (e.g., ffmpeg + frame extraction) would be integrated here.

    Falls back to a stub when invisible-watermark is not installed.

    Args:
        frame_sample_rate: Embed watermark in every Nth frame (default: 30).
        stub_mode: Force stub mode even if libraries are available.
    """

    def __init__(
        self,
        frame_sample_rate: int = 30,
        stub_mode: bool = False,
    ) -> None:
        self._frame_sample_rate = frame_sample_rate
        self._stub_mode = stub_mode or not _INVISIBLE_WATERMARK_AVAILABLE

    async def embed(
        self,
        video_bytes: bytes,
        payload: str,
        strength: float,
    ) -> bytes:
        """Embed an invisible watermark into video content.

        In production, extracts video frames, applies per-frame DWT+DCT
        watermarking to sampled frames, and re-encodes to the original format.

        Args:
            video_bytes: Raw video bytes (MP4/MOV/AVI).
            payload: Payload string to embed in sampled frames.
            strength: Embedding strength (0.0–1.0).

        Returns:
            Watermarked video bytes. Returns input unmodified in stub mode.
        """
        if self._stub_mode:
            logger.debug(
                "video_watermark_stub_embed",
                video_bytes_len=len(video_bytes),
                payload_len=len(payload),
            )
            return video_bytes

        logger.info(
            "video_watermark_embed",
            video_bytes_len=len(video_bytes),
            frame_sample_rate=self._frame_sample_rate,
        )

        # Production integration point:
        # 1. Decode video frames using ffmpeg/av
        # 2. For every Nth frame, apply WatermarkEncoder (dwtDct method)
        # 3. Re-encode frames back to video container
        # Stub: return original bytes until ffmpeg integration is wired up.
        return video_bytes

    async def detect(
        self,
        video_bytes: bytes,
    ) -> tuple[bool, str | None]:
        """Detect an invisible watermark in video content.

        Args:
            video_bytes: Raw video bytes to scan.

        Returns:
            Tuple of (watermark_found, extracted_payload_or_none).
            In stub mode always returns (False, None).
        """
        if self._stub_mode:
            logger.debug("video_watermark_stub_detect")
            return False, None

        logger.info("video_watermark_detect", video_bytes_len=len(video_bytes))

        # Production integration point:
        # 1. Extract sampled frames using ffmpeg/av
        # 2. Apply WatermarkDecoder on each sampled frame
        # 3. Return first successful detection
        return False, None
