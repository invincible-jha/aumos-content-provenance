"""Tamper detector adapter for aumos-content-provenance.

Detects content tampering using multiple complementary techniques:
cryptographic hash comparison, watermark integrity checks, metadata
consistency validation, and statistical pixel-level analysis for images.
Produces confidence-scored tamper reports suitable for legal proceedings.
"""

import hashlib
import io
import math
import struct
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class TamperMethod(str, Enum):
    """Detection method used to identify tampering."""

    HASH_COMPARISON = "hash_comparison"
    WATERMARK_INTEGRITY = "watermark_integrity"
    METADATA_CONSISTENCY = "metadata_consistency"
    STATISTICAL_ANOMALY = "statistical_anomaly"
    PIXEL_REGION = "pixel_region"


class TamperSeverity(str, Enum):
    """Severity classification for detected tampering."""

    NONE = "none"
    LOW = "low"          # Minor anomalies, likely compression artifacts
    MEDIUM = "medium"    # Suspicious inconsistencies, possible tampering
    HIGH = "high"        # Strong evidence of intentional manipulation
    CRITICAL = "critical"  # Definitive tampering with chain of custody broken


@dataclass
class TamperIndicator:
    """A single piece of evidence supporting a tamper conclusion."""

    method: TamperMethod
    severity: TamperSeverity
    confidence: float                   # 0.0–1.0
    description: str
    region: dict[str, int] | None = None  # {"x", "y", "width", "height"} if localized
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class TamperReport:
    """Comprehensive tamper detection report for a content item."""

    report_id: str
    content_id: str
    content_hash: str
    overall_tampered: bool
    overall_confidence: float          # Weighted average across all indicators
    severity: TamperSeverity
    indicators: list[TamperIndicator]
    affected_regions: list[dict[str, int]]   # Localized tamper regions
    detection_methods_used: list[str]
    original_hash: str | None          # Known-good hash for comparison, if provided
    metadata_issues: list[str]
    generated_at: datetime
    notes: str


class TamperDetector:
    """Detect content tampering using cryptographic and statistical methods.

    Implements a multi-layer tamper detection strategy:
    1. Cryptographic hash comparison against known-good hashes
    2. Watermark integrity verification
    3. Metadata consistency cross-checking
    4. Statistical anomaly detection in pixel data
    5. Region-level localization for identified tampering

    Confidence scores are computed per-method and aggregated via
    weighted voting to produce a single tamper confidence score.
    """

    # Weights for each detection method when computing overall confidence
    _METHOD_WEIGHTS: dict[TamperMethod, float] = {
        TamperMethod.HASH_COMPARISON: 1.0,       # Definitive when matched
        TamperMethod.WATERMARK_INTEGRITY: 0.9,   # Near-definitive
        TamperMethod.METADATA_CONSISTENCY: 0.6,  # Supporting evidence
        TamperMethod.STATISTICAL_ANOMALY: 0.7,   # Probabilistic
        TamperMethod.PIXEL_REGION: 0.8,          # Strong localized evidence
    }

    def __init__(
        self,
        statistical_threshold: float = 0.35,    # Chi-square deviation threshold
        block_size: int = 16,                    # Pixel block size for region analysis
    ) -> None:
        self._statistical_threshold = statistical_threshold
        self._block_size = block_size
        self._imaging_available = self._check_imaging_library()

        if not self._imaging_available:
            logger.warning(
                "Pillow/numpy not available — pixel-level tamper detection disabled. "
                "Install Pillow and numpy for full tamper analysis."
            )

    def _check_imaging_library(self) -> bool:
        """Check if Pillow and numpy are installed."""
        try:
            from PIL import Image  # type: ignore[import-not-found]  # noqa: F401
            import numpy  # type: ignore[import-not-found]  # noqa: F401

            return True
        except ImportError:
            return False

    async def detect_tampering(
        self,
        content_id: str,
        content_bytes: bytes,
        original_hash: str | None = None,
        expected_watermark_payload: str | None = None,
        expected_metadata: dict[str, Any] | None = None,
    ) -> TamperReport:
        """Run full tamper detection suite on content bytes.

        Executes all applicable detection methods and aggregates their
        results into a single tamper report with an overall confidence score.

        Args:
            content_id: Identifier for the content being analyzed.
            content_bytes: Raw bytes of the content to analyze.
            original_hash: Known-good SHA-256 hash for comparison, if available.
            expected_watermark_payload: Expected watermark payload string, if known.
            expected_metadata: Expected metadata key-value pairs for consistency check.

        Returns:
            TamperReport with full analysis results.
        """
        report_id = str(uuid.uuid4())
        current_hash = hashlib.sha256(content_bytes).hexdigest()
        indicators: list[TamperIndicator] = []
        methods_used: list[str] = []

        logger.info(
            "Starting tamper detection",
            content_id=content_id,
            report_id=report_id,
            content_size=len(content_bytes),
            has_reference_hash=original_hash is not None,
        )

        # --- Method 1: Cryptographic hash comparison ---
        if original_hash is not None:
            hash_indicator = self._check_hash(
                current_hash=current_hash,
                original_hash=original_hash,
            )
            indicators.append(hash_indicator)
            methods_used.append(TamperMethod.HASH_COMPARISON.value)

        # --- Method 2: Watermark integrity ---
        if expected_watermark_payload is not None:
            watermark_indicator = await self._check_watermark_integrity(
                content_bytes=content_bytes,
                expected_payload=expected_watermark_payload,
            )
            indicators.append(watermark_indicator)
            methods_used.append(TamperMethod.WATERMARK_INTEGRITY.value)

        # --- Method 3: Metadata consistency ---
        if expected_metadata is not None:
            metadata_indicator = self._check_metadata_consistency(
                content_bytes=content_bytes,
                expected_metadata=expected_metadata,
            )
            indicators.append(metadata_indicator)
            methods_used.append(TamperMethod.METADATA_CONSISTENCY.value)

        # --- Methods 4 & 5: Statistical and pixel-level analysis ---
        if self._imaging_available and self._is_image_content(content_bytes):
            stat_indicator, region_indicators = await self._analyze_pixel_statistics(
                content_bytes=content_bytes,
            )
            indicators.append(stat_indicator)
            indicators.extend(region_indicators)
            methods_used.append(TamperMethod.STATISTICAL_ANOMALY.value)
            if region_indicators:
                methods_used.append(TamperMethod.PIXEL_REGION.value)

        # --- Aggregate results ---
        overall_confidence, overall_tampered, severity = self._aggregate_indicators(indicators)

        affected_regions = [
            indicator.region
            for indicator in indicators
            if indicator.region is not None and indicator.severity != TamperSeverity.NONE
        ]

        metadata_issues = [
            indicator.description
            for indicator in indicators
            if indicator.method == TamperMethod.METADATA_CONSISTENCY
            and indicator.severity != TamperSeverity.NONE
        ]

        report = TamperReport(
            report_id=report_id,
            content_id=content_id,
            content_hash=current_hash,
            overall_tampered=overall_tampered,
            overall_confidence=overall_confidence,
            severity=severity,
            indicators=indicators,
            affected_regions=affected_regions,
            detection_methods_used=methods_used,
            original_hash=original_hash,
            metadata_issues=metadata_issues,
            generated_at=datetime.now(UTC),
            notes=self._generate_notes(overall_tampered, severity, len(methods_used)),
        )

        logger.info(
            "Tamper detection complete",
            content_id=content_id,
            report_id=report_id,
            overall_tampered=overall_tampered,
            severity=severity.value,
            confidence=round(overall_confidence, 3),
            indicator_count=len(indicators),
        )

        return report

    def _check_hash(self, current_hash: str, original_hash: str) -> TamperIndicator:
        """Compare current SHA-256 hash against known-good reference.

        Args:
            current_hash: SHA-256 of the content bytes being analyzed.
            original_hash: Known-good reference hash.

        Returns:
            TamperIndicator with definitive result.
        """
        if current_hash == original_hash:
            return TamperIndicator(
                method=TamperMethod.HASH_COMPARISON,
                severity=TamperSeverity.NONE,
                confidence=0.0,
                description="SHA-256 hash matches reference — content unmodified",
                evidence={"current_hash": current_hash, "reference_hash": original_hash},
            )

        return TamperIndicator(
            method=TamperMethod.HASH_COMPARISON,
            severity=TamperSeverity.CRITICAL,
            confidence=1.0,
            description=(
                f"SHA-256 mismatch: current={current_hash[:16]}... "
                f"expected={original_hash[:16]}..."
            ),
            evidence={"current_hash": current_hash, "reference_hash": original_hash},
        )

    async def _check_watermark_integrity(
        self,
        content_bytes: bytes,
        expected_payload: str,
    ) -> TamperIndicator:
        """Verify embedded watermark payload matches expected value.

        Uses SHA-256 comparison of the expected payload to avoid
        exposing the raw payload in the indicator.

        Args:
            content_bytes: Raw content bytes.
            expected_payload: Expected watermark payload string.

        Returns:
            TamperIndicator reporting watermark integrity status.
        """
        expected_hash = hashlib.sha256(expected_payload.encode()).hexdigest()

        # In production this calls the WatermarkEngine adapter; here we
        # perform a metadata-level check using stored payload hash.
        # The actual detection is handled by WatermarkEngine.detect().
        if not self._imaging_available:
            return TamperIndicator(
                method=TamperMethod.WATERMARK_INTEGRITY,
                severity=TamperSeverity.LOW,
                confidence=0.3,
                description="Watermark verification skipped — imaging library not available",
                evidence={"expected_payload_hash": expected_hash[:16]},
            )

        try:
            import io as _io

            import numpy as np
            from imwatermark import WatermarkDecoder  # type: ignore[import-not-found]
            from PIL import Image

            image = Image.open(_io.BytesIO(content_bytes)).convert("RGB")
            image_array = np.array(image)
            decoder = WatermarkDecoder("bytes", 64)
            watermark_bytes: bytes = decoder.decode(image_array, "dwtDct")
            extracted_payload = watermark_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")
            extracted_hash = hashlib.sha256(extracted_payload.encode()).hexdigest()

            if extracted_hash == expected_hash:
                return TamperIndicator(
                    method=TamperMethod.WATERMARK_INTEGRITY,
                    severity=TamperSeverity.NONE,
                    confidence=0.0,
                    description="Watermark payload verified — content unmodified",
                    evidence={"payload_hash_match": True},
                )

            return TamperIndicator(
                method=TamperMethod.WATERMARK_INTEGRITY,
                severity=TamperSeverity.HIGH,
                confidence=0.9,
                description="Watermark payload mismatch — possible content substitution",
                evidence={
                    "expected_payload_hash": expected_hash[:16],
                    "extracted_payload_hash": extracted_hash[:16],
                },
            )
        except Exception as exc:
            logger.warning("Watermark integrity check failed", error=str(exc))
            return TamperIndicator(
                method=TamperMethod.WATERMARK_INTEGRITY,
                severity=TamperSeverity.MEDIUM,
                confidence=0.5,
                description=f"Watermark extraction error — cannot verify: {exc}",
                evidence={"error": str(exc)},
            )

    def _check_metadata_consistency(
        self,
        content_bytes: bytes,
        expected_metadata: dict[str, Any],
    ) -> TamperIndicator:
        """Check embedded metadata fields for consistency with expected values.

        Reads EXIF/XMP fields from image bytes and compares to expected values.
        Discrepancies suggest metadata stripping or injection.

        Args:
            content_bytes: Raw image bytes.
            expected_metadata: Dict of expected metadata key-value pairs.

        Returns:
            TamperIndicator with consistency check results.
        """
        issues: list[str] = []

        if self._imaging_available:
            try:
                from PIL import Image
                from PIL.ExifTags import TAGS  # type: ignore[import-not-found]

                image = Image.open(io.BytesIO(content_bytes))
                exif_data = image._getexif() or {}  # type: ignore[attr-defined]
                actual_metadata = {
                    TAGS.get(tag_id, str(tag_id)): value
                    for tag_id, value in exif_data.items()
                }

                for key, expected_value in expected_metadata.items():
                    actual_value = actual_metadata.get(key)
                    if actual_value is None:
                        issues.append(f"Expected metadata field '{key}' not found in content")
                    elif str(actual_value) != str(expected_value):
                        issues.append(
                            f"Metadata field '{key}': expected '{expected_value}' "
                            f"but found '{actual_value}'"
                        )
            except Exception as exc:
                issues.append(f"Metadata extraction failed: {exc}")

        if not issues:
            return TamperIndicator(
                method=TamperMethod.METADATA_CONSISTENCY,
                severity=TamperSeverity.NONE,
                confidence=0.0,
                description="All metadata fields consistent with expected values",
            )

        severity = TamperSeverity.MEDIUM if len(issues) <= 2 else TamperSeverity.HIGH
        return TamperIndicator(
            method=TamperMethod.METADATA_CONSISTENCY,
            severity=severity,
            confidence=min(0.5 + 0.15 * len(issues), 0.9),
            description=f"{len(issues)} metadata inconsistencies detected",
            evidence={"issues": issues},
        )

    async def _analyze_pixel_statistics(
        self,
        content_bytes: bytes,
    ) -> tuple[TamperIndicator, list[TamperIndicator]]:
        """Analyze pixel-level statistics for splicing and copy-move artifacts.

        Uses chi-square analysis of pixel value distributions per block.
        Regions with abnormal distributions relative to the image mean
        are flagged as potentially tampered.

        Args:
            content_bytes: Raw image bytes.

        Returns:
            Tuple of (overall statistical indicator, list of region indicators).
        """
        try:
            import numpy as np
            from PIL import Image

            image = Image.open(io.BytesIO(content_bytes)).convert("L")  # Grayscale
            pixel_array = np.array(image, dtype=np.float64)
            height, width = pixel_array.shape

            block_size = self._block_size
            block_scores: list[tuple[int, int, float]] = []  # (row, col, anomaly_score)

            for row in range(0, height - block_size, block_size):
                for col in range(0, width - block_size, block_size):
                    block = pixel_array[row : row + block_size, col : col + block_size]
                    score = self._compute_block_anomaly_score(block, pixel_array)
                    block_scores.append((row, col, score))

            if not block_scores:
                return (
                    TamperIndicator(
                        method=TamperMethod.STATISTICAL_ANOMALY,
                        severity=TamperSeverity.NONE,
                        confidence=0.0,
                        description="Image too small for block-level statistical analysis",
                    ),
                    [],
                )

            all_scores = [score for _, _, score in block_scores]
            mean_score = sum(all_scores) / len(all_scores)
            anomaly_threshold = mean_score + self._statistical_threshold

            flagged_blocks = [
                (row, col, score)
                for row, col, score in block_scores
                if score > anomaly_threshold
            ]

            region_indicators: list[TamperIndicator] = []
            for row, col, score in flagged_blocks[:10]:  # Cap at 10 region reports
                region_indicators.append(
                    TamperIndicator(
                        method=TamperMethod.PIXEL_REGION,
                        severity=TamperSeverity.MEDIUM if score < 0.7 else TamperSeverity.HIGH,
                        confidence=min(score, 0.95),
                        description=f"Statistical anomaly at pixel block ({col},{row})",
                        region={
                            "x": col,
                            "y": row,
                            "width": block_size,
                            "height": block_size,
                        },
                        evidence={"anomaly_score": round(score, 4), "threshold": anomaly_threshold},
                    )
                )

            tamper_ratio = len(flagged_blocks) / max(len(block_scores), 1)

            if tamper_ratio < 0.05:
                overall_severity = TamperSeverity.NONE
                overall_confidence = 0.0
                description = f"No significant statistical anomalies ({tamper_ratio:.1%} of blocks)"
            elif tamper_ratio < 0.15:
                overall_severity = TamperSeverity.LOW
                overall_confidence = 0.3
                description = f"Minor anomalies in {tamper_ratio:.1%} of blocks — possible compression"
            elif tamper_ratio < 0.30:
                overall_severity = TamperSeverity.MEDIUM
                overall_confidence = 0.6
                description = f"Suspicious anomalies in {tamper_ratio:.1%} of blocks"
            else:
                overall_severity = TamperSeverity.HIGH
                overall_confidence = 0.85
                description = f"High anomaly density in {tamper_ratio:.1%} of blocks — strong tamper evidence"

            overall_indicator = TamperIndicator(
                method=TamperMethod.STATISTICAL_ANOMALY,
                severity=overall_severity,
                confidence=overall_confidence,
                description=description,
                evidence={
                    "total_blocks": len(block_scores),
                    "flagged_blocks": len(flagged_blocks),
                    "tamper_ratio": round(tamper_ratio, 4),
                    "mean_anomaly_score": round(mean_score, 4),
                },
            )

            return overall_indicator, region_indicators

        except Exception as exc:
            logger.warning("Pixel-level statistical analysis failed", error=str(exc))
            return (
                TamperIndicator(
                    method=TamperMethod.STATISTICAL_ANOMALY,
                    severity=TamperSeverity.NONE,
                    confidence=0.0,
                    description=f"Statistical analysis failed: {exc}",
                ),
                [],
            )

    def _compute_block_anomaly_score(
        self,
        block: Any,
        full_image: Any,
    ) -> float:
        """Compute an anomaly score for a pixel block relative to the full image.

        Uses normalized chi-square deviation of the block's pixel histogram
        against the image-wide histogram.

        Args:
            block: 2D numpy array for the block (float64).
            full_image: Full image array (float64) for reference statistics.

        Returns:
            Anomaly score between 0.0 (normal) and 1.0 (highly anomalous).
        """
        import numpy as np

        block_hist, _ = np.histogram(block.flatten(), bins=16, range=(0, 256))
        image_hist, _ = np.histogram(full_image.flatten(), bins=16, range=(0, 256))

        # Normalize histograms
        block_hist = block_hist.astype(np.float64) / (block_hist.sum() + 1e-9)
        image_hist = image_hist.astype(np.float64) / (image_hist.sum() + 1e-9)

        # Chi-square divergence
        chi_sq = np.sum(
            (block_hist - image_hist) ** 2 / (image_hist + 1e-9)
        )

        # Normalize to 0–1 using sigmoid-like mapping
        score = 1.0 - math.exp(-chi_sq / 5.0)
        return float(score)

    def _is_image_content(self, content_bytes: bytes) -> bool:
        """Heuristically detect if content bytes represent an image.

        Args:
            content_bytes: Raw bytes to check.

        Returns:
            True if content appears to be a supported image format.
        """
        if len(content_bytes) < 4:
            return False

        # JPEG magic: FF D8 FF
        if content_bytes[:3] == b"\xff\xd8\xff":
            return True
        # PNG magic: 89 50 4E 47
        if content_bytes[:4] == b"\x89PNG":
            return True
        # GIF magic: 47 49 46
        if content_bytes[:3] in (b"GIF", b"GIF"):
            return True
        # WEBP: RIFF....WEBP
        if content_bytes[:4] == b"RIFF" and content_bytes[8:12] == b"WEBP":
            return True

        return False

    def _aggregate_indicators(
        self,
        indicators: list[TamperIndicator],
    ) -> tuple[float, bool, TamperSeverity]:
        """Aggregate all detection indicators into a single verdict.

        Uses weighted average of confidence scores, where each method's
        weight is defined in _METHOD_WEIGHTS. A weighted confidence >= 0.5
        is considered tampered.

        Args:
            indicators: All TamperIndicators from this detection run.

        Returns:
            Tuple of (overall_confidence, is_tampered, severity).
        """
        if not indicators:
            return 0.0, False, TamperSeverity.NONE

        # If any definitive hash mismatch, immediately return critical
        for indicator in indicators:
            if (
                indicator.method == TamperMethod.HASH_COMPARISON
                and indicator.severity == TamperSeverity.CRITICAL
            ):
                return 1.0, True, TamperSeverity.CRITICAL

        total_weight = 0.0
        weighted_confidence = 0.0

        for indicator in indicators:
            weight = self._METHOD_WEIGHTS.get(indicator.method, 0.5)
            weighted_confidence += indicator.confidence * weight
            total_weight += weight

        overall_confidence = weighted_confidence / max(total_weight, 1e-9)
        is_tampered = overall_confidence >= 0.5

        # Determine severity from highest-severity indicator
        severity_order = [
            TamperSeverity.CRITICAL,
            TamperSeverity.HIGH,
            TamperSeverity.MEDIUM,
            TamperSeverity.LOW,
            TamperSeverity.NONE,
        ]
        max_severity = TamperSeverity.NONE
        for sev in severity_order:
            if any(i.severity == sev for i in indicators):
                max_severity = sev
                break

        # If confidence is low but severity label is high, downgrade
        if not is_tampered:
            max_severity = TamperSeverity.NONE

        return round(overall_confidence, 4), is_tampered, max_severity

    def _generate_notes(
        self,
        is_tampered: bool,
        severity: TamperSeverity,
        methods_count: int,
    ) -> str:
        """Generate human-readable notes for the tamper report.

        Args:
            is_tampered: Overall tamper verdict.
            severity: Overall severity classification.
            methods_count: Number of detection methods applied.

        Returns:
            Narrative notes string for the report.
        """
        if not is_tampered:
            return (
                f"Content passed tamper detection across {methods_count} method(s). "
                "No significant evidence of modification detected."
            )

        severity_descriptions = {
            TamperSeverity.LOW: "minor anomalies detected, likely benign (compression artifacts)",
            TamperSeverity.MEDIUM: "suspicious inconsistencies detected — manual review recommended",
            TamperSeverity.HIGH: "strong tamper evidence detected — content integrity compromised",
            TamperSeverity.CRITICAL: (
                "DEFINITIVE TAMPERING: cryptographic hash mismatch confirms content modification. "
                "Chain of custody broken."
            ),
        }

        return (
            f"Tamper detected ({severity.value}): "
            + severity_descriptions.get(severity, "evidence of modification")
            + f". {methods_count} detection method(s) applied."
        )


__all__ = [
    "TamperMethod",
    "TamperSeverity",
    "TamperIndicator",
    "TamperReport",
    "TamperDetector",
]
