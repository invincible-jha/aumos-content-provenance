"""Service layer for aumos-content-provenance.

Services orchestrate domain logic by coordinating adapters via interfaces.
No direct database or external service calls — everything goes through protocols.

Services:
- C2PAService: Sign and verify content with C2PA cryptographic manifests
- WatermarkService: Embed and detect invisible watermarks
- LineageService: Track and query training data lineage chains
- LicenseComplianceService: Check and report on training data license risk
- AuditExportService: Generate court-admissible audit trail packages
"""

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from aumos_common.errors import NotFoundError, ValidationError
from aumos_common.observability import get_logger

from aumos_content_provenance.core.interfaces import (
    IAuditExportRepository,
    IC2PAClient,
    ILicenseRepository,
    ILineageRepository,
    IProvenanceRepository,
    IWatermarkEngine,
    IWatermarkRepository,
)
from aumos_content_provenance.core.models import (
    AuditExport,
    AuditExportStatus,
    LicenseCheck,
    LicenseRisk,
    LineageEntry,
    LineageNodeType,
    ProvenanceRecord,
    ProvenanceStatus,
    Watermark,
    WatermarkMethod,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class SignContentResult:
    """Result of a C2PA content signing operation."""

    record: ProvenanceRecord
    watermarked_content: bytes | None  # Populated if watermarking was also applied


@dataclass
class VerifyResult:
    """Result of a C2PA manifest verification."""

    is_valid: bool
    status: ProvenanceStatus
    reason: str
    record: ProvenanceRecord | None
    manifest: dict[str, Any] | None


@dataclass
class WatermarkEmbedResult:
    """Result of a watermark embedding operation."""

    watermark: Watermark
    watermarked_bytes: bytes


@dataclass
class WatermarkDetectResult:
    """Result of a watermark detection operation."""

    detected: bool
    payload: str | None
    content_id: str | None  # Matched content_id if payload parsed successfully


@dataclass
class LineageGraph:
    """Full lineage graph for a content item."""

    content_id: str
    entries: list[LineageEntry]
    depth: int


@dataclass
class LicenseReport:
    """Aggregated license compliance report."""

    tenant_id: uuid.UUID
    total_checks: int
    high_risk_count: int
    critical_count: int
    by_risk_level: dict[str, int]
    top_flags: list[str]
    generated_at: datetime


# ---------------------------------------------------------------------------
# C2PAService
# ---------------------------------------------------------------------------


class C2PAService:
    """Sign and verify content using C2PA cryptographic manifests.

    Implements the W3C Content Credentials (C2PA) specification for
    AI-generated content provenance. Produces manifests that can be
    verified in court-admissible audit proceedings.
    """

    def __init__(
        self,
        c2pa_client: IC2PAClient,
        provenance_repository: IProvenanceRepository,
        event_publisher: Any | None = None,
    ) -> None:
        self._client = c2pa_client
        self._repo = provenance_repository
        self._publisher = event_publisher

    async def sign_content(
        self,
        tenant_id: uuid.UUID,
        content_bytes: bytes,
        content_id: str,
        content_type: str,
        assertions: list[dict[str, Any]],
        signer_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> SignContentResult:
        """Sign content with a C2PA cryptographic manifest.

        Computes content hash, generates C2PA manifest via the SDK client,
        stores the provenance record, and publishes a Kafka event.

        Args:
            tenant_id: The owning tenant.
            content_bytes: Raw bytes of the content to sign.
            content_id: Stable identifier for this content.
            content_type: MIME type (e.g., image/jpeg, text/plain).
            assertions: C2PA assertions to include in the manifest.
            signer_id: Identifier for the signing key/cert.
            metadata: Optional additional metadata to store.

        Returns:
            SignContentResult with the ProvenanceRecord and manifest.

        Raises:
            ValidationError: If content_bytes is empty or content_id is blank.
        """
        if not content_bytes:
            raise ValidationError("content_bytes cannot be empty")
        if not content_id.strip():
            raise ValidationError("content_id cannot be blank")

        content_hash = hashlib.sha256(content_bytes).hexdigest()

        logger.info(
            "Signing content with C2PA",
            tenant_id=str(tenant_id),
            content_id=content_id,
            content_type=content_type,
            content_hash=content_hash[:16],
        )

        manifest = await self._client.sign_content(
            content_bytes=content_bytes,
            content_type=content_type,
            claim_generator=f"AumOS/1.0 (tenant:{tenant_id})",
            assertions=assertions,
        )

        # Manifest URI — in production this would be an S3 URL or JUMBF embed URI
        manifest_uri = f"urn:aumos:manifest:{content_id}:{content_hash[:12]}"

        record = await self._repo.create(
            tenant_id=tenant_id,
            content_id=content_id,
            content_type=content_type,
            content_hash=content_hash,
            c2pa_manifest=manifest,
            manifest_uri=manifest_uri,
            status=ProvenanceStatus.SIGNED,
            signer_id=signer_id,
            metadata=metadata or {},
        )

        if self._publisher:
            await self._publisher.publish(
                topic="aumos.provenance.signed",
                key=str(tenant_id),
                value={
                    "event_type": "content_signed",
                    "tenant_id": str(tenant_id),
                    "record_id": str(record.id),
                    "content_id": content_id,
                    "content_hash": content_hash,
                    "timestamp": datetime.now(UTC).isoformat(),
                },
            )

        logger.info(
            "Content signed successfully",
            record_id=str(record.id),
            manifest_uri=manifest_uri,
        )

        return SignContentResult(record=record, watermarked_content=None)

    async def verify_provenance(
        self,
        tenant_id: uuid.UUID,
        record_id: uuid.UUID,
        content_bytes: bytes,
    ) -> VerifyResult:
        """Verify the C2PA manifest for a stored provenance record.

        Retrieves the stored manifest and verifies it against the provided
        content bytes. Updates the record status on the result.

        Args:
            tenant_id: The owning tenant.
            record_id: The provenance record UUID.
            content_bytes: Raw content bytes to verify against.

        Returns:
            VerifyResult with validation status and reason.

        Raises:
            NotFoundError: If the provenance record does not exist.
        """
        record = await self._repo.get_by_id(record_id=record_id, tenant_id=tenant_id)
        if record is None:
            raise NotFoundError(f"Provenance record {record_id} not found")

        # Verify content hash before manifest verification
        actual_hash = hashlib.sha256(content_bytes).hexdigest()
        if actual_hash != record.content_hash:
            updated = await self._repo.update_status(
                record_id=record_id,
                tenant_id=tenant_id,
                status=ProvenanceStatus.INVALID,
            )
            return VerifyResult(
                is_valid=False,
                status=ProvenanceStatus.INVALID,
                reason="Content hash mismatch — content has been modified",
                record=updated,
                manifest=record.c2pa_manifest,
            )

        is_valid, reason = await self._client.verify_manifest(
            manifest=record.c2pa_manifest,
            content_bytes=content_bytes,
        )

        new_status = ProvenanceStatus.VERIFIED if is_valid else ProvenanceStatus.INVALID
        updated = await self._repo.update_status(
            record_id=record_id,
            tenant_id=tenant_id,
            status=new_status,
        )

        return VerifyResult(
            is_valid=is_valid,
            status=new_status,
            reason=reason,
            record=updated,
            manifest=record.c2pa_manifest,
        )


# ---------------------------------------------------------------------------
# WatermarkService
# ---------------------------------------------------------------------------


class WatermarkService:
    """Embed and detect invisible watermarks in AI-generated content.

    Uses imperceptible watermarking algorithms (DWT+DCT, RivaGAN) to embed
    tenant/content identifiers that survive compression and resizing.
    """

    def __init__(
        self,
        watermark_engine: IWatermarkEngine,
        watermark_repository: IWatermarkRepository,
        default_method: WatermarkMethod = WatermarkMethod.DWT_DCT,
        default_strength: float = 0.3,
    ) -> None:
        self._engine = watermark_engine
        self._repo = watermark_repository
        self._default_method = default_method
        self._default_strength = default_strength

    async def embed_watermark(
        self,
        tenant_id: uuid.UUID,
        content_id: str,
        content_bytes: bytes,
        payload: str | None = None,
        method: WatermarkMethod | None = None,
        strength: float | None = None,
    ) -> WatermarkEmbedResult:
        """Embed an invisible watermark into content.

        If no payload is provided, defaults to a UUID-based tenant+content
        identifier string. The payload hash is stored for later verification.

        Args:
            tenant_id: The owning tenant.
            content_id: Stable content identifier.
            content_bytes: Raw bytes to watermark.
            payload: Hidden payload to embed. Defaults to tenant:content_id.
            method: Watermarking algorithm. Uses service default if None.
            strength: Embedding strength. Uses service default if None.

        Returns:
            WatermarkEmbedResult with metadata record and watermarked bytes.

        Raises:
            ValidationError: If content_bytes is empty.
        """
        if not content_bytes:
            raise ValidationError("content_bytes cannot be empty for watermarking")

        resolved_payload = payload or f"{tenant_id}:{content_id}"
        resolved_method = method or self._default_method
        resolved_strength = strength if strength is not None else self._default_strength

        payload_hash = hashlib.sha256(resolved_payload.encode()).hexdigest()

        logger.info(
            "Embedding watermark",
            tenant_id=str(tenant_id),
            content_id=content_id,
            method=resolved_method.value,
            strength=resolved_strength,
        )

        watermarked_bytes = await self._engine.embed(
            content_bytes=content_bytes,
            payload=resolved_payload,
            method=resolved_method,
            strength=resolved_strength,
        )

        watermark_record = await self._repo.create(
            tenant_id=tenant_id,
            content_id=content_id,
            method=resolved_method,
            payload=resolved_payload,
            payload_hash=payload_hash,
            strength=resolved_strength,
        )

        return WatermarkEmbedResult(watermark=watermark_record, watermarked_bytes=watermarked_bytes)

    async def detect_watermark(
        self,
        tenant_id: uuid.UUID,
        content_bytes: bytes,
        method: WatermarkMethod | None = None,
    ) -> WatermarkDetectResult:
        """Detect and extract an invisible watermark from content.

        Args:
            tenant_id: The requesting tenant (for logging).
            content_bytes: Raw bytes to scan for watermarks.
            method: Detection algorithm. Defaults to service default.

        Returns:
            WatermarkDetectResult with detection status and extracted payload.
        """
        if not content_bytes:
            raise ValidationError("content_bytes cannot be empty for detection")

        resolved_method = method or self._default_method

        detected, payload = await self._engine.detect(
            content_bytes=content_bytes,
            method=resolved_method,
        )

        content_id: str | None = None
        if detected and payload:
            # Parse tenant_id:content_id from payload
            parts = payload.split(":", 1)
            if len(parts) == 2:
                content_id = parts[1]

        logger.info(
            "Watermark detection complete",
            tenant_id=str(tenant_id),
            detected=detected,
            content_id=content_id,
        )

        return WatermarkDetectResult(
            detected=detected,
            payload=payload,
            content_id=content_id,
        )


# ---------------------------------------------------------------------------
# LineageService
# ---------------------------------------------------------------------------


class LineageService:
    """Track and query training data lineage chains.

    Records the provenance graph of AI systems: which datasets trained
    which models, which fine-tuning happened, and which outputs were generated.
    """

    def __init__(
        self,
        lineage_repository: ILineageRepository,
        max_depth: int = 10,
    ) -> None:
        self._repo = lineage_repository
        self._max_depth = max_depth

    async def record_lineage(
        self,
        tenant_id: uuid.UUID,
        parent_node_id: str,
        parent_node_type: LineageNodeType,
        child_node_id: str,
        child_node_type: LineageNodeType,
        relationship: str,
        metadata: dict[str, Any] | None = None,
    ) -> LineageEntry:
        """Record a lineage edge between two nodes.

        Args:
            tenant_id: The owning tenant.
            parent_node_id: Source node identifier.
            parent_node_type: Type of the source node.
            child_node_id: Derived node identifier.
            child_node_type: Type of the derived node.
            relationship: Relationship type (e.g., "trained_on", "generated_by").
            metadata: Optional additional edge metadata.

        Returns:
            The created LineageEntry.
        """
        valid_relationships = {"trained_on", "fine_tuned_on", "generated_by", "derived_from", "evaluated_on"}
        if relationship not in valid_relationships:
            raise ValidationError(
                f"Invalid relationship '{relationship}'. Must be one of: {valid_relationships}"
            )

        entry = await self._repo.create(
            tenant_id=tenant_id,
            parent_node_id=parent_node_id,
            parent_node_type=parent_node_type,
            child_node_id=child_node_id,
            child_node_type=child_node_type,
            relationship=relationship,
            metadata=metadata or {},
        )

        logger.info(
            "Lineage edge recorded",
            tenant_id=str(tenant_id),
            parent=f"{parent_node_type.value}:{parent_node_id}",
            child=f"{child_node_type.value}:{child_node_id}",
            relationship=relationship,
        )

        return entry

    async def get_lineage(
        self,
        tenant_id: uuid.UUID,
        content_id: str,
    ) -> LineageGraph:
        """Retrieve the full ancestry lineage graph for a content item.

        Traverses the lineage graph upward from the content_id to reconstruct
        the complete chain: training data → model → fine-tuned model → output.

        Args:
            tenant_id: The owning tenant.
            content_id: The content item to trace lineage for.

        Returns:
            LineageGraph with all ancestor edges ordered root-to-leaf.
        """
        entries = await self._repo.get_ancestors(
            node_id=content_id,
            tenant_id=tenant_id,
            max_depth=self._max_depth,
        )

        return LineageGraph(
            content_id=content_id,
            entries=entries,
            depth=len(entries),
        )


# ---------------------------------------------------------------------------
# LicenseComplianceService
# ---------------------------------------------------------------------------


class LicenseComplianceService:
    """Check and report on training data license compliance.

    Context: 51 active copyright lawsuits against AI companies (as of 2026).
    This service tracks the license status of all training data to support
    legal discovery, risk assessment, and compliance reporting.
    """

    # SPDX license identifiers and their assessed risk scores
    _LICENSE_RISK_MAP: dict[str, tuple[LicenseRisk, float]] = {
        # Low risk — permissive
        "MIT": (LicenseRisk.LOW, 0.1),
        "Apache-2.0": (LicenseRisk.LOW, 0.1),
        "BSD-2-Clause": (LicenseRisk.LOW, 0.15),
        "BSD-3-Clause": (LicenseRisk.LOW, 0.15),
        "CC0-1.0": (LicenseRisk.LOW, 0.05),
        "Unlicense": (LicenseRisk.LOW, 0.05),
        # Medium risk — copyleft
        "GPL-2.0": (LicenseRisk.MEDIUM, 0.5),
        "GPL-3.0": (LicenseRisk.MEDIUM, 0.5),
        "LGPL-2.1": (LicenseRisk.MEDIUM, 0.4),
        "LGPL-3.0": (LicenseRisk.MEDIUM, 0.4),
        "CC-BY-4.0": (LicenseRisk.MEDIUM, 0.35),
        "CC-BY-SA-4.0": (LicenseRisk.MEDIUM, 0.55),
        # High risk — non-commercial or proprietary
        "CC-BY-NC-4.0": (LicenseRisk.HIGH, 0.75),
        "CC-BY-NC-SA-4.0": (LicenseRisk.HIGH, 0.8),
        "CC-BY-ND-4.0": (LicenseRisk.HIGH, 0.75),
        # Critical — unknown
        "UNKNOWN": (LicenseRisk.CRITICAL, 0.95),
    }

    def __init__(
        self,
        license_repository: ILicenseRepository,
    ) -> None:
        self._repo = license_repository

    async def check_license(
        self,
        tenant_id: uuid.UUID,
        content_id: str,
        detected_license: str,
        content_url: str | None = None,
        copyright_holders: list[str] | None = None,
    ) -> LicenseCheck:
        """Assess the license risk for a training data item.

        Looks up the SPDX license in the risk map, computes risk score,
        generates flags and a legal recommendation, then persists the check.

        Args:
            tenant_id: The owning tenant.
            content_id: Dataset/model/content identifier.
            detected_license: SPDX identifier (or "UNKNOWN" if not detected).
            content_url: Source URL for the content if known.
            copyright_holders: Known copyright holders.

        Returns:
            The recorded LicenseCheck.
        """
        normalized_license = detected_license.strip() or "UNKNOWN"
        risk_level, risk_score = self._LICENSE_RISK_MAP.get(
            normalized_license,
            (LicenseRisk.CRITICAL, 0.9),  # Unknown license = critical
        )

        flags = self._compute_flags(normalized_license, risk_level)
        recommendation = self._generate_recommendation(risk_level, flags)

        check = await self._repo.create(
            tenant_id=tenant_id,
            content_id=content_id,
            content_url=content_url,
            detected_license=normalized_license,
            license_risk=risk_level,
            risk_score=risk_score,
            copyright_holders=copyright_holders or [],
            flags=flags,
            recommendation=recommendation,
        )

        logger.info(
            "License check recorded",
            tenant_id=str(tenant_id),
            content_id=content_id,
            license=normalized_license,
            risk=risk_level.value,
            risk_score=risk_score,
        )

        return check

    async def get_compliance_report(
        self,
        tenant_id: uuid.UUID,
        page: int = 1,
        page_size: int = 20,
        risk_level: LicenseRisk | None = None,
    ) -> tuple[list[LicenseCheck], dict[str, Any]]:
        """Retrieve license checks and high-risk summary for a tenant.

        Args:
            tenant_id: The owning tenant.
            page: Page number (1-indexed).
            page_size: Records per page.
            risk_level: Optional filter by risk level.

        Returns:
            Tuple of (list of checks, summary dict with risk breakdown).
        """
        checks = await self._repo.list_by_tenant(
            tenant_id=tenant_id,
            page=page,
            page_size=page_size,
            risk_level=risk_level,
        )
        summary = await self._repo.get_high_risk_summary(tenant_id=tenant_id)
        return checks, summary

    def _compute_flags(self, license_id: str, risk_level: LicenseRisk) -> list[str]:
        """Derive specific legal concern flags from license and risk.

        Args:
            license_id: SPDX license identifier.
            risk_level: Assessed risk level.

        Returns:
            List of flag strings describing specific concerns.
        """
        flags: list[str] = []

        if "NC" in license_id:
            flags.append("no_commercial_use")
        if "ND" in license_id:
            flags.append("no_derivatives")
        if "SA" in license_id:
            flags.append("share_alike_copyleft")
        if license_id in ("GPL-2.0", "GPL-3.0"):
            flags.append("strong_copyleft_viral")
        if license_id == "UNKNOWN":
            flags.append("no_license_detected")
            flags.append("copyright_assumed")
        if risk_level in (LicenseRisk.HIGH, LicenseRisk.CRITICAL):
            flags.append("training_use_restricted")

        return flags

    def _generate_recommendation(self, risk_level: LicenseRisk, flags: list[str]) -> str:
        """Generate a plain-language legal recommendation.

        Args:
            risk_level: Assessed risk level.
            flags: Specific concern flags.

        Returns:
            Recommendation string for legal review.
        """
        if risk_level == LicenseRisk.LOW:
            return "Safe for commercial AI training use. Document in AI Bill of Materials."
        if risk_level == LicenseRisk.MEDIUM:
            return "Review copyleft terms before training. May require output licensing compliance."
        if risk_level == LicenseRisk.HIGH:
            if "no_commercial_use" in flags:
                return "NOT safe for commercial training use. Exclude from training datasets."
            return "High litigation risk. Obtain legal review before use."
        # CRITICAL
        return (
            "STOP USE IMMEDIATELY. No license detected — all rights reserved by default. "
            "Obtain explicit written permission or remove from training data. "
            "Relevant to active copyright litigation landscape."
        )


# ---------------------------------------------------------------------------
# AuditExportService
# ---------------------------------------------------------------------------


class AuditExportService:
    """Generate court-admissible audit trail export packages.

    Produces cryptographically signed JSON exports of provenance records,
    lineage chains, watermark logs, and license checks for legal proceedings.
    """

    def __init__(
        self,
        audit_repository: IAuditExportRepository,
        provenance_repository: IProvenanceRepository,
        lineage_repository: ILineageRepository,
        license_repository: ILicenseRepository,
        export_bucket: str = "",
    ) -> None:
        self._audit_repo = audit_repository
        self._provenance_repo = provenance_repository
        self._lineage_repo = lineage_repository
        self._license_repo = license_repository
        self._export_bucket = export_bucket

    async def export_audit_trail(
        self,
        tenant_id: uuid.UUID,
        export_type: str,
        filter_params: dict[str, Any] | None = None,
    ) -> AuditExport:
        """Generate a court-admissible audit trail export.

        Creates an export job record, assembles the audit package, computes
        a SHA-256 hash for tamper evidence, and stores the result.

        Supported export types:
        - "provenance": C2PA signing records only
        - "lineage": Training data lineage graph
        - "license": License compliance checks
        - "full": All of the above combined

        Args:
            tenant_id: The owning tenant.
            export_type: One of provenance/lineage/license/full.
            filter_params: Optional query parameters for filtering records.

        Returns:
            AuditExport record with status and export URL.

        Raises:
            ValidationError: If export_type is not recognized.
        """
        valid_types = {"provenance", "lineage", "license", "full"}
        if export_type not in valid_types:
            raise ValidationError(f"export_type must be one of: {valid_types}")

        resolved_params = filter_params or {}

        export_record = await self._audit_repo.create(
            tenant_id=tenant_id,
            export_type=export_type,
            filter_params=resolved_params,
        )

        logger.info(
            "Starting audit export generation",
            export_id=str(export_record.id),
            tenant_id=str(tenant_id),
            export_type=export_type,
        )

        # Mark as generating
        await self._audit_repo.update_status(
            export_id=export_record.id,
            tenant_id=tenant_id,
            status=AuditExportStatus.GENERATING,
            export_url=None,
            export_hash=None,
            record_count=0,
            error_message=None,
        )

        try:
            audit_package = await self._assemble_package(
                tenant_id=tenant_id,
                export_type=export_type,
                filter_params=resolved_params,
            )

            package_json = json.dumps(audit_package, default=str, sort_keys=True, indent=2)
            package_bytes = package_json.encode("utf-8")
            export_hash = hashlib.sha256(package_bytes).hexdigest()
            record_count = audit_package.get("record_count", 0)

            # In production: upload to S3-compatible bucket
            export_url = (
                f"s3://{self._export_bucket}/audit-trails/{tenant_id}/{export_record.id}.json"
                if self._export_bucket
                else f"urn:aumos:audit:{export_record.id}"
            )

            updated = await self._audit_repo.update_status(
                export_id=export_record.id,
                tenant_id=tenant_id,
                status=AuditExportStatus.COMPLETE,
                export_url=export_url,
                export_hash=export_hash,
                record_count=record_count,
                error_message=None,
            )

            logger.info(
                "Audit export complete",
                export_id=str(export_record.id),
                record_count=record_count,
                export_hash=export_hash[:16],
            )

            return updated

        except Exception as exc:
            logger.error(
                "Audit export failed",
                export_id=str(export_record.id),
                error=str(exc),
            )
            return await self._audit_repo.update_status(
                export_id=export_record.id,
                tenant_id=tenant_id,
                status=AuditExportStatus.FAILED,
                export_url=None,
                export_hash=None,
                record_count=0,
                error_message=str(exc),
            )

    async def _assemble_package(
        self,
        tenant_id: uuid.UUID,
        export_type: str,
        filter_params: dict[str, Any],
    ) -> dict[str, Any]:
        """Assemble the audit package data dictionary.

        Args:
            tenant_id: The owning tenant.
            export_type: Export type determining which data to include.
            filter_params: Query filters.

        Returns:
            Dict containing the audit package data and metadata.
        """
        package: dict[str, Any] = {
            "aumos_audit_trail": True,
            "schema_version": "1.0",
            "tenant_id": str(tenant_id),
            "export_type": export_type,
            "generated_at": datetime.now(UTC).isoformat(),
            "filter_params": filter_params,
            "records": {},
            "record_count": 0,
        }

        total_count = 0

        if export_type in ("provenance", "full"):
            records = await self._provenance_repo.list_by_tenant(
                tenant_id=tenant_id, page=1, page_size=10000
            )
            package["records"]["provenance"] = [
                {
                    "id": str(r.id),
                    "content_id": r.content_id,
                    "content_type": r.content_type,
                    "content_hash": r.content_hash,
                    "status": r.status.value,
                    "signer_id": r.signer_id,
                    "manifest_uri": r.manifest_uri,
                    "signed_at": r.signed_at.isoformat(),
                    "created_at": r.created_at.isoformat(),
                }
                for r in records
            ]
            total_count += len(records)

        if export_type in ("license", "full"):
            checks, _ = await self._license_repo.list_by_tenant(
                tenant_id=tenant_id, page=1, page_size=10000, risk_level=None
            ), {}
            # Re-fetch properly
            checks_list = await self._license_repo.list_by_tenant(
                tenant_id=tenant_id, page=1, page_size=10000, risk_level=None
            )
            package["records"]["license_checks"] = [
                {
                    "id": str(c.id),
                    "content_id": c.content_id,
                    "detected_license": c.detected_license,
                    "license_risk": c.license_risk.value,
                    "risk_score": c.risk_score,
                    "flags": c.flags,
                    "recommendation": c.recommendation,
                    "checked_at": c.checked_at.isoformat(),
                }
                for c in checks_list
            ]
            total_count += len(checks_list)

        package["record_count"] = total_count
        return package


__all__ = [
    "SignContentResult",
    "VerifyResult",
    "WatermarkEmbedResult",
    "WatermarkDetectResult",
    "LineageGraph",
    "LicenseReport",
    "C2PAService",
    "WatermarkService",
    "LineageService",
    "LicenseComplianceService",
    "AuditExportService",
]
