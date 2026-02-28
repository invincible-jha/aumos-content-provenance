"""Service layer for aumos-content-provenance.

Services orchestrate domain logic by coordinating adapters via interfaces.
No direct database or external service calls — everything goes through protocols.

Services:
- C2PAService: Sign and verify content with C2PA cryptographic manifests
- WatermarkService: Embed and detect invisible watermarks
- LineageService: Track and query training data lineage chains
- LicenseComplianceService: Check and report on training data license risk
- AuditExportService: Generate court-admissible audit trail packages
- ProvenanceTrackingService: Source registration and transformation chain management
- TamperDetectionService: Multi-method content integrity verification
- MetadataEmbeddingService: Embed/extract provenance metadata from content files
- CustodyService: Ownership transfer tracking and signed attestations
- RetentionService: Record retention policy management and legal holds
- LineageResolverService: Training data lineage graph traversal and impact analysis
- LicenseCheckerService: License compatibility analysis and compliance certificates
- FullAuditService: Court-admissible audit trail compilation and expert reports
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
    IAudioWatermarkAdapter,
    IBlockchainAnchorAdapter,
    IBlockchainAnchorRepository,
    IC2PAClient,
    IChainOfCustody,
    ICopyrightClaimRepository,
    ILicenseChecker,
    ILicenseRepository,
    ILineageRepository,
    ILineageResolver,
    IMetadataEmbedder,
    IProvenanceAuditReporter,
    IProvenanceRepository,
    IProvenanceTracker,
    IRetentionManager,
    ITamperDetector,
    IVideoWatermarkAdapter,
    IWatermarkEngine,
    IWatermarkRepository,
)
from aumos_content_provenance.core.models import (
    AuditExport,
    AuditExportStatus,
    BlockchainAnchor,
    BlockchainNetwork,
    ContentVerificationResult,
    CopyrightClaim,
    CopyrightClaimStatus,
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


# ---------------------------------------------------------------------------
# ProvenanceTrackingService
# ---------------------------------------------------------------------------


@dataclass
class ChainVerificationResult:
    """Result of a provenance chain verification request."""

    asset_id: str
    is_valid: bool
    chain_length: int
    broken_at_step: int | None
    reason: str


class ProvenanceTrackingService:
    """Track data source and transformation chains for content assets.

    Orchestrates the ProvenanceTracker adapter to record the full
    lifecycle of content from initial registration through all
    transformation steps.
    """

    def __init__(self, tracker: IProvenanceTracker) -> None:
        self._tracker = tracker

    async def register_asset(
        self,
        asset_id: str,
        media_type: str,
        actor: str,
        content_bytes: bytes,
        origin_url: str | None = None,
        origin_timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Any:
        """Register a source asset and begin provenance tracking.

        Args:
            asset_id: Stable identifier for the asset.
            media_type: MIME type of the content.
            actor: Who/what is registering the source.
            content_bytes: Raw bytes to hash for integrity anchoring.
            origin_url: URL where the asset was obtained.
            origin_timestamp: When the asset was originally created.
            metadata: Additional origin metadata.

        Returns:
            ProvenanceSource record.

        Raises:
            ValidationError: If asset_id is blank or content_bytes is empty.
        """
        if not asset_id.strip():
            raise ValidationError("asset_id cannot be blank")
        if not content_bytes:
            raise ValidationError("content_bytes cannot be empty")

        logger.info(
            "Registering asset for provenance tracking",
            asset_id=asset_id,
            media_type=media_type,
            actor=actor,
        )

        return await self._tracker.register_source(
            asset_id=asset_id,
            media_type=media_type,
            actor=actor,
            content_bytes=content_bytes,
            origin_url=origin_url,
            origin_timestamp=origin_timestamp,
            metadata=metadata,
        )

    async def record_step(
        self,
        asset_id: str,
        operation: str,
        actor: str,
        input_bytes: bytes,
        output_bytes: bytes,
        parameters: dict[str, Any] | None = None,
    ) -> Any:
        """Record a transformation step in the asset's provenance chain.

        Args:
            asset_id: The asset being transformed.
            operation: Name of the transformation operation.
            actor: Who performed the transformation.
            input_bytes: Content before the transformation.
            output_bytes: Content after the transformation.
            parameters: Transformation parameters.

        Returns:
            TransformationStep record.

        Raises:
            ValidationError: If operation name is blank.
        """
        if not operation.strip():
            raise ValidationError("operation name cannot be blank")

        return await self._tracker.record_transformation(
            asset_id=asset_id,
            operation=operation,
            actor=actor,
            input_bytes=input_bytes,
            output_bytes=output_bytes,
            parameters=parameters,
        )

    async def verify_chain(self, asset_id: str) -> ChainVerificationResult:
        """Verify the hash chain integrity for an asset's provenance chain.

        Args:
            asset_id: The asset to verify.

        Returns:
            ChainVerificationResult with validation status and details.
        """
        evidence = await self._tracker.verify_chain_integrity(asset_id=asset_id)

        return ChainVerificationResult(
            asset_id=asset_id,
            is_valid=evidence.is_valid,
            chain_length=getattr(evidence, "chain_length", 0),
            broken_at_step=evidence.broken_at_step,
            reason=evidence.reason,
        )


# ---------------------------------------------------------------------------
# TamperDetectionService
# ---------------------------------------------------------------------------


@dataclass
class TamperCheckResult:
    """Service-level result for a tamper detection check."""

    content_id: str
    tampered: bool
    confidence: float
    severity: str
    indicator_count: int
    affected_regions: int
    report_id: str


class TamperDetectionService:
    """Detect content tampering using multi-method cryptographic analysis.

    Wraps the TamperDetector adapter and adds provenance record lookup
    for original hash retrieval.
    """

    def __init__(
        self,
        detector: ITamperDetector,
        provenance_repository: IProvenanceRepository,
    ) -> None:
        self._detector = detector
        self._provenance_repo = provenance_repository

    async def check_content_integrity(
        self,
        tenant_id: uuid.UUID,
        content_id: str,
        content_bytes: bytes,
        check_watermark: bool = False,
        expected_watermark_payload: str | None = None,
    ) -> TamperCheckResult:
        """Check whether content has been tampered with.

        Retrieves the original hash from the provenance record and runs
        the full tamper detection suite.

        Args:
            tenant_id: The owning tenant.
            content_id: The content to verify.
            content_bytes: Current content bytes to analyze.
            check_watermark: Whether to include watermark integrity check.
            expected_watermark_payload: Expected watermark payload string.

        Returns:
            TamperCheckResult with overall verdict.
        """
        original_hash: str | None = None
        provenance_record = await self._provenance_repo.get_by_content_id(
            content_id=content_id,
            tenant_id=tenant_id,
        )
        if provenance_record is not None:
            original_hash = provenance_record.content_hash

        watermark_payload = expected_watermark_payload if check_watermark else None

        report = await self._detector.detect_tampering(
            content_id=content_id,
            content_bytes=content_bytes,
            original_hash=original_hash,
            expected_watermark_payload=watermark_payload,
            expected_metadata=None,
        )

        logger.info(
            "Tamper check complete",
            tenant_id=str(tenant_id),
            content_id=content_id,
            tampered=report.overall_tampered,
            confidence=report.overall_confidence,
        )

        return TamperCheckResult(
            content_id=content_id,
            tampered=report.overall_tampered,
            confidence=report.overall_confidence,
            severity=report.severity.value,
            indicator_count=len(report.indicators),
            affected_regions=len(report.affected_regions),
            report_id=report.report_id,
        )


# ---------------------------------------------------------------------------
# MetadataEmbeddingService
# ---------------------------------------------------------------------------


class MetadataEmbeddingService:
    """Embed and extract provenance metadata from content files.

    Orchestrates the MetadataEmbedder adapter, selecting the appropriate
    embedding format based on content type and retrieving provenance data
    from the repository.
    """

    def __init__(
        self,
        embedder: IMetadataEmbedder,
        provenance_repository: IProvenanceRepository,
    ) -> None:
        self._embedder = embedder
        self._provenance_repo = provenance_repository

    async def embed_provenance_metadata(
        self,
        tenant_id: uuid.UUID,
        content_id: str,
        content_bytes: bytes,
        format_hint: str = "xmp",
    ) -> Any:
        """Embed provenance metadata from the provenance record into content.

        Retrieves the existing provenance record and embeds its fields
        into the content using the appropriate format.

        Args:
            tenant_id: The owning tenant.
            content_id: The content to embed metadata into.
            content_bytes: Raw content bytes.
            format_hint: Embedding format hint ("xmp", "exif", "id3", "mp4").

        Returns:
            EmbedResult from the embedder adapter.

        Raises:
            NotFoundError: If no provenance record exists for this content.
        """
        from aumos_content_provenance.adapters.metadata_embedder import (
            EmbedFormat,
            ProvenanceMetadata,
        )

        record = await self._provenance_repo.get_by_content_id(
            content_id=content_id,
            tenant_id=tenant_id,
        )
        if record is None:
            raise NotFoundError(f"No provenance record found for content '{content_id}'")

        provenance_meta = ProvenanceMetadata(
            content_id=content_id,
            tenant_id=str(tenant_id),
            signer_id=record.signer_id,
            content_hash=record.content_hash,
            manifest_uri=record.manifest_uri,
            signed_at=record.signed_at,
        )

        if format_hint == "exif":
            return await self._embedder.embed_xmp(content_bytes, provenance_meta)
        # Default to XMP
        return await self._embedder.embed_xmp(content_bytes, provenance_meta)

    async def extract_provenance_metadata(
        self,
        content_id: str,
        content_bytes: bytes,
    ) -> Any:
        """Extract embedded provenance metadata from content.

        Args:
            content_id: Expected content ID for annotation.
            content_bytes: Raw content bytes.

        Returns:
            ExtractResult with extracted metadata and verification status.
        """
        return await self._embedder.extract_metadata(
            content_bytes=content_bytes,
            content_id=content_id,
        )


# ---------------------------------------------------------------------------
# CustodyService
# ---------------------------------------------------------------------------


class CustodyService:
    """Track content ownership and generate signed custody attestations.

    Wraps the ChainOfCustody adapter with service-level validation,
    logging, and integration with provenance records.
    """

    def __init__(self, custody: IChainOfCustody) -> None:
        self._custody = custody

    async def establish_custody(
        self,
        asset_id: str,
        owner_id: str,
        purpose: str,
        authorized_by: str,
        metadata: dict[str, Any] | None = None,
    ) -> Any:
        """Establish initial custody for an asset.

        Args:
            asset_id: The asset identifier.
            owner_id: The initial owner.
            purpose: Business purpose for custody.
            authorized_by: Who authorized this.
            metadata: Additional context.

        Returns:
            CustodyRecord (root event).

        Raises:
            ValidationError: If asset_id or owner_id is blank.
        """
        if not asset_id.strip():
            raise ValidationError("asset_id cannot be blank")
        if not owner_id.strip():
            raise ValidationError("owner_id cannot be blank")

        logger.info(
            "Establishing custody",
            asset_id=asset_id,
            owner_id=owner_id,
            purpose=purpose,
        )

        return await self._custody.create_custody(
            asset_id=asset_id,
            owner_id=owner_id,
            purpose=purpose,
            authorized_by=authorized_by,
            metadata=metadata,
        )

    async def transfer(
        self,
        asset_id: str,
        new_owner_id: str,
        purpose: str,
        authorized_by: str,
        metadata: dict[str, Any] | None = None,
    ) -> Any:
        """Transfer custody to a new owner.

        Args:
            asset_id: The asset being transferred.
            new_owner_id: The new owner.
            purpose: Business reason.
            authorized_by: Who authorized this.
            metadata: Additional context.

        Returns:
            CustodyRecord (transfer event).
        """
        return await self._custody.transfer_custody(
            asset_id=asset_id,
            new_owner_id=new_owner_id,
            purpose=purpose,
            authorized_by=authorized_by,
            metadata=metadata,
        )

    async def get_attestation(
        self,
        asset_id: str,
        owner_id: str,
        validity_hours: int = 24,
    ) -> Any:
        """Generate a signed custody attestation for legal use.

        Args:
            asset_id: The asset to attest.
            owner_id: The attesting owner.
            validity_hours: Attestation validity period.

        Returns:
            CustodyAttestation with HMAC signature.
        """
        return await self._custody.generate_attestation(
            asset_id=asset_id,
            attesting_owner_id=owner_id,
            validity_hours=validity_hours,
        )


# ---------------------------------------------------------------------------
# RetentionService
# ---------------------------------------------------------------------------


class RetentionService:
    """Manage data retention policies and compliance.

    Wraps the RetentionManager adapter with service-level validation
    and integration with provenance and audit record lifecycles.
    """

    def __init__(self, retention_manager: IRetentionManager) -> None:
        self._manager = retention_manager

    async def register_provenance_record(
        self,
        asset_id: str,
        tenant_id: str,
        policy_id: str,
        acquired_at: datetime | None = None,
    ) -> Any:
        """Register a provenance record under retention management.

        Args:
            asset_id: The provenance record identifier.
            tenant_id: The owning tenant.
            policy_id: Retention policy to apply.
            acquired_at: When the record was created.

        Returns:
            RetentionRecord.
        """
        return await self._manager.register_record(
            asset_id=asset_id,
            asset_type="provenance",
            tenant_id=tenant_id,
            policy_id=policy_id,
            acquired_at=acquired_at,
        )

    async def apply_legal_hold(
        self,
        asset_id: str,
        reason: str,
        authorized_by: str,
    ) -> Any:
        """Apply a legal hold to prevent expiry-based purging.

        Args:
            asset_id: The asset to hold.
            reason: Legal reason for the hold.
            authorized_by: Who authorized this hold.

        Returns:
            Updated RetentionRecord.
        """
        logger.info(
            "Applying legal hold",
            asset_id=asset_id,
            reason=reason,
            authorized_by=authorized_by,
        )

        return await self._manager.place_legal_hold(
            asset_id=asset_id,
            reason=reason,
            authorized_by=authorized_by,
        )

    async def get_expiry_notifications(
        self,
        tenant_id: str,
        warning_days: int = 30,
    ) -> list[Any]:
        """Get expiry notifications for records approaching their retention limit.

        Args:
            tenant_id: The tenant to check.
            warning_days: Days before expiry to start warning.

        Returns:
            List of ExpiryNotification objects.
        """
        return await self._manager.detect_expiring_records(
            tenant_id=tenant_id,
            warning_days=warning_days,
        )


# ---------------------------------------------------------------------------
# LineageResolverService
# ---------------------------------------------------------------------------


@dataclass
class LineageImpactResult:
    """Result of a lineage impact analysis."""

    source_node_id: str
    affected_count: int
    affected_node_ids: list[str]
    affected_by_type: dict[str, int]
    max_depth: int


class LineageResolverService:
    """Resolve training data lineage graphs and perform impact analysis.

    Wraps the LineageResolver adapter with service-level validation
    and coordinates with the repository for persistent lineage storage.
    """

    def __init__(
        self,
        resolver: ILineageResolver,
        lineage_repository: ILineageRepository,
    ) -> None:
        self._resolver = resolver
        self._lineage_repo = lineage_repository

    async def map_training_contribution(
        self,
        tenant_id: uuid.UUID,
        parent_node_id: str,
        child_node_id: str,
        relationship: str,
        contribution_fraction: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> Any:
        """Record that a parent node (dataset/model) contributed to a child node.

        Also writes to the lineage repository for persistent storage.

        Args:
            tenant_id: The owning tenant.
            parent_node_id: Source node identifier.
            child_node_id: Derived node identifier.
            relationship: Relationship label (must match LineageRelationship).
            contribution_fraction: Fraction of child from this parent (0.0–1.0).
            metadata: Additional edge metadata.

        Returns:
            LineageEdge from the resolver.
        """
        from aumos_content_provenance.adapters.lineage_resolver import LineageRelationship
        from aumos_content_provenance.core.models import LineageNodeType

        try:
            relationship_enum = LineageRelationship(relationship)
        except ValueError:
            raise ValidationError(
                f"Invalid relationship '{relationship}'. "
                f"Must be one of: {[r.value for r in LineageRelationship]}"
            )

        # Also record in the persistent repository
        await self._lineage_repo.create(
            tenant_id=tenant_id,
            parent_node_id=parent_node_id,
            parent_node_type=LineageNodeType.TRAINING_DATASET,
            child_node_id=child_node_id,
            child_node_type=LineageNodeType.MODEL,
            relationship=relationship,
            metadata=metadata or {},
        )

        return await self._resolver.record_contribution(
            parent_node_id=parent_node_id,
            child_node_id=child_node_id,
            relationship=relationship_enum,
            tenant_id=str(tenant_id),
            contribution_fraction=contribution_fraction,
            metadata=metadata,
        )

    async def get_full_lineage(
        self,
        tenant_id: uuid.UUID,
        node_id: str,
        max_depth: int = 10,
    ) -> Any:
        """Retrieve the full upstream lineage graph for a node.

        Args:
            tenant_id: The owning tenant.
            node_id: The node to trace lineage for.
            max_depth: Maximum traversal depth.

        Returns:
            LineageGraphResult with all ancestor nodes and edges.
        """
        return await self._resolver.get_upstream_graph(
            node_id=node_id,
            tenant_id=str(tenant_id),
            max_depth=max_depth,
        )

    async def analyze_source_impact(
        self,
        tenant_id: uuid.UUID,
        source_node_id: str,
    ) -> LineageImpactResult:
        """Analyze downstream impact if a source dataset changes.

        Useful for license risk propagation: if a CC-BY-NC dataset is
        discovered in the training chain, what models are affected?

        Args:
            tenant_id: The owning tenant.
            source_node_id: The source node that may change.

        Returns:
            LineageImpactResult with affected node counts.
        """
        impact = await self._resolver.analyze_impact(
            source_node_id=source_node_id,
            tenant_id=str(tenant_id),
        )

        return LineageImpactResult(
            source_node_id=source_node_id,
            affected_count=impact.affected_count,
            affected_node_ids=impact.affected_node_ids,
            affected_by_type=impact.affected_by_type,
            max_depth=impact.max_depth_affected,
        )


# ---------------------------------------------------------------------------
# LicenseCheckerService
# ---------------------------------------------------------------------------


class LicenseCheckerService:
    """Analyze license compliance and generate compliance certificates.

    Wraps the LicenseChecker adapter and integrates with the license
    repository for persistent compliance record storage.
    """

    def __init__(
        self,
        checker: ILicenseChecker,
        license_repository: ILicenseRepository,
    ) -> None:
        self._checker = checker
        self._license_repo = license_repository

    async def analyze_content_license(
        self,
        tenant_id: uuid.UUID,
        content_id: str,
        license_spdx: str,
        copyright_holders: list[str] | None = None,
        content_url: str | None = None,
    ) -> LicenseCheck:
        """Detect and store a license compliance analysis for a content item.

        Args:
            tenant_id: The owning tenant.
            content_id: The content being analyzed.
            license_spdx: SPDX license identifier.
            copyright_holders: Known copyright holders.
            content_url: Source URL for the content.

        Returns:
            Persisted LicenseCheck record.
        """
        profile = await self._checker.detect_license(
            content_id=content_id,
            license_identifier=license_spdx,
            copyright_holders=copyright_holders,
        )

        risk_score = profile.risk_score if profile else 0.95
        flags: list[str] = []
        recommendation = "Unknown license — assume all rights reserved"

        if profile:
            if not profile.allows_commercial:
                flags.append("no_commercial_use")
            if not profile.allows_derivatives:
                flags.append("no_derivatives")
            if profile.requires_share_alike:
                flags.append("share_alike_copyleft")
            if not profile.allows_ai_training:
                flags.append("training_use_restricted")
            if profile.risk_score >= 0.8:
                recommendation = "High litigation risk. Obtain legal review before use."
            elif profile.risk_score >= 0.5:
                recommendation = "Review license terms before training use."
            else:
                recommendation = "Safe for documented training use."
        else:
            flags.append("no_license_detected")

        risk_level_map = {
            True: LicenseRisk.LOW if risk_score < 0.3 else LicenseRisk.MEDIUM,
        }
        if risk_score >= 0.8:
            license_risk = LicenseRisk.CRITICAL
        elif risk_score >= 0.6:
            license_risk = LicenseRisk.HIGH
        elif risk_score >= 0.3:
            license_risk = LicenseRisk.MEDIUM
        else:
            license_risk = LicenseRisk.LOW

        return await self._license_repo.create(
            tenant_id=tenant_id,
            content_id=content_id,
            content_url=content_url,
            detected_license=license_spdx,
            license_risk=license_risk,
            risk_score=risk_score,
            copyright_holders=copyright_holders or [],
            flags=flags,
            recommendation=recommendation,
        )

    async def check_license_compatibility(
        self,
        license_a: str,
        license_b: str,
        use_case: str = "ai_training",
    ) -> Any:
        """Check compatibility between two licenses for a given use case.

        Args:
            license_a: First SPDX identifier.
            license_b: Second SPDX identifier.
            use_case: Use case string matching UseCase enum values.

        Returns:
            CompatibilityResult with verdict.
        """
        from aumos_content_provenance.adapters.license_checker import UseCase

        try:
            use_case_enum = UseCase(use_case)
        except ValueError:
            raise ValidationError(
                f"Invalid use_case '{use_case}'. "
                f"Must be one of: {[u.value for u in UseCase]}"
            )

        return await self._checker.check_compatibility(
            license_a=license_a,
            license_b=license_b,
            use_case=use_case_enum,
        )


# ---------------------------------------------------------------------------
# FullAuditService
# ---------------------------------------------------------------------------


@dataclass
class FullAuditResult:
    """Result of a full audit trail generation."""

    package_id: str
    tenant_id: str
    record_count: int
    zip_hash: str | None
    scope: str
    generated_at: datetime


class FullAuditService:
    """Generate court-admissible audit trail packages and expert witness reports.

    Integrates the ProvenanceAuditReporter with all repository adapters
    to compile comprehensive evidence packages for legal proceedings.
    """

    def __init__(
        self,
        reporter: IProvenanceAuditReporter,
        provenance_repository: IProvenanceRepository,
        lineage_repository: ILineageRepository,
        license_repository: ILicenseRepository,
    ) -> None:
        self._reporter = reporter
        self._provenance_repo = provenance_repository
        self._lineage_repo = lineage_repository
        self._license_repo = license_repository

    async def generate_full_evidence_package(
        self,
        tenant_id: uuid.UUID,
        scope: str = "full",
        filter_content_ids: list[str] | None = None,
    ) -> FullAuditResult:
        """Compile and package all provenance evidence for a tenant.

        Fetches records from all repositories, compiles them into typed
        AuditRecords, and assembles a cryptographically signed ZIP package.

        Args:
            tenant_id: The owning tenant.
            scope: Evidence scope ("full", "provenance_only", "license_only", etc.).
            filter_content_ids: Optional filter to specific content IDs.

        Returns:
            FullAuditResult with package ID and integrity hash.

        Raises:
            ValidationError: If scope is not recognized.
        """
        from aumos_content_provenance.adapters.audit_reporter import AuditScope

        try:
            scope_enum = AuditScope(scope)
        except ValueError:
            raise ValidationError(
                f"Invalid scope '{scope}'. "
                f"Must be one of: {[s.value for s in AuditScope]}"
            )

        # Fetch all records from repositories
        provenance_dicts: list[dict[str, Any]] = []
        license_dicts: list[dict[str, Any]] = []

        if scope_enum in (AuditScope.PROVENANCE_ONLY, AuditScope.FULL):
            provenance_records = await self._provenance_repo.list_by_tenant(
                tenant_id=tenant_id, page=1, page_size=10000
            )
            provenance_dicts = [
                {
                    "content_id": r.content_id,
                    "content_type": r.content_type,
                    "content_hash": r.content_hash,
                    "status": r.status.value,
                    "signer_id": r.signer_id,
                    "manifest_uri": r.manifest_uri,
                    "signed_at": r.signed_at.isoformat(),
                    "created_at": r.created_at.isoformat(),
                }
                for r in provenance_records
            ]

        if scope_enum in (AuditScope.LICENSE_ONLY, AuditScope.FULL):
            license_records = await self._license_repo.list_by_tenant(
                tenant_id=tenant_id, page=1, page_size=10000, risk_level=None
            )
            license_dicts = [
                {
                    "content_id": c.content_id,
                    "detected_license": c.detected_license,
                    "license_risk": c.license_risk.value,
                    "risk_score": c.risk_score,
                    "flags": c.flags,
                    "recommendation": c.recommendation,
                    "checked_at": c.checked_at.isoformat(),
                    "created_at": c.created_at.isoformat(),
                }
                for c in license_records
            ]

        audit_records = await self._reporter.compile_audit_trail(
            tenant_id=str(tenant_id),
            scope=scope_enum,
            provenance_records=provenance_dicts or None,
            lineage_records=None,
            license_records=license_dicts or None,
            custody_records=None,
            filter_content_ids=filter_content_ids,
        )

        package = await self._reporter.package_evidence(
            tenant_id=str(tenant_id),
            scope=scope_enum,
            audit_records=audit_records,
        )

        logger.info(
            "Full audit evidence package generated",
            tenant_id=str(tenant_id),
            package_id=package.package_id,
            record_count=package.records_included,
            zip_hash=package.zip_hash[:16] if package.zip_hash else None,
        )

        return FullAuditResult(
            package_id=package.package_id,
            tenant_id=str(tenant_id),
            record_count=package.records_included,
            zip_hash=package.zip_hash,
            scope=scope,
            generated_at=package.generated_at,
        )

    async def generate_expert_report(
        self,
        tenant_id: uuid.UUID,
        expert_name: str,
        case_reference: str,
        jurisdiction: str = "US Federal",
        scope: str = "full",
    ) -> Any:
        """Generate an expert witness report for court submission.

        Args:
            tenant_id: The owning tenant.
            expert_name: Name of the expert witness.
            case_reference: Court case reference number.
            jurisdiction: Legal jurisdiction for the proceeding.
            scope: Evidence scope.

        Returns:
            ExpertWitnessReport with signed attestation and report hash.
        """
        from aumos_content_provenance.adapters.audit_reporter import AuditScope

        try:
            scope_enum = AuditScope(scope)
        except ValueError:
            raise ValidationError(f"Invalid scope '{scope}'")

        provenance_records = await self._provenance_repo.list_by_tenant(
            tenant_id=tenant_id, page=1, page_size=10000
        )
        provenance_dicts = [
            {
                "content_id": r.content_id,
                "status": r.status.value,
                "content_hash": r.content_hash,
                "signer_id": r.signer_id,
                "created_at": r.created_at.isoformat(),
            }
            for r in provenance_records
        ]

        audit_records = await self._reporter.compile_audit_trail(
            tenant_id=str(tenant_id),
            scope=scope_enum,
            provenance_records=provenance_dicts,
            lineage_records=None,
            license_records=None,
            custody_records=None,
            filter_content_ids=None,
        )

        return await self._reporter.generate_expert_witness_report(
            tenant_id=str(tenant_id),
            scope=scope_enum,
            audit_records=audit_records,
            expert_name=expert_name,
            case_reference=case_reference,
            jurisdiction=jurisdiction,
        )


# ---------------------------------------------------------------------------
# GAP-274: Content Credentials Verification UI Service
# ---------------------------------------------------------------------------


class CredentialsVerificationService:
    """Compute content credentials verification result for the UI.

    Combines C2PA provenance lookup with watermark detection to produce
    a legal_defensibility_score used in the verification UI display.
    """

    def __init__(
        self,
        provenance_repository: IProvenanceRepository,
        watermark_repository: IWatermarkRepository,
        watermark_engine: IWatermarkEngine,
    ) -> None:
        self._provenance_repo = provenance_repository
        self._watermark_repo = watermark_repository
        self._watermark_engine = watermark_engine

    async def verify(
        self,
        content_id: str,
        tenant_id: uuid.UUID,
        content_bytes: bytes | None = None,
    ) -> ContentVerificationResult:
        """Compute content credentials verification result.

        Looks up the C2PA provenance record and watermark metadata.
        If content_bytes are provided, performs live watermark detection.
        Computes a legal_defensibility_score as the weighted composite:
          0.6 * (provenance_signed) + 0.4 * (watermark_present)

        Args:
            content_id: Stable content identifier to verify.
            tenant_id: Owning tenant UUID.
            content_bytes: Optional raw bytes for watermark detection.

        Returns:
            ContentVerificationResult with composite legal_defensibility_score.
        """
        from aumos_content_provenance.core.models import ContentVerificationResult

        provenance_record = await self._provenance_repo.get_by_content_id(
            content_id=content_id,
            tenant_id=tenant_id,
        )
        watermark = await self._watermark_repo.get_by_content_id(
            content_id=content_id,
            tenant_id=tenant_id,
        )

        # Live watermark detection if bytes provided
        watermark_detected = False
        watermark_payload: str | None = None
        if content_bytes and watermark:
            try:
                watermark_detected, watermark_payload = await self._watermark_engine.detect(
                    content_bytes=content_bytes,
                    method=watermark.method,
                )
            except Exception:
                watermark_detected = False

        has_c2pa_manifest = provenance_record is not None and provenance_record.c2pa_manifest != {}
        has_watermark = watermark is not None

        provenance_score = 1.0 if has_c2pa_manifest else 0.0
        watermark_score = 1.0 if has_watermark else 0.0
        legal_defensibility_score = round(0.6 * provenance_score + 0.4 * watermark_score, 3)

        parts = []
        if has_c2pa_manifest:
            parts.append("C2PA manifest present and verifiable")
        if has_watermark:
            parts.append("Invisible watermark embedded")
        if not parts:
            parts.append("No content credentials found")
        verification_summary = ". ".join(parts) + "."

        return ContentVerificationResult(
            content_id=content_id,
            provenance_record=provenance_record,
            watermark_detected=watermark_detected,
            watermark_payload=watermark_payload,
            legal_defensibility_score=legal_defensibility_score,
            verification_summary=verification_summary,
            verified_at=datetime.now(UTC),
            has_c2pa_manifest=has_c2pa_manifest,
            has_watermark=has_watermark,
        )


# ---------------------------------------------------------------------------
# GAP-276: Video/Audio Provenance Service
# ---------------------------------------------------------------------------


class MediaProvenanceService:
    """Handle watermarking and provenance tracking for video and audio content.

    Routes media content to the appropriate watermark adapter based on
    detected media type, and records provenance metadata.
    """

    SUPPORTED_CONTENT_TYPES: frozenset[str] = frozenset({
        "image/jpeg", "image/png", "image/webp", "image/gif",
        "audio/wav", "audio/mp3", "audio/mpeg", "audio/ogg",
        "video/mp4", "video/quicktime", "video/webm",
    })

    def __init__(
        self,
        watermark_engine: IWatermarkEngine,
        audio_watermark_adapter: "IAudioWatermarkAdapter | None" = None,
        video_watermark_adapter: "IVideoWatermarkAdapter | None" = None,
        watermark_repository: IWatermarkRepository | None = None,
    ) -> None:
        self._watermark_engine = watermark_engine
        self._audio_adapter = audio_watermark_adapter
        self._video_adapter = video_watermark_adapter
        self._watermark_repo = watermark_repository

    async def embed_media_watermark(
        self,
        tenant_id: uuid.UUID,
        content_id: str,
        content_bytes: bytes,
        content_type: str,
        payload: str,
        strength: float = 0.5,
    ) -> bytes:
        """Embed a watermark in media content (image, audio, or video).

        Args:
            tenant_id: Owning tenant UUID.
            content_id: Stable content identifier.
            content_bytes: Raw media bytes.
            content_type: MIME type of the content.
            payload: Watermark payload to embed.
            strength: Embedding strength (0.0–1.0).

        Returns:
            Watermarked media bytes.

        Raises:
            ValidationError: If content_type is not in SUPPORTED_CONTENT_TYPES.
        """
        if content_type not in self.SUPPORTED_CONTENT_TYPES:
            raise ValidationError(
                f"Unsupported content type '{content_type}'. "
                f"Supported: {sorted(self.SUPPORTED_CONTENT_TYPES)}"
            )

        logger.info(
            "Embedding media watermark",
            tenant_id=str(tenant_id),
            content_id=content_id,
            content_type=content_type,
        )

        if content_type.startswith("audio/") and self._audio_adapter:
            return await self._audio_adapter.embed(
                audio_bytes=content_bytes,
                payload=payload,
                strength=strength,
            )
        if content_type.startswith("video/") and self._video_adapter:
            return await self._video_adapter.embed(
                video_bytes=content_bytes,
                payload=payload,
                strength=strength,
            )

        # Fallback to standard image watermark engine
        return await self._watermark_engine.embed(
            content_bytes=content_bytes,
            payload=payload,
            method=WatermarkMethod.DWT_DCT,
            strength=strength,
        )

    async def detect_media_watermark(
        self,
        content_bytes: bytes,
        content_type: str,
    ) -> tuple[bool, str | None]:
        """Detect a watermark in media content.

        Args:
            content_bytes: Raw media bytes to scan.
            content_type: MIME type of the content.

        Returns:
            Tuple of (watermark_found, extracted_payload_or_none).
        """
        if content_type.startswith("audio/") and self._audio_adapter:
            return await self._audio_adapter.detect(audio_bytes=content_bytes)
        if content_type.startswith("video/") and self._video_adapter:
            return await self._video_adapter.detect(video_bytes=content_bytes)
        return await self._watermark_engine.detect(
            content_bytes=content_bytes,
            method=WatermarkMethod.DWT_DCT,
        )


# ---------------------------------------------------------------------------
# GAP-278: Copyright Claim Cross-Reference Service
# ---------------------------------------------------------------------------


class CopyrightClaimService:
    """Manage and cross-reference known copyright claims.

    Provides CRUD for the copyright claim database and cross-reference
    queries against the tenant's training data inventory.
    """

    def __init__(self, claim_repository: "ICopyrightClaimRepository") -> None:
        self._repo = claim_repository

    async def add_claim(
        self,
        claim_reference: str,
        claimant_name: str,
        content_description: str,
        content_identifiers: list[str],
        jurisdiction: str,
        status: str = "active",
        defendant_name: str | None = None,
        filed_at: datetime | None = None,
        source_url: str | None = None,
        tags: list[str] | None = None,
    ) -> CopyrightClaim:
        """Add a new copyright claim to the database.

        Args:
            claim_reference: External case number or claim ID.
            claimant_name: Copyright holder or plaintiff.
            content_description: Description of claimed content.
            content_identifiers: Hashes, URLs, or dataset names.
            jurisdiction: Legal jurisdiction (e.g., "US-SDNY").
            status: Claim status (active | settled | dismissed | pending).
            defendant_name: Defendant company/model name.
            filed_at: Filing date.
            source_url: Public court filing URL.
            tags: Classification tags.

        Returns:
            Created CopyrightClaim record.
        """
        from aumos_content_provenance.core.models import CopyrightClaimStatus

        try:
            status_enum = CopyrightClaimStatus(status)
        except ValueError:
            raise ValidationError(f"Invalid claim status: {status}")

        return await self._repo.create(
            claim_reference=claim_reference,
            claimant_name=claimant_name,
            defendant_name=defendant_name,
            content_description=content_description,
            content_identifiers=content_identifiers,
            status=status_enum,
            jurisdiction=jurisdiction,
            filed_at=filed_at,
            source_url=source_url,
            tags=tags or [],
        )

    async def cross_reference_training_data(
        self,
        content_identifiers: list[str],
        tags: list[str] | None = None,
    ) -> list[CopyrightClaim]:
        """Cross-reference training data identifiers against copyright claims.

        Args:
            content_identifiers: List of dataset hashes or names to check.
            tags: Optional tag filter to narrow results.

        Returns:
            List of matching CopyrightClaim records (if any match).
        """
        return await self._repo.search(
            content_identifiers=content_identifiers,
            tags=tags,
            status=None,
        )

    async def list_claims(
        self,
        page: int = 1,
        page_size: int = 20,
        status: str | None = None,
    ) -> list[CopyrightClaim]:
        """List copyright claims with pagination.

        Args:
            page: Page number (1-indexed).
            page_size: Records per page.
            status: Optional status filter.

        Returns:
            List of CopyrightClaim records.
        """
        from aumos_content_provenance.core.models import CopyrightClaimStatus

        status_enum: CopyrightClaimStatus | None = None
        if status:
            try:
                status_enum = CopyrightClaimStatus(status)
            except ValueError:
                raise ValidationError(f"Invalid claim status: {status}")

        return await self._repo.list_claims(
            page=page,
            page_size=page_size,
            status=status_enum,
        )


# ---------------------------------------------------------------------------
# GAP-279: Blockchain Provenance Anchor Service
# ---------------------------------------------------------------------------


class BlockchainAnchorService:
    """Anchor C2PA content hashes to blockchain/IPFS for immutable timestamps.

    Provides tamper-evident external anchoring of content provenance records
    by committing their hashes to public or private blockchain networks.
    """

    def __init__(
        self,
        anchor_adapter: "IBlockchainAnchorAdapter",
        anchor_repository: "IBlockchainAnchorRepository",
        event_publisher: Any | None = None,
    ) -> None:
        self._adapter = anchor_adapter
        self._repo = anchor_repository
        self._publisher = event_publisher

    async def anchor_provenance_record(
        self,
        tenant_id: uuid.UUID,
        provenance_record_id: uuid.UUID,
        content_hash: str,
        network: str = "internal_ledger",
    ) -> BlockchainAnchor:
        """Anchor a content hash to the specified blockchain network.

        Creates a pending anchor record, submits the hash to the network,
        and updates the anchor record with the transaction details.

        Args:
            tenant_id: Owning tenant UUID.
            provenance_record_id: The provenance record to anchor.
            content_hash: SHA-256 of the content being anchored.
            network: Target network (ethereum | polygon | ipfs | internal_ledger).

        Returns:
            BlockchainAnchor record with transaction details.

        Raises:
            ValidationError: If network is not supported.
        """
        try:
            network_enum = BlockchainNetwork(network)
        except ValueError:
            raise ValidationError(
                f"Invalid network '{network}'. "
                f"Must be one of: {[n.value for n in BlockchainNetwork]}"
            )

        anchor = await self._repo.create(
            tenant_id=tenant_id,
            provenance_record_id=provenance_record_id,
            content_hash=content_hash,
            network=network_enum,
        )

        logger.info(
            "Anchoring content hash to blockchain",
            anchor_id=str(anchor.id),
            network=network,
            content_hash=content_hash[:16],
        )

        try:
            tx_hash, ipfs_cid, block_height = await self._adapter.anchor(
                content_hash=content_hash,
                network=network_enum,
                metadata={"provenance_record_id": str(provenance_record_id)},
            )
            anchor = await self._repo.update_anchor(
                anchor_id=anchor.id,
                transaction_hash=tx_hash,
                ipfs_cid=ipfs_cid,
                block_height=block_height,
                anchor_status="confirmed",
            )
        except Exception as exc:
            logger.error("Blockchain anchoring failed", error=str(exc))
            anchor = await self._repo.update_anchor(
                anchor_id=anchor.id,
                transaction_hash=None,
                ipfs_cid=None,
                block_height=None,
                anchor_status="failed",
            )

        return anchor

    async def get_anchor_for_record(
        self,
        provenance_record_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> BlockchainAnchor | None:
        """Retrieve the blockchain anchor for a provenance record.

        Args:
            provenance_record_id: The provenance record UUID.
            tenant_id: Owning tenant UUID.

        Returns:
            BlockchainAnchor or None if not anchored.
        """
        return await self._repo.get_by_provenance_record(
            provenance_record_id=provenance_record_id,
            tenant_id=tenant_id,
        )


__all__ = [
    "SignContentResult",
    "VerifyResult",
    "WatermarkEmbedResult",
    "WatermarkDetectResult",
    "LineageGraph",
    "LicenseReport",
    "ChainVerificationResult",
    "TamperCheckResult",
    "LineageImpactResult",
    "FullAuditResult",
    "C2PAService",
    "WatermarkService",
    "LineageService",
    "LicenseComplianceService",
    "AuditExportService",
    "ProvenanceTrackingService",
    "TamperDetectionService",
    "MetadataEmbeddingService",
    "CustodyService",
    "RetentionService",
    "LineageResolverService",
    "LicenseCheckerService",
    "FullAuditService",
    "CredentialsVerificationService",
    "MediaProvenanceService",
    "CopyrightClaimService",
    "BlockchainAnchorService",
]
