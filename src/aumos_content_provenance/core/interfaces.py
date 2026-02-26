"""Abstract interfaces (Protocol classes) for aumos-content-provenance.

Defining interfaces as Protocol classes enables:
  - Dependency injection in services
  - Easy mocking in tests
  - Clear contracts between adapters and the service layer

Services depend on interfaces, not concrete implementations.
"""

import uuid
from typing import Any, Protocol, runtime_checkable

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


# ---------------------------------------------------------------------------
# C2PA Engine Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IC2PAClient(Protocol):
    """Interface for C2PA SDK operations — signing and verification."""

    async def sign_content(
        self,
        content_bytes: bytes,
        content_type: str,
        claim_generator: str,
        assertions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Sign content and produce a C2PA manifest.

        Args:
            content_bytes: Raw content bytes to sign.
            content_type: MIME type of the content.
            claim_generator: Identifier of the system generating the claim.
            assertions: List of C2PA assertion objects to include.

        Returns:
            C2PA manifest dict (JUMBF JSON representation).
        """
        ...

    async def verify_manifest(
        self,
        manifest: dict[str, Any],
        content_bytes: bytes,
    ) -> tuple[bool, str]:
        """Verify a C2PA manifest against content.

        Args:
            manifest: C2PA manifest to verify.
            content_bytes: Raw content bytes for hash verification.

        Returns:
            Tuple of (is_valid, reason_message).
        """
        ...


# ---------------------------------------------------------------------------
# Watermark Engine Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IWatermarkEngine(Protocol):
    """Interface for invisible watermark embedding and detection."""

    async def embed(
        self,
        content_bytes: bytes,
        payload: str,
        method: WatermarkMethod,
        strength: float,
    ) -> bytes:
        """Embed an invisible watermark into content.

        Args:
            content_bytes: Raw image/document bytes.
            payload: The hidden payload string to embed.
            method: Watermarking algorithm to use.
            strength: Embedding strength (0.0 = invisible, 1.0 = robust).

        Returns:
            Watermarked content bytes.
        """
        ...

    async def detect(
        self,
        content_bytes: bytes,
        method: WatermarkMethod,
    ) -> tuple[bool, str | None]:
        """Detect an invisible watermark in content.

        Args:
            content_bytes: Raw image/document bytes to scan.
            method: Watermarking algorithm to use for detection.

        Returns:
            Tuple of (watermark_found, extracted_payload_or_none).
        """
        ...


# ---------------------------------------------------------------------------
# Repository Interfaces
# ---------------------------------------------------------------------------


@runtime_checkable
class IProvenanceRepository(Protocol):
    """Repository interface for ProvenanceRecord records."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        content_id: str,
        content_type: str,
        content_hash: str,
        c2pa_manifest: dict[str, Any],
        manifest_uri: str,
        status: ProvenanceStatus,
        signer_id: str,
        metadata: dict[str, Any],
    ) -> ProvenanceRecord:
        """Create a new provenance record after C2PA signing.

        Args:
            tenant_id: The owning tenant.
            content_id: Stable content identifier.
            content_type: MIME type.
            content_hash: SHA-256 of content bytes.
            c2pa_manifest: Full C2PA manifest JSON.
            manifest_uri: URI where the manifest is stored.
            status: Initial provenance status.
            signer_id: Key ID used for signing.
            metadata: Additional metadata dict.

        Returns:
            The created ProvenanceRecord.
        """
        ...

    async def get_by_content_id(
        self,
        content_id: str,
        tenant_id: uuid.UUID,
    ) -> ProvenanceRecord | None:
        """Retrieve a provenance record by content ID.

        Args:
            content_id: The stable content identifier.
            tenant_id: The owning tenant.

        Returns:
            ProvenanceRecord or None if not found.
        """
        ...

    async def get_by_id(
        self,
        record_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> ProvenanceRecord | None:
        """Retrieve a provenance record by its primary key.

        Args:
            record_id: The record UUID.
            tenant_id: The owning tenant.

        Returns:
            ProvenanceRecord or None if not found.
        """
        ...

    async def update_status(
        self,
        record_id: uuid.UUID,
        tenant_id: uuid.UUID,
        status: ProvenanceStatus,
    ) -> ProvenanceRecord:
        """Update the verification status of a provenance record.

        Args:
            record_id: The record UUID.
            tenant_id: The owning tenant.
            status: New ProvenanceStatus value.

        Returns:
            Updated ProvenanceRecord.
        """
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> list[ProvenanceRecord]:
        """List provenance records for a tenant with pagination.

        Args:
            tenant_id: The owning tenant.
            page: Page number (1-indexed).
            page_size: Records per page.

        Returns:
            List of ProvenanceRecord.
        """
        ...


@runtime_checkable
class IWatermarkRepository(Protocol):
    """Repository interface for Watermark records."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        content_id: str,
        method: WatermarkMethod,
        payload: str,
        payload_hash: str,
        strength: float,
    ) -> Watermark:
        """Record a watermark embedding operation.

        Args:
            tenant_id: The owning tenant.
            content_id: Content identifier.
            method: Watermarking method used.
            payload: The embedded payload string.
            payload_hash: SHA-256 of the payload.
            strength: Embedding strength used.

        Returns:
            The created Watermark record.
        """
        ...

    async def get_by_content_id(
        self,
        content_id: str,
        tenant_id: uuid.UUID,
    ) -> Watermark | None:
        """Retrieve watermark metadata for a content item.

        Args:
            content_id: The content identifier.
            tenant_id: The owning tenant.

        Returns:
            Watermark record or None.
        """
        ...

    async def update_detection(
        self,
        watermark_id: uuid.UUID,
        tenant_id: uuid.UUID,
        detected: bool,
    ) -> Watermark:
        """Record the result of a watermark detection check.

        Args:
            watermark_id: The watermark record UUID.
            tenant_id: The owning tenant.
            detected: Whether the watermark was found.

        Returns:
            Updated Watermark record.
        """
        ...


@runtime_checkable
class ILineageRepository(Protocol):
    """Repository interface for LineageEntry records."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        parent_node_id: str,
        parent_node_type: LineageNodeType,
        child_node_id: str,
        child_node_type: LineageNodeType,
        relationship: str,
        metadata: dict[str, Any],
    ) -> LineageEntry:
        """Record a lineage relationship edge.

        Args:
            tenant_id: The owning tenant.
            parent_node_id: Source node identifier.
            parent_node_type: Type of the source node.
            child_node_id: Derived node identifier.
            child_node_type: Type of the derived node.
            relationship: Relationship label (e.g., "trained_on").
            metadata: Additional edge metadata.

        Returns:
            The created LineageEntry.
        """
        ...

    async def get_ancestors(
        self,
        node_id: str,
        tenant_id: uuid.UUID,
        max_depth: int,
    ) -> list[LineageEntry]:
        """Retrieve the full ancestor chain for a content node.

        Traverses the lineage graph upward from a node to reconstruct
        the complete data provenance chain.

        Args:
            node_id: Starting node (typically an output content ID).
            tenant_id: The owning tenant.
            max_depth: Maximum traversal depth.

        Returns:
            Ordered list of LineageEntry edges from root to node.
        """
        ...

    async def list_by_content_id(
        self,
        content_id: str,
        tenant_id: uuid.UUID,
    ) -> list[LineageEntry]:
        """List all lineage entries where content_id is parent or child.

        Args:
            content_id: The content identifier to look up.
            tenant_id: The owning tenant.

        Returns:
            List of related LineageEntry records.
        """
        ...


@runtime_checkable
class ILicenseRepository(Protocol):
    """Repository interface for LicenseCheck records."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        content_id: str,
        content_url: str | None,
        detected_license: str,
        license_risk: LicenseRisk,
        risk_score: float,
        copyright_holders: list[str],
        flags: list[str],
        recommendation: str,
    ) -> LicenseCheck:
        """Record a license compliance check result.

        Args:
            tenant_id: The owning tenant.
            content_id: The dataset/model/content being checked.
            content_url: Source URL if known.
            detected_license: SPDX license identifier.
            license_risk: Assessed risk category.
            risk_score: Numeric risk score (0.0–1.0).
            copyright_holders: Identified rights holders.
            flags: Specific legal concern flags.
            recommendation: Legal use recommendation.

        Returns:
            The created LicenseCheck record.
        """
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
        risk_level: LicenseRisk | None,
    ) -> list[LicenseCheck]:
        """List license checks for a tenant with optional risk filter.

        Args:
            tenant_id: The owning tenant.
            page: Page number (1-indexed).
            page_size: Records per page.
            risk_level: Optional filter by risk level.

        Returns:
            List of LicenseCheck records.
        """
        ...

    async def get_high_risk_summary(
        self,
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Aggregate summary of high-risk license items.

        Args:
            tenant_id: The owning tenant.

        Returns:
            Dict with counts per risk level and top flagged items.
        """
        ...


@runtime_checkable
class IAuditExportRepository(Protocol):
    """Repository interface for AuditExport records."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        export_type: str,
        filter_params: dict[str, Any],
    ) -> AuditExport:
        """Create a new audit export job record.

        Args:
            tenant_id: The owning tenant.
            export_type: Type of export (provenance/lineage/license/full).
            filter_params: Query parameters for the export.

        Returns:
            The created AuditExport record with PENDING status.
        """
        ...

    async def update_status(
        self,
        export_id: uuid.UUID,
        tenant_id: uuid.UUID,
        status: AuditExportStatus,
        export_url: str | None,
        export_hash: str | None,
        record_count: int,
        error_message: str | None,
    ) -> AuditExport:
        """Update an audit export job with completion details.

        Args:
            export_id: The export job UUID.
            tenant_id: The owning tenant.
            status: New status.
            export_url: S3 URL of the generated package.
            export_hash: SHA-256 hash for tamper evidence.
            record_count: Number of records in the export.
            error_message: Error detail if failed.

        Returns:
            Updated AuditExport record.
        """
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> list[AuditExport]:
        """List audit exports for a tenant.

        Args:
            tenant_id: The owning tenant.
            page: Page number (1-indexed).
            page_size: Records per page.

        Returns:
            List of AuditExport records.
        """
        ...


__all__ = [
    "IC2PAClient",
    "IWatermarkEngine",
    "IProvenanceRepository",
    "IWatermarkRepository",
    "ILineageRepository",
    "ILicenseRepository",
    "IAuditExportRepository",
]
