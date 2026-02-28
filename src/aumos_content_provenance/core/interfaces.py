"""Abstract interfaces (Protocol classes) for aumos-content-provenance.

Defining interfaces as Protocol classes enables:
  - Dependency injection in services
  - Easy mocking in tests
  - Clear contracts between adapters and the service layer

Services depend on interfaces, not concrete implementations.
"""

import uuid
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

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


# ---------------------------------------------------------------------------
# Provenance Tracker Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IProvenanceTracker(Protocol):
    """Interface for data source and transformation chain tracking."""

    async def register_source(
        self,
        asset_id: str,
        media_type: str,
        actor: str,
        content_bytes: bytes,
        origin_url: str | None,
        origin_timestamp: datetime | None,
        metadata: dict[str, Any] | None,
    ) -> Any:
        """Register a source asset and record its origin metadata.

        Args:
            asset_id: Stable identifier for the asset.
            media_type: MIME type of the content.
            actor: Who/what is registering the source.
            content_bytes: Raw bytes to hash for integrity.
            origin_url: URL where the asset was obtained, if known.
            origin_timestamp: When the asset was originally created.
            metadata: Additional origin metadata.

        Returns:
            ProvenanceSource record.
        """
        ...

    async def record_transformation(
        self,
        asset_id: str,
        operation: str,
        actor: str,
        input_bytes: bytes,
        output_bytes: bytes,
        parameters: dict[str, Any] | None,
    ) -> Any:
        """Record a transformation step in the asset provenance chain.

        Args:
            asset_id: The asset being transformed.
            operation: Name of the transformation operation.
            actor: Who performed the transformation.
            input_bytes: Content before transformation.
            output_bytes: Content after transformation.
            parameters: Transformation parameters.

        Returns:
            TransformationStep record.
        """
        ...

    async def verify_chain_integrity(self, asset_id: str) -> Any:
        """Verify the hash chain integrity for an asset.

        Args:
            asset_id: The asset to verify.

        Returns:
            TamperEvidence result with is_valid flag.
        """
        ...


# ---------------------------------------------------------------------------
# Tamper Detector Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class ITamperDetector(Protocol):
    """Interface for multi-method content tamper detection."""

    async def detect_tampering(
        self,
        content_id: str,
        content_bytes: bytes,
        original_hash: str | None,
        expected_watermark_payload: str | None,
        expected_metadata: dict[str, Any] | None,
    ) -> Any:
        """Run full tamper detection suite on content.

        Args:
            content_id: Identifier for the content being analyzed.
            content_bytes: Raw bytes to analyze.
            original_hash: Known-good SHA-256 for comparison.
            expected_watermark_payload: Expected watermark payload.
            expected_metadata: Expected metadata fields.

        Returns:
            TamperReport with overall verdict and per-method indicators.
        """
        ...


# ---------------------------------------------------------------------------
# Metadata Embedder Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IMetadataEmbedder(Protocol):
    """Interface for embedding provenance metadata into content files."""

    async def embed_xmp(
        self,
        content_bytes: bytes,
        provenance: Any,
    ) -> Any:
        """Embed provenance metadata as XMP fields in an image.

        Args:
            content_bytes: Raw image bytes.
            provenance: ProvenanceMetadata to embed.

        Returns:
            EmbedResult with status and metadata hash.
        """
        ...

    async def extract_metadata(
        self,
        content_bytes: bytes,
        content_id: str,
    ) -> Any:
        """Extract provenance metadata from content.

        Args:
            content_bytes: Raw content bytes.
            content_id: Expected content identifier.

        Returns:
            ExtractResult with extracted metadata.
        """
        ...


# ---------------------------------------------------------------------------
# Chain of Custody Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IChainOfCustody(Protocol):
    """Interface for content ownership and transfer tracking."""

    async def create_custody(
        self,
        asset_id: str,
        owner_id: str,
        purpose: str,
        authorized_by: str,
        metadata: dict[str, Any] | None,
    ) -> Any:
        """Establish initial custody of an asset.

        Args:
            asset_id: The asset to place under custody management.
            owner_id: The initial owner.
            purpose: Business purpose.
            authorized_by: Who authorized this.
            metadata: Additional context.

        Returns:
            CustodyRecord (root event).
        """
        ...

    async def transfer_custody(
        self,
        asset_id: str,
        new_owner_id: str,
        purpose: str,
        authorized_by: str,
        metadata: dict[str, Any] | None,
    ) -> Any:
        """Transfer custody of an asset to a new owner.

        Args:
            asset_id: The asset being transferred.
            new_owner_id: The new owner.
            purpose: Business reason for transfer.
            authorized_by: Who authorized the transfer.
            metadata: Additional context.

        Returns:
            CustodyRecord (transfer event).
        """
        ...

    async def validate_chain(self, asset_id: str) -> Any:
        """Validate the full custody chain for an asset.

        Args:
            asset_id: The asset to validate.

        Returns:
            CustodyChain with is_valid and has_gaps flags.
        """
        ...

    async def generate_attestation(
        self,
        asset_id: str,
        attesting_owner_id: str,
        validity_hours: int,
    ) -> Any:
        """Generate a signed custody attestation.

        Args:
            asset_id: The asset to attest.
            attesting_owner_id: The owner generating the attestation.
            validity_hours: Attestation validity window.

        Returns:
            CustodyAttestation with HMAC signature.
        """
        ...


# ---------------------------------------------------------------------------
# Retention Manager Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IRetentionManager(Protocol):
    """Interface for record retention policy management."""

    async def register_record(
        self,
        asset_id: str,
        asset_type: str,
        tenant_id: str,
        policy_id: str,
        acquired_at: datetime | None,
    ) -> Any:
        """Register a data record under a retention policy.

        Args:
            asset_id: The record to track.
            asset_type: Category label.
            tenant_id: Owning tenant.
            policy_id: Retention policy to apply.
            acquired_at: When the data was created.

        Returns:
            RetentionRecord.
        """
        ...

    async def place_legal_hold(
        self,
        asset_id: str,
        reason: str,
        authorized_by: str,
    ) -> Any:
        """Place a legal hold preventing expiry-based purging.

        Args:
            asset_id: The asset to hold.
            reason: Legal reason for the hold.
            authorized_by: Who authorized this.

        Returns:
            Updated RetentionRecord.
        """
        ...

    async def detect_expiring_records(
        self,
        tenant_id: str,
        warning_days: int,
    ) -> list[Any]:
        """Detect records that are expiring soon or already expired.

        Args:
            tenant_id: The tenant to check.
            warning_days: Days before expiry to warn.

        Returns:
            List of ExpiryNotification objects.
        """
        ...


# ---------------------------------------------------------------------------
# Lineage Resolver Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class ILineageResolver(Protocol):
    """Interface for training data lineage graph traversal."""

    async def record_contribution(
        self,
        parent_node_id: str,
        child_node_id: str,
        relationship: Any,
        tenant_id: str,
        contribution_fraction: float,
        metadata: dict[str, Any] | None,
    ) -> Any:
        """Record a lineage edge between two nodes.

        Args:
            parent_node_id: Upstream/source node.
            child_node_id: Downstream/derived node.
            relationship: Relationship type enum value.
            tenant_id: Owning tenant.
            contribution_fraction: Fraction of child from this parent.
            metadata: Edge metadata.

        Returns:
            LineageEdge record.
        """
        ...

    async def get_upstream_graph(
        self,
        node_id: str,
        tenant_id: str,
        max_depth: int | None,
    ) -> Any:
        """Traverse the lineage graph upstream from a node.

        Args:
            node_id: Starting node.
            tenant_id: Owning tenant.
            max_depth: Maximum traversal depth.

        Returns:
            LineageGraphResult with all ancestor nodes and edges.
        """
        ...

    async def analyze_impact(
        self,
        source_node_id: str,
        tenant_id: str,
    ) -> Any:
        """Analyze downstream impact of a source node change.

        Args:
            source_node_id: The node that may change.
            tenant_id: Owning tenant.

        Returns:
            ImpactAnalysis with affected node counts.
        """
        ...


# ---------------------------------------------------------------------------
# License Checker Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class ILicenseChecker(Protocol):
    """Interface for license compliance analysis."""

    async def detect_license(
        self,
        content_id: str,
        license_identifier: str,
        copyright_holders: list[str] | None,
    ) -> Any:
        """Look up a license profile by SPDX identifier.

        Args:
            content_id: The content being analyzed.
            license_identifier: SPDX license identifier.
            copyright_holders: Known copyright holders.

        Returns:
            LicenseProfile or None if unrecognized.
        """
        ...

    async def check_compatibility(
        self,
        license_a: str,
        license_b: str,
        use_case: Any,
    ) -> Any:
        """Check compatibility between two licenses for a use case.

        Args:
            license_a: First SPDX identifier.
            license_b: Second SPDX identifier.
            use_case: Intended use case enum value.

        Returns:
            CompatibilityResult with verdict and restrictions.
        """
        ...

    async def detect_violations(
        self,
        content_licenses: list[dict[str, Any]],
        use_case: Any,
    ) -> list[dict[str, Any]]:
        """Detect license violations across a collection of content.

        Args:
            content_licenses: List of dicts with content_id and license keys.
            use_case: Intended use case.

        Returns:
            List of violation dicts.
        """
        ...


# ---------------------------------------------------------------------------
# Audit Reporter Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IProvenanceAuditReporter(Protocol):
    """Interface for court-admissible audit trail generation."""

    async def compile_audit_trail(
        self,
        tenant_id: str,
        scope: Any,
        provenance_records: list[dict[str, Any]] | None,
        lineage_records: list[dict[str, Any]] | None,
        license_records: list[dict[str, Any]] | None,
        custody_records: list[dict[str, Any]] | None,
        filter_content_ids: list[str] | None,
    ) -> list[Any]:
        """Compile all available evidence into typed AuditRecord objects.

        Args:
            tenant_id: The owning tenant.
            scope: Which evidence categories to include.
            provenance_records: C2PA provenance data dicts.
            lineage_records: Lineage edge dicts.
            license_records: License compliance check dicts.
            custody_records: Chain of custody event dicts.
            filter_content_ids: Optional content ID filter.

        Returns:
            List of AuditRecord objects.
        """
        ...

    async def package_evidence(
        self,
        tenant_id: str,
        scope: Any,
        audit_records: list[Any],
    ) -> Any:
        """Assemble a ZIP evidence package from audit records.

        Args:
            tenant_id: The owning tenant.
            scope: Evidence scope.
            audit_records: Records to package.

        Returns:
            EvidencePackage with ZIP bytes and integrity manifest.
        """
        ...

    async def generate_expert_witness_report(
        self,
        tenant_id: str,
        scope: Any,
        audit_records: list[Any],
        expert_name: str,
        case_reference: str,
        jurisdiction: str,
    ) -> Any:
        """Generate a structured expert witness report.

        Args:
            tenant_id: The owning tenant.
            scope: Evidence scope.
            audit_records: Evidence records to analyze.
            expert_name: Expert witness name.
            case_reference: Court case reference.
            jurisdiction: Legal jurisdiction.

        Returns:
            ExpertWitnessReport with signed attestation.
        """
        ...


# ---------------------------------------------------------------------------
# GAP-274: Content Credentials Verification UI Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IContentVerificationService(Protocol):
    """Interface for computing content credentials verification results."""

    async def verify(
        self,
        content_id: str,
        tenant_id: uuid.UUID,
        content_bytes: bytes | None,
    ) -> ContentVerificationResult:
        """Compute the verification result and legal defensibility score.

        Args:
            content_id: Stable content identifier to verify.
            tenant_id: Owning tenant UUID.
            content_bytes: Optional raw bytes for watermark detection.

        Returns:
            ContentVerificationResult with legal_defensibility_score.
        """
        ...


# ---------------------------------------------------------------------------
# GAP-276: Video/Audio Watermark Interfaces
# ---------------------------------------------------------------------------


@runtime_checkable
class IAudioWatermarkAdapter(Protocol):
    """Interface for embedding and detecting watermarks in audio content."""

    async def embed(
        self,
        audio_bytes: bytes,
        payload: str,
        strength: float,
    ) -> bytes:
        """Embed an inaudible watermark into audio content.

        Args:
            audio_bytes: Raw PCM/WAV/MP3 bytes.
            payload: Payload to embed.
            strength: Embedding strength (0.0–1.0).

        Returns:
            Watermarked audio bytes.
        """
        ...

    async def detect(
        self,
        audio_bytes: bytes,
    ) -> tuple[bool, str | None]:
        """Detect an inaudible watermark in audio content.

        Args:
            audio_bytes: Audio bytes to analyse.

        Returns:
            Tuple of (watermark_found, extracted_payload_or_none).
        """
        ...


@runtime_checkable
class IVideoWatermarkAdapter(Protocol):
    """Interface for embedding and detecting watermarks in video content."""

    async def embed(
        self,
        video_bytes: bytes,
        payload: str,
        strength: float,
    ) -> bytes:
        """Embed an invisible watermark into video content.

        Args:
            video_bytes: Raw video bytes (MP4/MOV/AVI).
            payload: Payload to embed in video frames.
            strength: Embedding strength (0.0–1.0).

        Returns:
            Watermarked video bytes.
        """
        ...

    async def detect(
        self,
        video_bytes: bytes,
    ) -> tuple[bool, str | None]:
        """Detect an invisible watermark in video content.

        Args:
            video_bytes: Video bytes to analyse.

        Returns:
            Tuple of (watermark_found, extracted_payload_or_none).
        """
        ...


# ---------------------------------------------------------------------------
# GAP-278: Copyright Claim Database Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class ICopyrightClaimRepository(Protocol):
    """Repository interface for copyright claim records."""

    async def create(
        self,
        claim_reference: str,
        claimant_name: str,
        defendant_name: str | None,
        content_description: str,
        content_identifiers: list[str],
        status: CopyrightClaimStatus,
        jurisdiction: str,
        filed_at: datetime | None,
        source_url: str | None,
        tags: list[str],
    ) -> CopyrightClaim:
        """Record a new copyright claim.

        Args:
            claim_reference: External case number or claim ID.
            claimant_name: Copyright holder or plaintiff.
            defendant_name: Defendant company/model name.
            content_description: Description of claimed content.
            content_identifiers: Hashes, URLs, or dataset names.
            status: Initial claim status.
            jurisdiction: Legal jurisdiction.
            filed_at: Filing date.
            source_url: Public court filing URL.
            tags: Classification tags.

        Returns:
            The created CopyrightClaim record.
        """
        ...

    async def search(
        self,
        content_identifiers: list[str],
        tags: list[str] | None,
        status: CopyrightClaimStatus | None,
    ) -> list[CopyrightClaim]:
        """Search copyright claims by content identifier cross-reference.

        Args:
            content_identifiers: Hashes or dataset names to cross-reference.
            tags: Optional tag filter (e.g., ["generative_ai"]).
            status: Optional status filter.

        Returns:
            List of matching CopyrightClaim records.
        """
        ...

    async def list_claims(
        self,
        page: int,
        page_size: int,
        status: CopyrightClaimStatus | None,
    ) -> list[CopyrightClaim]:
        """List all copyright claims with pagination.

        Args:
            page: Page number (1-indexed).
            page_size: Records per page.
            status: Optional status filter.

        Returns:
            List of CopyrightClaim records.
        """
        ...


# ---------------------------------------------------------------------------
# GAP-279: Blockchain Anchor Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IBlockchainAnchorAdapter(Protocol):
    """Interface for anchoring content hashes to blockchain/IPFS."""

    async def anchor(
        self,
        content_hash: str,
        network: BlockchainNetwork,
        metadata: dict[str, Any],
    ) -> tuple[str | None, str | None, int | None]:
        """Anchor a content hash to the specified network.

        Args:
            content_hash: SHA-256 of content to anchor.
            network: Target blockchain network or IPFS.
            metadata: Additional metadata to include in the anchor payload.

        Returns:
            Tuple of (transaction_hash_or_none, ipfs_cid_or_none, block_height_or_none).
        """
        ...

    async def check_confirmation(
        self,
        transaction_hash: str,
        network: BlockchainNetwork,
    ) -> int:
        """Check the number of block confirmations for a transaction.

        Args:
            transaction_hash: On-chain transaction hash.
            network: Blockchain network.

        Returns:
            Number of block confirmations.
        """
        ...


@runtime_checkable
class IBlockchainAnchorRepository(Protocol):
    """Repository interface for BlockchainAnchor records."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        provenance_record_id: uuid.UUID,
        content_hash: str,
        network: BlockchainNetwork,
    ) -> BlockchainAnchor:
        """Create a pending blockchain anchor record.

        Args:
            tenant_id: Owning tenant UUID.
            provenance_record_id: The provenance record being anchored.
            content_hash: SHA-256 of content.
            network: Target network.

        Returns:
            The created BlockchainAnchor record with pending status.
        """
        ...

    async def update_anchor(
        self,
        anchor_id: uuid.UUID,
        transaction_hash: str | None,
        ipfs_cid: str | None,
        block_height: int | None,
        anchor_status: str,
    ) -> BlockchainAnchor:
        """Update an anchor record with on-chain confirmation details.

        Args:
            anchor_id: Anchor record UUID.
            transaction_hash: On-chain transaction hash.
            ipfs_cid: IPFS CID if applicable.
            block_height: Block height at confirmation.
            anchor_status: New status (confirmed | failed).

        Returns:
            Updated BlockchainAnchor record.
        """
        ...

    async def get_by_provenance_record(
        self,
        provenance_record_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> BlockchainAnchor | None:
        """Retrieve anchor for a provenance record.

        Args:
            provenance_record_id: The provenance record UUID.
            tenant_id: Owning tenant UUID.

        Returns:
            BlockchainAnchor or None.
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
    "IProvenanceTracker",
    "ITamperDetector",
    "IMetadataEmbedder",
    "IChainOfCustody",
    "IRetentionManager",
    "ILineageResolver",
    "ILicenseChecker",
    "IProvenanceAuditReporter",
    "IContentVerificationService",
    "IAudioWatermarkAdapter",
    "IVideoWatermarkAdapter",
    "ICopyrightClaimRepository",
    "IBlockchainAnchorAdapter",
    "IBlockchainAnchorRepository",
]
