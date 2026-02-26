"""Unit tests for aumos-content-provenance service layer.

Tests use mock implementations of all Protocol interfaces — no database
or external service connections required.
"""

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from aumos_content_provenance.core.models import (
    AuditExportStatus,
    LicenseRisk,
    LineageEntry,
    LineageNodeType,
    ProvenanceRecord,
    ProvenanceStatus,
    Watermark,
    WatermarkMethod,
)
from aumos_content_provenance.core.services import (
    AuditExportService,
    C2PAService,
    LicenseComplianceService,
    LineageService,
    WatermarkService,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tenant_id() -> uuid.UUID:
    """Fixed tenant UUID for test isolation."""
    return uuid.UUID("11111111-1111-1111-1111-111111111111")


@pytest.fixture
def sample_content() -> bytes:
    """Sample content bytes for signing and watermarking tests."""
    return b"Sample AI-generated content for provenance testing."


@pytest.fixture
def sample_content_hash(sample_content: bytes) -> str:
    """SHA-256 hash of sample content."""
    return hashlib.sha256(sample_content).hexdigest()


def _make_provenance_record(
    tenant_id: uuid.UUID,
    content_id: str = "test-content-001",
    status: ProvenanceStatus = ProvenanceStatus.SIGNED,
) -> ProvenanceRecord:
    """Build a ProvenanceRecord for test assertions."""
    now = datetime.now(UTC)
    return ProvenanceRecord(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        content_id=content_id,
        content_type="text/plain",
        content_hash=hashlib.sha256(b"test").hexdigest(),
        c2pa_manifest={"schema": "c2pa_manifest_v2", "content_hash": {"value": hashlib.sha256(b"test").hexdigest()}},
        manifest_uri=f"urn:aumos:manifest:{content_id}:abc123",
        status=status,
        signer_id="aumos-default-signer",
        signed_at=now,
        verified_at=None,
        metadata={},
        created_at=now,
    )


def _make_watermark(tenant_id: uuid.UUID, content_id: str = "test-content-001") -> Watermark:
    """Build a Watermark record for test assertions."""
    now = datetime.now(UTC)
    payload = f"{tenant_id}:{content_id}"
    return Watermark(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        content_id=content_id,
        method=WatermarkMethod.DWT_DCT,
        payload=payload,
        payload_hash=hashlib.sha256(payload.encode()).hexdigest(),
        strength=0.3,
        detected=None,
        detected_at=None,
        created_at=now,
    )


def _make_lineage_entry(
    tenant_id: uuid.UUID,
    parent_id: str = "dataset-001",
    child_id: str = "model-001",
) -> LineageEntry:
    """Build a LineageEntry for test assertions."""
    return LineageEntry(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        parent_node_id=parent_id,
        parent_node_type=LineageNodeType.TRAINING_DATASET,
        child_node_id=child_id,
        child_node_type=LineageNodeType.MODEL,
        relationship="trained_on",
        metadata={"version": "1.0"},
        created_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# C2PAService tests
# ---------------------------------------------------------------------------


class TestC2PAService:
    """Tests for C2PAService sign and verify operations."""

    @pytest.fixture
    def mock_c2pa_client(self) -> MagicMock:
        """Mock IC2PAClient that returns a valid stub manifest."""
        client = MagicMock()
        client.sign_content = AsyncMock(
            return_value={
                "schema": "c2pa_manifest_v2",
                "stub_mode": True,
                "manifest_id": str(uuid.uuid4()),
                "content_hash": {"alg": "sha256", "value": hashlib.sha256(b"test").hexdigest()},
            }
        )
        client.verify_manifest = AsyncMock(return_value=(True, "Verified successfully"))
        return client

    @pytest.fixture
    def mock_provenance_repo(self, tenant_id: uuid.UUID) -> MagicMock:
        """Mock IProvenanceRepository."""
        repo = MagicMock()
        repo.create = AsyncMock(side_effect=lambda **kwargs: _make_provenance_record(tenant_id))
        repo.get_by_id = AsyncMock(return_value=None)
        repo.update_status = AsyncMock(
            side_effect=lambda **kwargs: _make_provenance_record(
                tenant_id, status=kwargs.get("status", ProvenanceStatus.SIGNED)
            )
        )
        repo.list_by_tenant = AsyncMock(return_value=[])
        return repo

    @pytest.fixture
    def service(self, mock_c2pa_client: MagicMock, mock_provenance_repo: MagicMock) -> C2PAService:
        """C2PAService with mock adapters."""
        return C2PAService(
            c2pa_client=mock_c2pa_client,
            provenance_repository=mock_provenance_repo,
            event_publisher=None,
        )

    @pytest.mark.asyncio
    async def test_sign_content_creates_record(
        self,
        service: C2PAService,
        tenant_id: uuid.UUID,
        sample_content: bytes,
        mock_provenance_repo: MagicMock,
    ) -> None:
        """sign_content should call create on the repository."""
        result = await service.sign_content(
            tenant_id=tenant_id,
            content_bytes=sample_content,
            content_id="test-content-001",
            content_type="text/plain",
            assertions=[],
            signer_id="test-signer",
        )

        assert result.record is not None
        mock_provenance_repo.create.assert_called_once()
        call_kwargs = mock_provenance_repo.create.call_args.kwargs
        assert call_kwargs["tenant_id"] == tenant_id
        assert call_kwargs["content_id"] == "test-content-001"
        assert call_kwargs["status"] == ProvenanceStatus.SIGNED

    @pytest.mark.asyncio
    async def test_sign_content_computes_hash(
        self,
        service: C2PAService,
        tenant_id: uuid.UUID,
        sample_content: bytes,
        sample_content_hash: str,
        mock_provenance_repo: MagicMock,
    ) -> None:
        """sign_content should pass the SHA-256 hash to the repository."""
        await service.sign_content(
            tenant_id=tenant_id,
            content_bytes=sample_content,
            content_id="test-content-001",
            content_type="text/plain",
            assertions=[],
            signer_id="test-signer",
        )

        call_kwargs = mock_provenance_repo.create.call_args.kwargs
        assert call_kwargs["content_hash"] == sample_content_hash

    @pytest.mark.asyncio
    async def test_sign_empty_content_raises(
        self,
        service: C2PAService,
        tenant_id: uuid.UUID,
    ) -> None:
        """sign_content should raise ValidationError for empty content."""
        from aumos_common.errors import ValidationError

        with pytest.raises(ValidationError, match="content_bytes cannot be empty"):
            await service.sign_content(
                tenant_id=tenant_id,
                content_bytes=b"",
                content_id="test-content-001",
                content_type="text/plain",
                assertions=[],
                signer_id="test-signer",
            )

    @pytest.mark.asyncio
    async def test_sign_blank_content_id_raises(
        self,
        service: C2PAService,
        tenant_id: uuid.UUID,
    ) -> None:
        """sign_content should raise ValidationError for blank content_id."""
        from aumos_common.errors import ValidationError

        with pytest.raises(ValidationError, match="content_id cannot be blank"):
            await service.sign_content(
                tenant_id=tenant_id,
                content_bytes=b"some content",
                content_id="   ",
                content_type="text/plain",
                assertions=[],
                signer_id="test-signer",
            )

    @pytest.mark.asyncio
    async def test_verify_not_found_raises(
        self,
        service: C2PAService,
        tenant_id: uuid.UUID,
        mock_provenance_repo: MagicMock,
    ) -> None:
        """verify_provenance should raise NotFoundError when record not found."""
        from aumos_common.errors import NotFoundError

        mock_provenance_repo.get_by_id = AsyncMock(return_value=None)
        record_id = uuid.uuid4()

        with pytest.raises(NotFoundError):
            await service.verify_provenance(
                tenant_id=tenant_id,
                record_id=record_id,
                content_bytes=b"some content",
            )

    @pytest.mark.asyncio
    async def test_verify_hash_mismatch_returns_invalid(
        self,
        service: C2PAService,
        tenant_id: uuid.UUID,
        mock_provenance_repo: MagicMock,
    ) -> None:
        """verify_provenance should return INVALID when content hash does not match."""
        stored_record = _make_provenance_record(tenant_id)
        # stored_record.content_hash is SHA-256 of b"test", but we pass different content
        mock_provenance_repo.get_by_id = AsyncMock(return_value=stored_record)

        result = await service.verify_provenance(
            tenant_id=tenant_id,
            record_id=stored_record.id,
            content_bytes=b"different content",
        )

        assert result.is_valid is False
        assert result.status == ProvenanceStatus.INVALID
        assert "hash mismatch" in result.reason.lower()


# ---------------------------------------------------------------------------
# WatermarkService tests
# ---------------------------------------------------------------------------


class TestWatermarkService:
    """Tests for WatermarkService embed and detect operations."""

    @pytest.fixture
    def mock_watermark_engine(self) -> MagicMock:
        """Mock IWatermarkEngine."""
        engine = MagicMock()
        engine.embed = AsyncMock(return_value=b"watermarked-content-bytes")
        engine.detect = AsyncMock(return_value=(True, "tenant-id:content-001"))
        return engine

    @pytest.fixture
    def mock_watermark_repo(self, tenant_id: uuid.UUID) -> MagicMock:
        """Mock IWatermarkRepository."""
        repo = MagicMock()
        repo.create = AsyncMock(side_effect=lambda **kwargs: _make_watermark(tenant_id))
        return repo

    @pytest.fixture
    def service(
        self, mock_watermark_engine: MagicMock, mock_watermark_repo: MagicMock
    ) -> WatermarkService:
        """WatermarkService with mock adapters."""
        return WatermarkService(
            watermark_engine=mock_watermark_engine,
            watermark_repository=mock_watermark_repo,
        )

    @pytest.mark.asyncio
    async def test_embed_returns_watermarked_bytes(
        self,
        service: WatermarkService,
        tenant_id: uuid.UUID,
    ) -> None:
        """embed_watermark should return the engine's output bytes."""
        result = await service.embed_watermark(
            tenant_id=tenant_id,
            content_id="content-001",
            content_bytes=b"original content",
        )

        assert result.watermarked_bytes == b"watermarked-content-bytes"
        assert result.watermark is not None

    @pytest.mark.asyncio
    async def test_embed_uses_default_payload(
        self,
        service: WatermarkService,
        tenant_id: uuid.UUID,
        mock_watermark_engine: MagicMock,
    ) -> None:
        """embed_watermark should default payload to tenant_id:content_id."""
        await service.embed_watermark(
            tenant_id=tenant_id,
            content_id="content-001",
            content_bytes=b"original content",
        )

        call_kwargs = mock_watermark_engine.embed.call_args.kwargs
        assert call_kwargs["payload"] == f"{tenant_id}:content-001"

    @pytest.mark.asyncio
    async def test_embed_empty_content_raises(
        self,
        service: WatermarkService,
        tenant_id: uuid.UUID,
    ) -> None:
        """embed_watermark should raise ValidationError for empty content."""
        from aumos_common.errors import ValidationError

        with pytest.raises(ValidationError, match="content_bytes cannot be empty"):
            await service.embed_watermark(
                tenant_id=tenant_id,
                content_id="content-001",
                content_bytes=b"",
            )

    @pytest.mark.asyncio
    async def test_detect_returns_payload(
        self,
        service: WatermarkService,
        tenant_id: uuid.UUID,
    ) -> None:
        """detect_watermark should return detected payload and parsed content_id."""
        result = await service.detect_watermark(
            tenant_id=tenant_id,
            content_bytes=b"watermarked content",
        )

        assert result.detected is True
        assert result.payload == "tenant-id:content-001"
        assert result.content_id == "content-001"


# ---------------------------------------------------------------------------
# LineageService tests
# ---------------------------------------------------------------------------


class TestLineageService:
    """Tests for LineageService lineage graph operations."""

    @pytest.fixture
    def mock_lineage_repo(self, tenant_id: uuid.UUID) -> MagicMock:
        """Mock ILineageRepository."""
        repo = MagicMock()
        repo.create = AsyncMock(
            side_effect=lambda **kwargs: _make_lineage_entry(
                tenant_id,
                parent_id=kwargs["parent_node_id"],
                child_id=kwargs["child_node_id"],
            )
        )
        repo.get_ancestors = AsyncMock(
            return_value=[_make_lineage_entry(tenant_id)]
        )
        return repo

    @pytest.fixture
    def service(self, mock_lineage_repo: MagicMock) -> LineageService:
        """LineageService with mock repository."""
        return LineageService(lineage_repository=mock_lineage_repo, max_depth=10)

    @pytest.mark.asyncio
    async def test_record_valid_relationship(
        self,
        service: LineageService,
        tenant_id: uuid.UUID,
        mock_lineage_repo: MagicMock,
    ) -> None:
        """record_lineage should create an entry for valid relationships."""
        entry = await service.record_lineage(
            tenant_id=tenant_id,
            parent_node_id="dataset-001",
            parent_node_type=LineageNodeType.TRAINING_DATASET,
            child_node_id="model-001",
            child_node_type=LineageNodeType.MODEL,
            relationship="trained_on",
        )

        assert entry.parent_node_id == "dataset-001"
        assert entry.child_node_id == "model-001"
        mock_lineage_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_record_invalid_relationship_raises(
        self,
        service: LineageService,
        tenant_id: uuid.UUID,
    ) -> None:
        """record_lineage should raise ValidationError for unknown relationships."""
        from aumos_common.errors import ValidationError

        with pytest.raises(ValidationError, match="Invalid relationship"):
            await service.record_lineage(
                tenant_id=tenant_id,
                parent_node_id="dataset-001",
                parent_node_type=LineageNodeType.TRAINING_DATASET,
                child_node_id="model-001",
                child_node_type=LineageNodeType.MODEL,
                relationship="invented_by",  # Not a valid relationship
            )

    @pytest.mark.asyncio
    async def test_get_lineage_returns_graph(
        self,
        service: LineageService,
        tenant_id: uuid.UUID,
        mock_lineage_repo: MagicMock,
    ) -> None:
        """get_lineage should return a LineageGraph with entries."""
        graph = await service.get_lineage(tenant_id=tenant_id, content_id="model-001")

        assert graph.content_id == "model-001"
        assert len(graph.entries) == 1
        assert graph.depth == 1
        mock_lineage_repo.get_ancestors.assert_called_once_with(
            node_id="model-001",
            tenant_id=tenant_id,
            max_depth=10,
        )


# ---------------------------------------------------------------------------
# LicenseComplianceService tests
# ---------------------------------------------------------------------------


class TestLicenseComplianceService:
    """Tests for LicenseComplianceService risk assessment."""

    @pytest.fixture
    def mock_license_repo(self, tenant_id: uuid.UUID) -> MagicMock:
        """Mock ILicenseRepository."""
        from aumos_content_provenance.core.models import LicenseCheck

        now = datetime.now(UTC)

        def _make_check(**kwargs: Any) -> LicenseCheck:
            return LicenseCheck(
                id=uuid.uuid4(),
                tenant_id=kwargs["tenant_id"],
                content_id=kwargs["content_id"],
                content_url=kwargs.get("content_url"),
                detected_license=kwargs["detected_license"],
                license_risk=kwargs["license_risk"],
                risk_score=kwargs["risk_score"],
                copyright_holders=kwargs.get("copyright_holders", []),
                flags=kwargs.get("flags", []),
                recommendation=kwargs["recommendation"],
                checked_at=now,
                created_at=now,
            )

        repo = MagicMock()
        repo.create = AsyncMock(side_effect=_make_check)
        repo.list_by_tenant = AsyncMock(return_value=[])
        repo.get_high_risk_summary = AsyncMock(return_value={"by_risk_level": {}, "total": 0, "high_risk_count": 0})
        return repo

    @pytest.fixture
    def service(self, mock_license_repo: MagicMock) -> LicenseComplianceService:
        """LicenseComplianceService with mock repository."""
        return LicenseComplianceService(license_repository=mock_license_repo)

    @pytest.mark.asyncio
    async def test_mit_license_is_low_risk(
        self,
        service: LicenseComplianceService,
        tenant_id: uuid.UUID,
    ) -> None:
        """MIT license should be assessed as LOW risk."""
        check = await service.check_license(
            tenant_id=tenant_id,
            content_id="dataset-mit",
            detected_license="MIT",
        )

        assert check.license_risk == LicenseRisk.LOW
        assert check.risk_score == 0.1

    @pytest.mark.asyncio
    async def test_unknown_license_is_critical(
        self,
        service: LicenseComplianceService,
        tenant_id: uuid.UUID,
    ) -> None:
        """Unknown license should be assessed as CRITICAL risk."""
        check = await service.check_license(
            tenant_id=tenant_id,
            content_id="dataset-unknown",
            detected_license="UNKNOWN",
        )

        assert check.license_risk == LicenseRisk.CRITICAL
        assert "no_license_detected" in check.flags
        assert "STOP USE IMMEDIATELY" in check.recommendation

    @pytest.mark.asyncio
    async def test_cc_by_nc_is_high_risk(
        self,
        service: LicenseComplianceService,
        tenant_id: uuid.UUID,
    ) -> None:
        """CC-BY-NC-4.0 should be HIGH risk with no_commercial_use flag."""
        check = await service.check_license(
            tenant_id=tenant_id,
            content_id="dataset-nc",
            detected_license="CC-BY-NC-4.0",
        )

        assert check.license_risk == LicenseRisk.HIGH
        assert "no_commercial_use" in check.flags

    @pytest.mark.asyncio
    async def test_gpl_is_medium_risk(
        self,
        service: LicenseComplianceService,
        tenant_id: uuid.UUID,
    ) -> None:
        """GPL-3.0 should be MEDIUM risk with copyleft flags."""
        check = await service.check_license(
            tenant_id=tenant_id,
            content_id="dataset-gpl",
            detected_license="GPL-3.0",
        )

        assert check.license_risk == LicenseRisk.MEDIUM
        assert "strong_copyleft_viral" in check.flags

    @pytest.mark.asyncio
    async def test_empty_license_treated_as_unknown(
        self,
        service: LicenseComplianceService,
        tenant_id: uuid.UUID,
    ) -> None:
        """Empty license string should default to UNKNOWN (CRITICAL risk)."""
        check = await service.check_license(
            tenant_id=tenant_id,
            content_id="dataset-empty",
            detected_license="",
        )

        assert check.license_risk == LicenseRisk.CRITICAL


# ---------------------------------------------------------------------------
# AuditExportService tests
# ---------------------------------------------------------------------------


class TestAuditExportService:
    """Tests for AuditExportService audit trail generation."""

    @pytest.fixture
    def mock_audit_repo(self, tenant_id: uuid.UUID) -> MagicMock:
        """Mock IAuditExportRepository."""
        from aumos_content_provenance.core.models import AuditExport

        now = datetime.now(UTC)

        def _make_export(**kwargs: Any) -> AuditExport:
            return AuditExport(
                id=uuid.uuid4(),
                tenant_id=kwargs.get("tenant_id", tenant_id),
                export_type=kwargs.get("export_type", "full"),
                status=kwargs.get("status", AuditExportStatus.PENDING),
                filter_params=kwargs.get("filter_params", {}),
                record_count=kwargs.get("record_count", 0),
                export_url=kwargs.get("export_url"),
                export_hash=kwargs.get("export_hash"),
                signed_by=None,
                generated_at=kwargs.get("generated_at"),
                expires_at=None,
                created_at=now,
                error_message=kwargs.get("error_message"),
            )

        repo = MagicMock()
        repo.create = AsyncMock(side_effect=_make_export)
        repo.update_status = AsyncMock(side_effect=_make_export)
        return repo

    @pytest.fixture
    def service(
        self,
        mock_audit_repo: MagicMock,
        tenant_id: uuid.UUID,
    ) -> AuditExportService:
        """AuditExportService with mock repositories."""
        mock_prov_repo = MagicMock()
        mock_prov_repo.list_by_tenant = AsyncMock(return_value=[])
        mock_lineage_repo = MagicMock()
        mock_lineage_repo.list_by_tenant = AsyncMock(return_value=[])
        mock_license_repo = MagicMock()
        mock_license_repo.list_by_tenant = AsyncMock(return_value=[])
        mock_license_repo.get_high_risk_summary = AsyncMock(return_value={})

        return AuditExportService(
            audit_repository=mock_audit_repo,
            provenance_repository=mock_prov_repo,
            lineage_repository=mock_lineage_repo,
            license_repository=mock_license_repo,
            export_bucket="test-bucket",
        )

    @pytest.mark.asyncio
    async def test_export_invalid_type_raises(
        self,
        service: AuditExportService,
        tenant_id: uuid.UUID,
    ) -> None:
        """export_audit_trail should raise ValidationError for invalid export_type."""
        from aumos_common.errors import ValidationError

        with pytest.raises(ValidationError, match="export_type must be one of"):
            await service.export_audit_trail(
                tenant_id=tenant_id,
                export_type="invalid_type",
            )

    @pytest.mark.asyncio
    async def test_export_creates_job_and_completes(
        self,
        service: AuditExportService,
        tenant_id: uuid.UUID,
        mock_audit_repo: MagicMock,
    ) -> None:
        """export_audit_trail should create an export job and update to COMPLETE."""
        result = await service.export_audit_trail(
            tenant_id=tenant_id,
            export_type="provenance",
        )

        assert result is not None
        # Should have called create once (initial job) and update_status twice
        # (once for GENERATING, once for COMPLETE)
        assert mock_audit_repo.create.call_count == 1
        assert mock_audit_repo.update_status.call_count >= 2

    @pytest.mark.asyncio
    async def test_valid_export_types(
        self,
        service: AuditExportService,
        tenant_id: uuid.UUID,
    ) -> None:
        """export_audit_trail should accept all valid export types."""
        for export_type in ("provenance", "lineage", "license", "full"):
            result = await service.export_audit_trail(
                tenant_id=tenant_id,
                export_type=export_type,
            )
            assert result is not None
