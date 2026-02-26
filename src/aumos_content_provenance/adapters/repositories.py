"""SQLAlchemy repository implementations for aumos-content-provenance.

All repositories implement their respective Protocol interfaces from core/interfaces.py.
Table prefix: cpv_

Tables:
- cpv_provenance_records
- cpv_watermarks
- cpv_lineage_entries
- cpv_license_checks
- cpv_audit_exports
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger

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
# ProvenanceRepository
# ---------------------------------------------------------------------------


class ProvenanceRepository:
    """Repository for cpv_provenance_records table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

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
        """Insert a new provenance record."""
        import json

        record_id = uuid.uuid4()
        now = datetime.now(UTC)

        await self._session.execute(
            text("""
                INSERT INTO cpv_provenance_records
                    (id, tenant_id, content_id, content_type, content_hash,
                     c2pa_manifest, manifest_uri, status, signer_id,
                     signed_at, metadata, created_at)
                VALUES
                    (:id, :tenant_id, :content_id, :content_type, :content_hash,
                     :c2pa_manifest::jsonb, :manifest_uri, :status, :signer_id,
                     :signed_at, :metadata::jsonb, :created_at)
            """),
            {
                "id": record_id,
                "tenant_id": tenant_id,
                "content_id": content_id,
                "content_type": content_type,
                "content_hash": content_hash,
                "c2pa_manifest": json.dumps(c2pa_manifest),
                "manifest_uri": manifest_uri,
                "status": status.value,
                "signer_id": signer_id,
                "signed_at": now,
                "metadata": json.dumps(metadata),
                "created_at": now,
            },
        )
        await self._session.flush()

        return ProvenanceRecord(
            id=record_id,
            tenant_id=tenant_id,
            content_id=content_id,
            content_type=content_type,
            content_hash=content_hash,
            c2pa_manifest=c2pa_manifest,
            manifest_uri=manifest_uri,
            status=status,
            signer_id=signer_id,
            signed_at=now,
            verified_at=None,
            metadata=metadata,
            created_at=now,
        )

    async def get_by_id(
        self,
        record_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> ProvenanceRecord | None:
        """Fetch a provenance record by primary key within tenant scope."""
        result = await self._session.execute(
            text("""
                SELECT id, tenant_id, content_id, content_type, content_hash,
                       c2pa_manifest, manifest_uri, status, signer_id,
                       signed_at, verified_at, metadata, created_at
                FROM cpv_provenance_records
                WHERE id = :id AND tenant_id = :tenant_id
            """),
            {"id": record_id, "tenant_id": tenant_id},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return self._row_to_model(row)

    async def get_by_content_id(
        self,
        content_id: str,
        tenant_id: uuid.UUID,
    ) -> ProvenanceRecord | None:
        """Fetch a provenance record by content_id within tenant scope."""
        result = await self._session.execute(
            text("""
                SELECT id, tenant_id, content_id, content_type, content_hash,
                       c2pa_manifest, manifest_uri, status, signer_id,
                       signed_at, verified_at, metadata, created_at
                FROM cpv_provenance_records
                WHERE content_id = :content_id AND tenant_id = :tenant_id
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"content_id": content_id, "tenant_id": tenant_id},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return self._row_to_model(row)

    async def update_status(
        self,
        record_id: uuid.UUID,
        tenant_id: uuid.UUID,
        status: ProvenanceStatus,
    ) -> ProvenanceRecord:
        """Update the status of a provenance record."""
        now = datetime.now(UTC)
        verified_at = now if status == ProvenanceStatus.VERIFIED else None

        result = await self._session.execute(
            text("""
                UPDATE cpv_provenance_records
                SET status = :status,
                    verified_at = :verified_at
                WHERE id = :id AND tenant_id = :tenant_id
                RETURNING id, tenant_id, content_id, content_type, content_hash,
                          c2pa_manifest, manifest_uri, status, signer_id,
                          signed_at, verified_at, metadata, created_at
            """),
            {
                "status": status.value,
                "verified_at": verified_at,
                "id": record_id,
                "tenant_id": tenant_id,
            },
        )
        row = result.mappings().first()
        if row is None:
            raise NotFoundError(f"Provenance record {record_id} not found for update")
        return self._row_to_model(row)

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> list[ProvenanceRecord]:
        """List provenance records for a tenant, newest first."""
        offset = (page - 1) * page_size
        result = await self._session.execute(
            text("""
                SELECT id, tenant_id, content_id, content_type, content_hash,
                       c2pa_manifest, manifest_uri, status, signer_id,
                       signed_at, verified_at, metadata, created_at
                FROM cpv_provenance_records
                WHERE tenant_id = :tenant_id
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"tenant_id": tenant_id, "limit": page_size, "offset": offset},
        )
        return [self._row_to_model(row) for row in result.mappings()]

    @staticmethod
    def _row_to_model(row: Any) -> ProvenanceRecord:
        """Map a database row to a ProvenanceRecord domain model."""
        return ProvenanceRecord(
            id=row["id"],
            tenant_id=row["tenant_id"],
            content_id=row["content_id"],
            content_type=row["content_type"],
            content_hash=row["content_hash"],
            c2pa_manifest=row["c2pa_manifest"] if isinstance(row["c2pa_manifest"], dict) else {},
            manifest_uri=row["manifest_uri"],
            status=ProvenanceStatus(row["status"]),
            signer_id=row["signer_id"],
            signed_at=row["signed_at"],
            verified_at=row["verified_at"],
            metadata=row["metadata"] if isinstance(row["metadata"], dict) else {},
            created_at=row["created_at"],
        )


# ---------------------------------------------------------------------------
# WatermarkRepository
# ---------------------------------------------------------------------------


class WatermarkRepository:
    """Repository for cpv_watermarks table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        tenant_id: uuid.UUID,
        content_id: str,
        method: WatermarkMethod,
        payload: str,
        payload_hash: str,
        strength: float,
    ) -> Watermark:
        """Insert a new watermark record."""
        watermark_id = uuid.uuid4()
        now = datetime.now(UTC)

        await self._session.execute(
            text("""
                INSERT INTO cpv_watermarks
                    (id, tenant_id, content_id, method, payload, payload_hash,
                     strength, detected, created_at)
                VALUES
                    (:id, :tenant_id, :content_id, :method, :payload, :payload_hash,
                     :strength, NULL, :created_at)
            """),
            {
                "id": watermark_id,
                "tenant_id": tenant_id,
                "content_id": content_id,
                "method": method.value,
                "payload": payload,
                "payload_hash": payload_hash,
                "strength": strength,
                "created_at": now,
            },
        )
        await self._session.flush()

        return Watermark(
            id=watermark_id,
            tenant_id=tenant_id,
            content_id=content_id,
            method=method,
            payload=payload,
            payload_hash=payload_hash,
            strength=strength,
            detected=None,
            detected_at=None,
            created_at=now,
        )

    async def get_by_content_id(
        self,
        content_id: str,
        tenant_id: uuid.UUID,
    ) -> Watermark | None:
        """Fetch watermark metadata for a content item."""
        result = await self._session.execute(
            text("""
                SELECT id, tenant_id, content_id, method, payload, payload_hash,
                       strength, detected, detected_at, created_at
                FROM cpv_watermarks
                WHERE content_id = :content_id AND tenant_id = :tenant_id
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"content_id": content_id, "tenant_id": tenant_id},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return self._row_to_model(row)

    async def update_detection(
        self,
        watermark_id: uuid.UUID,
        tenant_id: uuid.UUID,
        detected: bool,
    ) -> Watermark:
        """Record detection result for a watermark."""
        now = datetime.now(UTC)

        result = await self._session.execute(
            text("""
                UPDATE cpv_watermarks
                SET detected = :detected, detected_at = :detected_at
                WHERE id = :id AND tenant_id = :tenant_id
                RETURNING id, tenant_id, content_id, method, payload, payload_hash,
                          strength, detected, detected_at, created_at
            """),
            {
                "detected": detected,
                "detected_at": now,
                "id": watermark_id,
                "tenant_id": tenant_id,
            },
        )
        row = result.mappings().first()
        if row is None:
            raise NotFoundError(f"Watermark {watermark_id} not found for update")
        return self._row_to_model(row)

    @staticmethod
    def _row_to_model(row: Any) -> Watermark:
        """Map a database row to a Watermark domain model."""
        return Watermark(
            id=row["id"],
            tenant_id=row["tenant_id"],
            content_id=row["content_id"],
            method=WatermarkMethod(row["method"]),
            payload=row["payload"],
            payload_hash=row["payload_hash"],
            strength=float(row["strength"]),
            detected=row["detected"],
            detected_at=row["detected_at"],
            created_at=row["created_at"],
        )


# ---------------------------------------------------------------------------
# LineageRepository
# ---------------------------------------------------------------------------


class LineageRepository:
    """Repository for cpv_lineage_entries table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

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
        """Insert a lineage edge."""
        import json

        entry_id = uuid.uuid4()
        now = datetime.now(UTC)

        await self._session.execute(
            text("""
                INSERT INTO cpv_lineage_entries
                    (id, tenant_id, parent_node_id, parent_node_type,
                     child_node_id, child_node_type, relationship, metadata, created_at)
                VALUES
                    (:id, :tenant_id, :parent_node_id, :parent_node_type,
                     :child_node_id, :child_node_type, :relationship,
                     :metadata::jsonb, :created_at)
            """),
            {
                "id": entry_id,
                "tenant_id": tenant_id,
                "parent_node_id": parent_node_id,
                "parent_node_type": parent_node_type.value,
                "child_node_id": child_node_id,
                "child_node_type": child_node_type.value,
                "relationship": relationship,
                "metadata": json.dumps(metadata),
                "created_at": now,
            },
        )
        await self._session.flush()

        return LineageEntry(
            id=entry_id,
            tenant_id=tenant_id,
            parent_node_id=parent_node_id,
            parent_node_type=parent_node_type,
            child_node_id=child_node_id,
            child_node_type=child_node_type,
            relationship=relationship,
            metadata=metadata,
            created_at=now,
        )

    async def get_ancestors(
        self,
        node_id: str,
        tenant_id: uuid.UUID,
        max_depth: int,
    ) -> list[LineageEntry]:
        """Traverse lineage graph upward via recursive CTE."""
        result = await self._session.execute(
            text("""
                WITH RECURSIVE lineage_chain AS (
                    -- Base case: direct parents of node_id
                    SELECT id, tenant_id, parent_node_id, parent_node_type,
                           child_node_id, child_node_type, relationship, metadata,
                           created_at, 1 AS depth
                    FROM cpv_lineage_entries
                    WHERE child_node_id = :node_id AND tenant_id = :tenant_id

                    UNION ALL

                    -- Recursive case: walk upward
                    SELECT e.id, e.tenant_id, e.parent_node_id, e.parent_node_type,
                           e.child_node_id, e.child_node_type, e.relationship,
                           e.metadata, e.created_at, lc.depth + 1
                    FROM cpv_lineage_entries e
                    INNER JOIN lineage_chain lc ON e.child_node_id = lc.parent_node_id
                        AND e.tenant_id = lc.tenant_id
                    WHERE lc.depth < :max_depth
                )
                SELECT DISTINCT id, tenant_id, parent_node_id, parent_node_type,
                       child_node_id, child_node_type, relationship, metadata, created_at
                FROM lineage_chain
                ORDER BY created_at ASC
            """),
            {"node_id": node_id, "tenant_id": tenant_id, "max_depth": max_depth},
        )
        return [self._row_to_model(row) for row in result.mappings()]

    async def list_by_content_id(
        self,
        content_id: str,
        tenant_id: uuid.UUID,
    ) -> list[LineageEntry]:
        """List all edges touching a content_id (as parent or child)."""
        result = await self._session.execute(
            text("""
                SELECT id, tenant_id, parent_node_id, parent_node_type,
                       child_node_id, child_node_type, relationship, metadata, created_at
                FROM cpv_lineage_entries
                WHERE tenant_id = :tenant_id
                  AND (parent_node_id = :content_id OR child_node_id = :content_id)
                ORDER BY created_at ASC
            """),
            {"tenant_id": tenant_id, "content_id": content_id},
        )
        return [self._row_to_model(row) for row in result.mappings()]

    @staticmethod
    def _row_to_model(row: Any) -> LineageEntry:
        """Map a database row to a LineageEntry domain model."""
        return LineageEntry(
            id=row["id"],
            tenant_id=row["tenant_id"],
            parent_node_id=row["parent_node_id"],
            parent_node_type=LineageNodeType(row["parent_node_type"]),
            child_node_id=row["child_node_id"],
            child_node_type=LineageNodeType(row["child_node_type"]),
            relationship=row["relationship"],
            metadata=row["metadata"] if isinstance(row["metadata"], dict) else {},
            created_at=row["created_at"],
        )


# ---------------------------------------------------------------------------
# LicenseRepository
# ---------------------------------------------------------------------------


class LicenseRepository:
    """Repository for cpv_license_checks table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

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
        """Insert a new license check record."""
        import json

        check_id = uuid.uuid4()
        now = datetime.now(UTC)

        await self._session.execute(
            text("""
                INSERT INTO cpv_license_checks
                    (id, tenant_id, content_id, content_url, detected_license,
                     license_risk, risk_score, copyright_holders, flags,
                     recommendation, checked_at, created_at)
                VALUES
                    (:id, :tenant_id, :content_id, :content_url, :detected_license,
                     :license_risk, :risk_score, :copyright_holders::jsonb, :flags::jsonb,
                     :recommendation, :checked_at, :created_at)
            """),
            {
                "id": check_id,
                "tenant_id": tenant_id,
                "content_id": content_id,
                "content_url": content_url,
                "detected_license": detected_license,
                "license_risk": license_risk.value,
                "risk_score": risk_score,
                "copyright_holders": json.dumps(copyright_holders),
                "flags": json.dumps(flags),
                "recommendation": recommendation,
                "checked_at": now,
                "created_at": now,
            },
        )
        await self._session.flush()

        return LicenseCheck(
            id=check_id,
            tenant_id=tenant_id,
            content_id=content_id,
            content_url=content_url,
            detected_license=detected_license,
            license_risk=license_risk,
            risk_score=risk_score,
            copyright_holders=copyright_holders,
            flags=flags,
            recommendation=recommendation,
            checked_at=now,
            created_at=now,
        )

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
        risk_level: LicenseRisk | None,
    ) -> list[LicenseCheck]:
        """List license checks for a tenant with optional risk filter."""
        offset = (page - 1) * page_size

        if risk_level is not None:
            result = await self._session.execute(
                text("""
                    SELECT id, tenant_id, content_id, content_url, detected_license,
                           license_risk, risk_score, copyright_holders, flags,
                           recommendation, checked_at, created_at
                    FROM cpv_license_checks
                    WHERE tenant_id = :tenant_id AND license_risk = :risk_level
                    ORDER BY risk_score DESC, created_at DESC
                    LIMIT :limit OFFSET :offset
                """),
                {
                    "tenant_id": tenant_id,
                    "risk_level": risk_level.value,
                    "limit": page_size,
                    "offset": offset,
                },
            )
        else:
            result = await self._session.execute(
                text("""
                    SELECT id, tenant_id, content_id, content_url, detected_license,
                           license_risk, risk_score, copyright_holders, flags,
                           recommendation, checked_at, created_at
                    FROM cpv_license_checks
                    WHERE tenant_id = :tenant_id
                    ORDER BY risk_score DESC, created_at DESC
                    LIMIT :limit OFFSET :offset
                """),
                {"tenant_id": tenant_id, "limit": page_size, "offset": offset},
            )

        return [self._row_to_model(row) for row in result.mappings()]

    async def get_high_risk_summary(
        self,
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Aggregate risk level counts for a tenant."""
        result = await self._session.execute(
            text("""
                SELECT license_risk, COUNT(*) AS count
                FROM cpv_license_checks
                WHERE tenant_id = :tenant_id
                GROUP BY license_risk
            """),
            {"tenant_id": tenant_id},
        )
        rows = result.mappings().all()
        by_risk: dict[str, int] = {row["license_risk"]: row["count"] for row in rows}

        return {
            "by_risk_level": by_risk,
            "total": sum(by_risk.values()),
            "high_risk_count": by_risk.get("high", 0) + by_risk.get("critical", 0),
        }

    @staticmethod
    def _row_to_model(row: Any) -> LicenseCheck:
        """Map a database row to a LicenseCheck domain model."""
        return LicenseCheck(
            id=row["id"],
            tenant_id=row["tenant_id"],
            content_id=row["content_id"],
            content_url=row["content_url"],
            detected_license=row["detected_license"],
            license_risk=LicenseRisk(row["license_risk"]),
            risk_score=float(row["risk_score"]),
            copyright_holders=row["copyright_holders"] if isinstance(row["copyright_holders"], list) else [],
            flags=row["flags"] if isinstance(row["flags"], list) else [],
            recommendation=row["recommendation"],
            checked_at=row["checked_at"],
            created_at=row["created_at"],
        )


# ---------------------------------------------------------------------------
# AuditExportRepository
# ---------------------------------------------------------------------------


class AuditExportRepository:
    """Repository for cpv_audit_exports table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        tenant_id: uuid.UUID,
        export_type: str,
        filter_params: dict[str, Any],
    ) -> AuditExport:
        """Insert a new audit export job record with PENDING status."""
        import json

        export_id = uuid.uuid4()
        now = datetime.now(UTC)

        await self._session.execute(
            text("""
                INSERT INTO cpv_audit_exports
                    (id, tenant_id, export_type, status, filter_params,
                     record_count, created_at)
                VALUES
                    (:id, :tenant_id, :export_type, :status, :filter_params::jsonb,
                     0, :created_at)
            """),
            {
                "id": export_id,
                "tenant_id": tenant_id,
                "export_type": export_type,
                "status": AuditExportStatus.PENDING.value,
                "filter_params": json.dumps(filter_params),
                "created_at": now,
            },
        )
        await self._session.flush()

        return AuditExport(
            id=export_id,
            tenant_id=tenant_id,
            export_type=export_type,
            status=AuditExportStatus.PENDING,
            filter_params=filter_params,
            record_count=0,
            export_url=None,
            export_hash=None,
            signed_by=None,
            generated_at=None,
            expires_at=None,
            created_at=now,
        )

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
        """Update audit export job status and completion details."""
        now = datetime.now(UTC)
        generated_at = now if status == AuditExportStatus.COMPLETE else None

        result = await self._session.execute(
            text("""
                UPDATE cpv_audit_exports
                SET status = :status,
                    export_url = :export_url,
                    export_hash = :export_hash,
                    record_count = :record_count,
                    error_message = :error_message,
                    generated_at = :generated_at
                WHERE id = :id AND tenant_id = :tenant_id
                RETURNING id, tenant_id, export_type, status, filter_params,
                          record_count, export_url, export_hash, signed_by,
                          generated_at, expires_at, error_message, created_at
            """),
            {
                "status": status.value,
                "export_url": export_url,
                "export_hash": export_hash,
                "record_count": record_count,
                "error_message": error_message,
                "generated_at": generated_at,
                "id": export_id,
                "tenant_id": tenant_id,
            },
        )
        row = result.mappings().first()
        if row is None:
            raise NotFoundError(f"Audit export {export_id} not found for update")
        return self._row_to_model(row)

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> list[AuditExport]:
        """List audit exports for a tenant, newest first."""
        offset = (page - 1) * page_size
        result = await self._session.execute(
            text("""
                SELECT id, tenant_id, export_type, status, filter_params,
                       record_count, export_url, export_hash, signed_by,
                       generated_at, expires_at, error_message, created_at
                FROM cpv_audit_exports
                WHERE tenant_id = :tenant_id
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"tenant_id": tenant_id, "limit": page_size, "offset": offset},
        )
        return [self._row_to_model(row) for row in result.mappings()]

    @staticmethod
    def _row_to_model(row: Any) -> AuditExport:
        """Map a database row to an AuditExport domain model."""
        return AuditExport(
            id=row["id"],
            tenant_id=row["tenant_id"],
            export_type=row["export_type"],
            status=AuditExportStatus(row["status"]),
            filter_params=row["filter_params"] if isinstance(row["filter_params"], dict) else {},
            record_count=row["record_count"],
            export_url=row["export_url"],
            export_hash=row["export_hash"],
            signed_by=row["signed_by"],
            generated_at=row["generated_at"],
            expires_at=row["expires_at"],
            created_at=row["created_at"],
            error_message=row["error_message"],
        )


__all__ = [
    "ProvenanceRepository",
    "WatermarkRepository",
    "LineageRepository",
    "LicenseRepository",
    "AuditExportRepository",
]
