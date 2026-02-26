"""API router for aumos-content-provenance.

All endpoints registered here and included in main.py under /api/v1.
Routes delegate all logic to service layer — no business logic in routes.

Endpoints:
  POST /provenance/sign               — Sign content with C2PA manifest
  GET  /provenance/verify/{id}         — Verify content provenance
  POST /watermark/embed               — Embed invisible watermark
  POST /watermark/detect              — Detect invisible watermark
  GET  /lineage/{content_id}           — Get training data lineage
  POST /lineage                        — Record a lineage edge
  POST /license/check                  — Check license compliance
  GET  /license/reports                — License compliance reports
  POST /audit/export                   — Export court-admissible audit trail
"""

import base64
import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext, get_current_user
from aumos_common.database import get_db_session
from aumos_common.observability import get_logger

from aumos_content_provenance.adapters.c2pa_client import C2PAClient
from aumos_content_provenance.adapters.repositories import (
    AuditExportRepository,
    LicenseRepository,
    LineageRepository,
    ProvenanceRepository,
    WatermarkRepository,
)
from aumos_content_provenance.adapters.watermark_engine import WatermarkEngine
from aumos_content_provenance.api.schemas import (
    AuditExportRequest,
    AuditExportResponse,
    LicenseCheckRequest,
    LicenseCheckResponse,
    LicenseReportResponse,
    LineageEntryResponse,
    LineageGraphResponse,
    ProvenanceListResponse,
    ProvenanceRecordResponse,
    RecordLineageRequest,
    SignContentRequest,
    SignContentResponse,
    VerifyProvenanceResponse,
    WatermarkDetectRequest,
    WatermarkDetectResponse,
    WatermarkEmbedRequest,
    WatermarkEmbedResponse,
)
from aumos_content_provenance.core.models import LicenseRisk, WatermarkMethod
from aumos_content_provenance.core.services import (
    AuditExportService,
    C2PAService,
    LicenseComplianceService,
    LineageService,
    WatermarkService,
)

logger = get_logger(__name__)

router = APIRouter(tags=["content-provenance"])


# ---------------------------------------------------------------------------
# Dependency builders
# ---------------------------------------------------------------------------


def _get_c2pa_service(
    session: AsyncSession = Depends(get_db_session),
) -> C2PAService:
    """Build C2PAService with session-scoped repository."""
    return C2PAService(
        c2pa_client=C2PAClient(),
        provenance_repository=ProvenanceRepository(session),
        event_publisher=None,
    )


def _get_watermark_service(
    session: AsyncSession = Depends(get_db_session),
) -> WatermarkService:
    """Build WatermarkService with session-scoped repository."""
    from aumos_content_provenance.main import settings

    return WatermarkService(
        watermark_engine=WatermarkEngine(),
        watermark_repository=WatermarkRepository(session),
        default_method=WatermarkMethod(settings.watermark_method),
        default_strength=settings.watermark_strength,
    )


def _get_lineage_service(
    session: AsyncSession = Depends(get_db_session),
) -> LineageService:
    """Build LineageService with session-scoped repository."""
    from aumos_content_provenance.main import settings

    return LineageService(
        lineage_repository=LineageRepository(session),
        max_depth=settings.lineage_max_depth,
    )


def _get_license_service(
    session: AsyncSession = Depends(get_db_session),
) -> LicenseComplianceService:
    """Build LicenseComplianceService with session-scoped repository."""
    return LicenseComplianceService(
        license_repository=LicenseRepository(session),
    )


def _get_audit_service(
    session: AsyncSession = Depends(get_db_session),
) -> AuditExportService:
    """Build AuditExportService with all session-scoped repositories."""
    from aumos_content_provenance.main import settings

    return AuditExportService(
        audit_repository=AuditExportRepository(session),
        provenance_repository=ProvenanceRepository(session),
        lineage_repository=LineageRepository(session),
        license_repository=LicenseRepository(session),
        export_bucket=settings.audit_export_bucket,
    )


# ---------------------------------------------------------------------------
# Provenance endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/provenance/sign",
    response_model=SignContentResponse,
    status_code=201,
    summary="Sign content with C2PA cryptographic provenance",
    description=(
        "Creates a C2PA manifest for AI-generated or AI-processed content. "
        "The manifest cryptographically binds the content hash to metadata "
        "assertions, enabling court-admissible provenance verification."
    ),
)
async def sign_content(
    body: SignContentRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: C2PAService = Depends(_get_c2pa_service),
) -> SignContentResponse:
    """Sign content with a C2PA cryptographic manifest.

    Args:
        body: Sign request with content and assertions.
        tenant: Authenticated tenant context.
        service: C2PA service (injected).

    Returns:
        SignContentResponse with manifest URI and record ID.
    """
    content_bytes = base64.b64decode(body.content_base64)

    result = await service.sign_content(
        tenant_id=tenant.tenant_id,
        content_bytes=content_bytes,
        content_id=body.content_id,
        content_type=body.content_type,
        assertions=body.assertions,
        signer_id=body.signer_id,
        metadata=body.metadata,
    )

    record = result.record
    return SignContentResponse(
        record_id=record.id,
        content_id=record.content_id,
        content_hash=record.content_hash,
        manifest_uri=record.manifest_uri,
        status=record.status,
        signer_id=record.signer_id,
        signed_at=record.signed_at,
    )


@router.get(
    "/provenance/verify/{record_id}",
    response_model=VerifyProvenanceResponse,
    summary="Verify content provenance",
    description=(
        "Verifies a C2PA manifest against content bytes. Checks cryptographic "
        "integrity and content hash match. Updates the record status to VERIFIED "
        "or INVALID. Suitable for court-admissible verification workflows."
    ),
)
async def verify_provenance(
    record_id: uuid.UUID,
    content_base64: str = Query(description="Base64-encoded content bytes to verify against"),
    tenant: TenantContext = Depends(get_current_user),
    service: C2PAService = Depends(_get_c2pa_service),
) -> VerifyProvenanceResponse:
    """Verify content provenance against its C2PA manifest.

    Args:
        record_id: UUID of the provenance record to verify.
        content_base64: Base64-encoded content bytes.
        tenant: Authenticated tenant context.
        service: C2PA service (injected).

    Returns:
        VerifyProvenanceResponse with validation result.
    """
    content_bytes = base64.b64decode(content_base64)

    result = await service.verify_provenance(
        tenant_id=tenant.tenant_id,
        record_id=record_id,
        content_bytes=content_bytes,
    )

    return VerifyProvenanceResponse(
        record_id=result.record.id if result.record else record_id,
        is_valid=result.is_valid,
        status=result.status,
        reason=result.reason,
        content_hash=result.record.content_hash if result.record else None,
        manifest_uri=result.record.manifest_uri if result.record else None,
    )


@router.get(
    "/provenance",
    response_model=ProvenanceListResponse,
    summary="List provenance records",
    description="Returns a paginated list of C2PA provenance records for the current tenant.",
)
async def list_provenance(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Records per page"),
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ProvenanceListResponse:
    """List provenance records for the current tenant.

    Args:
        page: Page number (1-indexed).
        page_size: Records per page.
        tenant: Authenticated tenant context.
        session: Async DB session.

    Returns:
        Paginated ProvenanceListResponse.
    """
    repo = ProvenanceRepository(session)
    records = await repo.list_by_tenant(
        tenant_id=tenant.tenant_id, page=page, page_size=page_size
    )

    return ProvenanceListResponse(
        items=[
            ProvenanceRecordResponse(
                id=r.id,
                tenant_id=r.tenant_id,
                content_id=r.content_id,
                content_type=r.content_type,
                content_hash=r.content_hash,
                manifest_uri=r.manifest_uri,
                status=r.status,
                signer_id=r.signer_id,
                signed_at=r.signed_at,
                verified_at=r.verified_at,
                metadata=r.metadata,
                created_at=r.created_at,
            )
            for r in records
        ],
        total=len(records),
        page=page,
        page_size=page_size,
    )


# ---------------------------------------------------------------------------
# Watermark endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/watermark/embed",
    response_model=WatermarkEmbedResponse,
    status_code=201,
    summary="Embed invisible watermark",
    description=(
        "Embeds an imperceptible watermark into an image or document using "
        "DWT+DCT frequency-domain techniques. The watermark survives JPEG "
        "compression and moderate resizing while remaining invisible to the eye."
    ),
)
async def embed_watermark(
    body: WatermarkEmbedRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: WatermarkService = Depends(_get_watermark_service),
) -> WatermarkEmbedResponse:
    """Embed an invisible watermark into content.

    Args:
        body: Watermark embed request.
        tenant: Authenticated tenant context.
        service: Watermark service (injected).

    Returns:
        WatermarkEmbedResponse with watermarked content bytes and metadata.
    """
    content_bytes = base64.b64decode(body.content_base64)

    result = await service.embed_watermark(
        tenant_id=tenant.tenant_id,
        content_id=body.content_id,
        content_bytes=content_bytes,
        payload=body.payload,
        method=body.method,
        strength=body.strength,
    )

    return WatermarkEmbedResponse(
        watermark_id=result.watermark.id,
        content_id=result.watermark.content_id,
        method=result.watermark.method,
        strength=result.watermark.strength,
        watermarked_base64=base64.b64encode(result.watermarked_bytes).decode("utf-8"),
        payload_hash=result.watermark.payload_hash,
    )


@router.post(
    "/watermark/detect",
    response_model=WatermarkDetectResponse,
    summary="Detect invisible watermark",
    description=(
        "Scans content for an embedded invisible watermark. Returns the "
        "extracted payload if a watermark is found, allowing attribution "
        "of AI-generated content back to its originating tenant/model."
    ),
)
async def detect_watermark(
    body: WatermarkDetectRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: WatermarkService = Depends(_get_watermark_service),
) -> WatermarkDetectResponse:
    """Detect an invisible watermark in content.

    Args:
        body: Watermark detect request.
        tenant: Authenticated tenant context.
        service: Watermark service (injected).

    Returns:
        WatermarkDetectResponse with detection result and extracted payload.
    """
    content_bytes = base64.b64decode(body.content_base64)

    result = await service.detect_watermark(
        tenant_id=tenant.tenant_id,
        content_bytes=content_bytes,
        method=body.method,
    )

    return WatermarkDetectResponse(
        detected=result.detected,
        payload=result.payload,
        content_id=result.content_id,
        method=body.method,
    )


# ---------------------------------------------------------------------------
# Lineage endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/lineage/{content_id}",
    response_model=LineageGraphResponse,
    summary="Get training data lineage",
    description=(
        "Traverses the lineage graph to reconstruct the full provenance chain "
        "for a content item: training datasets → base model → fine-tuning → output. "
        "Essential for IP discovery and copyright compliance analysis."
    ),
)
async def get_lineage(
    content_id: str,
    tenant: TenantContext = Depends(get_current_user),
    service: LineageService = Depends(_get_lineage_service),
) -> LineageGraphResponse:
    """Get full training data lineage for a content item.

    Args:
        content_id: The content item to trace lineage for.
        tenant: Authenticated tenant context.
        service: Lineage service (injected).

    Returns:
        LineageGraphResponse with ordered ancestry chain.
    """
    graph = await service.get_lineage(
        tenant_id=tenant.tenant_id,
        content_id=content_id,
    )

    return LineageGraphResponse(
        content_id=graph.content_id,
        entries=[
            LineageEntryResponse(
                id=e.id,
                parent_node_id=e.parent_node_id,
                parent_node_type=e.parent_node_type,
                child_node_id=e.child_node_id,
                child_node_type=e.child_node_type,
                relationship=e.relationship,
                metadata=e.metadata,
                created_at=e.created_at,
            )
            for e in graph.entries
        ],
        depth=graph.depth,
    )


@router.post(
    "/lineage",
    response_model=LineageEntryResponse,
    status_code=201,
    summary="Record lineage edge",
    description=(
        "Records a single provenance relationship edge in the lineage graph. "
        "Call this when a model is trained on a dataset, when outputs are "
        "generated by a model, or when fine-tuning relationships are established."
    ),
)
async def record_lineage(
    body: RecordLineageRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: LineageService = Depends(_get_lineage_service),
) -> LineageEntryResponse:
    """Record a lineage edge between two nodes.

    Args:
        body: Lineage edge recording request.
        tenant: Authenticated tenant context.
        service: Lineage service (injected).

    Returns:
        LineageEntryResponse for the created edge.
    """
    entry = await service.record_lineage(
        tenant_id=tenant.tenant_id,
        parent_node_id=body.parent_node_id,
        parent_node_type=body.parent_node_type,
        child_node_id=body.child_node_id,
        child_node_type=body.child_node_type,
        relationship=body.relationship,
        metadata=body.metadata,
    )

    return LineageEntryResponse(
        id=entry.id,
        parent_node_id=entry.parent_node_id,
        parent_node_type=entry.parent_node_type,
        child_node_id=entry.child_node_id,
        child_node_type=entry.child_node_type,
        relationship=entry.relationship,
        metadata=entry.metadata,
        created_at=entry.created_at,
    )


# ---------------------------------------------------------------------------
# License compliance endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/license/check",
    response_model=LicenseCheckResponse,
    status_code=201,
    summary="Check license compliance",
    description=(
        "Assesses the license risk for a training data item or content source. "
        "Returns risk level (LOW/MEDIUM/HIGH/CRITICAL), flags, and a legal "
        "recommendation. Critical for managing exposure in the context of active "
        "AI copyright litigation."
    ),
)
async def check_license(
    body: LicenseCheckRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: LicenseComplianceService = Depends(_get_license_service),
) -> LicenseCheckResponse:
    """Check license compliance for a content item.

    Args:
        body: License check request.
        tenant: Authenticated tenant context.
        service: License compliance service (injected).

    Returns:
        LicenseCheckResponse with risk assessment and recommendation.
    """
    check = await service.check_license(
        tenant_id=tenant.tenant_id,
        content_id=body.content_id,
        detected_license=body.detected_license,
        content_url=body.content_url,
        copyright_holders=body.copyright_holders,
    )

    return LicenseCheckResponse(
        id=check.id,
        content_id=check.content_id,
        content_url=check.content_url,
        detected_license=check.detected_license,
        license_risk=check.license_risk,
        risk_score=check.risk_score,
        copyright_holders=check.copyright_holders,
        flags=check.flags,
        recommendation=check.recommendation,
        checked_at=check.checked_at,
        created_at=check.created_at,
    )


@router.get(
    "/license/reports",
    response_model=LicenseReportResponse,
    summary="Get license compliance reports",
    description=(
        "Returns a paginated list of license compliance checks with an "
        "aggregated risk summary for the current tenant. Supports filtering "
        "by risk level for focused legal review."
    ),
)
async def get_license_reports(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Records per page"),
    risk_level: LicenseRisk | None = Query(default=None, description="Filter by risk level"),
    tenant: TenantContext = Depends(get_current_user),
    service: LicenseComplianceService = Depends(_get_license_service),
) -> LicenseReportResponse:
    """Get license compliance reports for the current tenant.

    Args:
        page: Page number (1-indexed).
        page_size: Records per page.
        risk_level: Optional filter by risk level.
        tenant: Authenticated tenant context.
        service: License compliance service (injected).

    Returns:
        Paginated LicenseReportResponse with risk summary.
    """
    checks, summary = await service.get_compliance_report(
        tenant_id=tenant.tenant_id,
        page=page,
        page_size=page_size,
        risk_level=risk_level,
    )

    return LicenseReportResponse(
        items=[
            LicenseCheckResponse(
                id=c.id,
                content_id=c.content_id,
                content_url=c.content_url,
                detected_license=c.detected_license,
                license_risk=c.license_risk,
                risk_score=c.risk_score,
                copyright_holders=c.copyright_holders,
                flags=c.flags,
                recommendation=c.recommendation,
                checked_at=c.checked_at,
                created_at=c.created_at,
            )
            for c in checks
        ],
        total=len(checks),
        page=page,
        page_size=page_size,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Audit export endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/audit/export",
    response_model=AuditExportResponse,
    status_code=201,
    summary="Export court-admissible audit trail",
    description=(
        "Generates a cryptographically hashed export package of provenance records, "
        "lineage chains, watermark logs, and license checks. The package includes "
        "a SHA-256 hash for tamper evidence — suitable for legal discovery and "
        "court proceedings related to AI copyright claims."
    ),
)
async def export_audit_trail(
    body: AuditExportRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: AuditExportService = Depends(_get_audit_service),
) -> AuditExportResponse:
    """Generate a court-admissible audit trail export.

    Args:
        body: Audit export request specifying scope and filters.
        tenant: Authenticated tenant context.
        service: Audit export service (injected).

    Returns:
        AuditExportResponse with job status and export URL.
    """
    export = await service.export_audit_trail(
        tenant_id=tenant.tenant_id,
        export_type=body.export_type,
        filter_params=body.filter_params,
    )

    return AuditExportResponse(
        export_id=export.id,
        tenant_id=export.tenant_id,
        export_type=export.export_type,
        status=export.status,
        filter_params=export.filter_params,
        record_count=export.record_count,
        export_url=export.export_url,
        export_hash=export.export_hash,
        generated_at=export.generated_at,
        expires_at=export.expires_at,
        error_message=export.error_message,
        created_at=export.created_at,
    )
