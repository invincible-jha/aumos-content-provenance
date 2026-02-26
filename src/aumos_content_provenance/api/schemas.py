"""Request/response Pydantic schemas for aumos-content-provenance API.

All schemas use strict validation. No optional fields with dangerous defaults.
Input schemas: validate at system boundary
Output schemas: serialize domain models to JSON
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from aumos_content_provenance.core.models import (
    AuditExportStatus,
    LicenseRisk,
    LineageNodeType,
    ProvenanceStatus,
    WatermarkMethod,
)


# ---------------------------------------------------------------------------
# Provenance Sign
# ---------------------------------------------------------------------------


class SignContentRequest(BaseModel):
    """Request to sign content with a C2PA manifest."""

    content_id: str = Field(
        description="Stable identifier for this content (e.g., file UUID or content hash)"
    )
    content_type: str = Field(
        description="MIME type of the content (e.g., image/jpeg, text/plain, application/pdf)"
    )
    content_base64: str = Field(
        description="Base64-encoded content bytes to sign"
    )
    assertions: list[dict[str, Any]] = Field(
        default_factory=list,
        description="C2PA assertions to include in the manifest",
    )
    signer_id: str = Field(
        default="aumos-default-signer",
        description="Identifier for the signing key/cert to use",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata to store with the provenance record",
    )

    @field_validator("content_id")
    @classmethod
    def content_id_not_blank(cls, value: str) -> str:
        """Ensure content_id is not whitespace-only."""
        if not value.strip():
            raise ValueError("content_id cannot be blank")
        return value.strip()

    @field_validator("content_type")
    @classmethod
    def content_type_valid(cls, value: str) -> str:
        """Ensure content_type looks like a MIME type."""
        if "/" not in value:
            raise ValueError("content_type must be a valid MIME type (e.g., image/jpeg)")
        return value.lower().strip()


class SignContentResponse(BaseModel):
    """Response after signing content with C2PA."""

    record_id: uuid.UUID = Field(description="Provenance record UUID")
    content_id: str = Field(description="The signed content identifier")
    content_hash: str = Field(description="SHA-256 of the signed content")
    manifest_uri: str = Field(description="URI where the C2PA manifest is stored")
    status: ProvenanceStatus = Field(description="Provenance status after signing")
    signer_id: str = Field(description="Key ID used for signing")
    signed_at: datetime = Field(description="Timestamp of signing")


# ---------------------------------------------------------------------------
# Provenance Verify
# ---------------------------------------------------------------------------


class VerifyProvenanceResponse(BaseModel):
    """Response after verifying a content provenance record."""

    record_id: uuid.UUID = Field(description="Provenance record UUID")
    is_valid: bool = Field(description="Whether the content matches the signed manifest")
    status: ProvenanceStatus = Field(description="Updated provenance status")
    reason: str = Field(description="Human-readable explanation of the verification result")
    content_hash: str | None = Field(default=None, description="Stored content hash")
    manifest_uri: str | None = Field(default=None, description="Manifest URI for reference")


# ---------------------------------------------------------------------------
# Watermark Embed
# ---------------------------------------------------------------------------


class WatermarkEmbedRequest(BaseModel):
    """Request to embed an invisible watermark into content."""

    content_id: str = Field(description="Stable content identifier")
    content_base64: str = Field(description="Base64-encoded content bytes")
    payload: str | None = Field(
        default=None,
        description="Payload to embed. Defaults to tenant_id:content_id if not provided.",
    )
    method: WatermarkMethod = Field(
        default=WatermarkMethod.DWT_DCT,
        description="Watermarking algorithm to use",
    )
    strength: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Embedding strength (0.0 = most invisible, 1.0 = most robust)",
    )


class WatermarkEmbedResponse(BaseModel):
    """Response after embedding a watermark."""

    watermark_id: uuid.UUID = Field(description="Watermark record UUID")
    content_id: str = Field(description="Content that was watermarked")
    method: WatermarkMethod = Field(description="Algorithm used")
    strength: float = Field(description="Embedding strength applied")
    watermarked_base64: str = Field(description="Base64-encoded watermarked content bytes")
    payload_hash: str = Field(description="SHA-256 of the embedded payload for verification")


# ---------------------------------------------------------------------------
# Watermark Detect
# ---------------------------------------------------------------------------


class WatermarkDetectRequest(BaseModel):
    """Request to detect a watermark in content."""

    content_base64: str = Field(description="Base64-encoded content bytes to scan")
    method: WatermarkMethod = Field(
        default=WatermarkMethod.DWT_DCT,
        description="Detection algorithm (must match embedding algorithm)",
    )


class WatermarkDetectResponse(BaseModel):
    """Response from watermark detection."""

    detected: bool = Field(description="Whether a watermark was found")
    payload: str | None = Field(default=None, description="Extracted payload if detected")
    content_id: str | None = Field(
        default=None,
        description="Parsed content_id from payload if it follows the tenant:content_id format",
    )
    method: WatermarkMethod = Field(description="Detection algorithm used")


# ---------------------------------------------------------------------------
# Lineage
# ---------------------------------------------------------------------------


class RecordLineageRequest(BaseModel):
    """Request to record a lineage edge between two nodes."""

    parent_node_id: str = Field(description="Source node identifier (dataset, model, etc.)")
    parent_node_type: LineageNodeType = Field(description="Type of the source node")
    child_node_id: str = Field(description="Derived node identifier")
    child_node_type: LineageNodeType = Field(description="Type of the derived node")
    relationship: str = Field(
        description="Relationship type: trained_on, fine_tuned_on, generated_by, derived_from, evaluated_on"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional edge metadata (versions, timestamps, etc.)",
    )


class LineageEntryResponse(BaseModel):
    """A single lineage edge in the graph."""

    id: uuid.UUID
    parent_node_id: str
    parent_node_type: LineageNodeType
    child_node_id: str
    child_node_type: LineageNodeType
    relationship: str
    metadata: dict[str, Any]
    created_at: datetime


class LineageGraphResponse(BaseModel):
    """Full lineage graph for a content item."""

    content_id: str = Field(description="The content item whose lineage was queried")
    entries: list[LineageEntryResponse] = Field(description="Ordered list of lineage edges root-to-leaf")
    depth: int = Field(description="Number of edges in the lineage chain")


# ---------------------------------------------------------------------------
# License Compliance
# ---------------------------------------------------------------------------


class LicenseCheckRequest(BaseModel):
    """Request to check license compliance for a content item."""

    content_id: str = Field(description="Dataset/model/content identifier")
    detected_license: str = Field(
        description="SPDX license identifier (e.g., MIT, Apache-2.0, UNKNOWN)"
    )
    content_url: str | None = Field(default=None, description="Source URL of the content")
    copyright_holders: list[str] = Field(
        default_factory=list,
        description="Known copyright holders",
    )


class LicenseCheckResponse(BaseModel):
    """Response from a license compliance check."""

    id: uuid.UUID = Field(description="License check record UUID")
    content_id: str
    content_url: str | None
    detected_license: str
    license_risk: LicenseRisk
    risk_score: float = Field(ge=0.0, le=1.0, description="Numeric risk score (0.0–1.0)")
    copyright_holders: list[str]
    flags: list[str] = Field(description="Specific legal concern flags")
    recommendation: str = Field(description="Legal recommendation for use")
    checked_at: datetime
    created_at: datetime


class LicenseReportResponse(BaseModel):
    """Aggregated license compliance report for a tenant."""

    items: list[LicenseCheckResponse]
    total: int
    page: int
    page_size: int
    summary: dict[str, Any] = Field(description="High-risk summary with counts per risk level")


# ---------------------------------------------------------------------------
# Audit Export
# ---------------------------------------------------------------------------


class AuditExportRequest(BaseModel):
    """Request to generate a court-admissible audit trail export."""

    export_type: str = Field(
        description="Export scope: provenance | lineage | license | full"
    )
    filter_params: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional query parameters to filter which records are exported",
    )

    @field_validator("export_type")
    @classmethod
    def export_type_valid(cls, value: str) -> str:
        """Validate export_type is one of the supported values."""
        valid_types = {"provenance", "lineage", "license", "full"}
        if value not in valid_types:
            raise ValueError(f"export_type must be one of: {valid_types}")
        return value


class AuditExportResponse(BaseModel):
    """Response after initiating or checking an audit export."""

    export_id: uuid.UUID = Field(description="Audit export job UUID")
    tenant_id: uuid.UUID
    export_type: str
    status: AuditExportStatus
    filter_params: dict[str, Any]
    record_count: int
    export_url: str | None = Field(default=None, description="S3 URL of the generated export package")
    export_hash: str | None = Field(
        default=None, description="SHA-256 of the export package for tamper evidence"
    )
    generated_at: datetime | None = None
    expires_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime


# ---------------------------------------------------------------------------
# Shared list wrappers
# ---------------------------------------------------------------------------


class ProvenanceRecordResponse(BaseModel):
    """Provenance record details."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    content_id: str
    content_type: str
    content_hash: str
    manifest_uri: str
    status: ProvenanceStatus
    signer_id: str
    signed_at: datetime
    verified_at: datetime | None
    metadata: dict[str, Any]
    created_at: datetime


class ProvenanceListResponse(BaseModel):
    """Paginated list of provenance records."""

    items: list[ProvenanceRecordResponse]
    total: int
    page: int
    page_size: int


__all__ = [
    "SignContentRequest",
    "SignContentResponse",
    "VerifyProvenanceResponse",
    "WatermarkEmbedRequest",
    "WatermarkEmbedResponse",
    "WatermarkDetectRequest",
    "WatermarkDetectResponse",
    "RecordLineageRequest",
    "LineageEntryResponse",
    "LineageGraphResponse",
    "LicenseCheckRequest",
    "LicenseCheckResponse",
    "LicenseReportResponse",
    "AuditExportRequest",
    "AuditExportResponse",
    "ProvenanceRecordResponse",
    "ProvenanceListResponse",
]
