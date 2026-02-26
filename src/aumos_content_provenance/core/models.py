"""Domain models for aumos-content-provenance.

All models are pure Python dataclasses — no SQLAlchemy, no ORM concerns.
The repository layer translates between these models and the database.

Table prefix: cpv_
- cpv_provenance_records
- cpv_watermarks
- cpv_lineage_entries
- cpv_license_checks
- cpv_audit_exports
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ProvenanceStatus(str, Enum):
    """Status of a C2PA provenance signing operation."""

    SIGNED = "signed"
    VERIFIED = "verified"
    INVALID = "invalid"
    REVOKED = "revoked"
    PENDING = "pending"


class WatermarkMethod(str, Enum):
    """Invisible watermarking algorithm."""

    DWT_DCT = "dwtDct"           # Discrete Wavelet Transform + DCT (default, robust)
    DWT_DCT_SVD = "dwtDctSvd"   # DWT + DCT + SVD (most robust, slight visibility)
    RIVAGG = "rivaGan"           # RivaGAN deep learning watermark


class LineageNodeType(str, Enum):
    """Type of node in the training data lineage graph."""

    TRAINING_DATASET = "training_dataset"
    MODEL = "model"
    FINE_TUNED_MODEL = "fine_tuned_model"
    OUTPUT = "output"
    DERIVED_DATASET = "derived_dataset"


class LicenseRisk(str, Enum):
    """Assessed risk level for a content license."""

    LOW = "low"          # Permissive (MIT, Apache, CC0)
    MEDIUM = "medium"    # Copyleft (GPL, LGPL, CC-BY-SA)
    HIGH = "high"        # Restrictive (CC-BY-NC, proprietary)
    CRITICAL = "critical"  # Unknown or no license — lawsuit risk


class AuditExportStatus(str, Enum):
    """Status of an audit trail export job."""

    PENDING = "pending"
    GENERATING = "generating"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class ProvenanceRecord:
    """C2PA signed content provenance record.

    Stores the C2PA manifest, content hash, and signing metadata for a
    piece of AI-generated or AI-processed content. The manifest can be
    used to verify authenticity and provenance chain in court proceedings.

    Table: cpv_provenance_records
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    content_id: str                   # Stable content identifier (e.g., file hash or UUID)
    content_type: str                  # MIME type (image/jpeg, text/plain, etc.)
    content_hash: str                  # SHA-256 of raw content bytes
    c2pa_manifest: dict[str, Any]     # Full C2PA manifest (JUMBF JSON representation)
    manifest_uri: str                  # URI where manifest is stored / retrievable
    status: ProvenanceStatus
    signer_id: str                     # Key ID used for signing
    signed_at: datetime
    verified_at: datetime | None
    metadata: dict[str, Any]
    created_at: datetime


@dataclass
class Watermark:
    """Invisible watermark embedded in content.

    Tracks which watermark payload was embedded into which content,
    using which method. Detection results can be stored alongside
    for audit trail purposes.

    Table: cpv_watermarks
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    content_id: str                    # References ProvenanceRecord.content_id
    method: WatermarkMethod
    payload: str                       # The hidden payload (tenant/content identifier)
    payload_hash: str                  # SHA-256 of payload for detection verification
    strength: float                    # Embedding strength used (0.0–1.0)
    detected: bool | None              # None = not yet verified, True/False = verified
    detected_at: datetime | None
    created_at: datetime


@dataclass
class LineageEntry:
    """Single edge in the training data lineage graph.

    Represents a provenance relationship: parent_node produced child_node.
    By traversing the graph from an output backward, you can reconstruct
    the full chain of training data → model → fine-tuning → output.

    Table: cpv_lineage_entries
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    parent_node_id: str                # Source node (dataset, model, etc.)
    parent_node_type: LineageNodeType
    child_node_id: str                 # Derived node (model, output, etc.)
    child_node_type: LineageNodeType
    relationship: str                  # "trained_on", "fine_tuned_on", "generated_by"
    metadata: dict[str, Any]          # Versions, timestamps, hyperparameters
    created_at: datetime


@dataclass
class LicenseCheck:
    """License compliance check result for a piece of training data or content.

    Records the assessed license, risk level, and any copyright flags.
    Designed to support legal discovery in copyright litigation contexts.

    Table: cpv_license_checks
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    content_id: str                    # Dataset, model, or content being checked
    content_url: str | None            # Source URL if known
    detected_license: str              # SPDX license identifier or "UNKNOWN"
    license_risk: LicenseRisk
    risk_score: float                  # 0.0–1.0 composite risk
    copyright_holders: list[str]       # Identified copyright holders
    flags: list[str]                   # Specific concerns (e.g., "no_commercial_use")
    recommendation: str                # Legal recommendation for use
    checked_at: datetime
    created_at: datetime


@dataclass
class AuditExport:
    """Court-admissible audit trail export record.

    Represents a generated audit export package containing provenance records,
    watermark logs, lineage chains, and license checks. Includes a cryptographic
    hash of the export package for tamper evidence.

    Table: cpv_audit_exports
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    export_type: str                   # "provenance", "lineage", "license", "full"
    status: AuditExportStatus
    filter_params: dict[str, Any]     # Query parameters used to generate the export
    record_count: int
    export_url: str | None            # S3 URL of the generated export package
    export_hash: str | None           # SHA-256 of export package for tamper evidence
    signed_by: str | None             # Key ID that signed the export
    generated_at: datetime | None
    expires_at: datetime | None       # Export package retention
    created_at: datetime
    error_message: str | None = field(default=None)


__all__ = [
    "ProvenanceStatus",
    "WatermarkMethod",
    "LineageNodeType",
    "LicenseRisk",
    "AuditExportStatus",
    "ProvenanceRecord",
    "Watermark",
    "LineageEntry",
    "LicenseCheck",
    "AuditExport",
]
