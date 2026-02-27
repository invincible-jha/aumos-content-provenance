"""Adapters layer — repositories, external clients, and messaging.

Concrete implementations of all Protocol interfaces defined in core/interfaces.py.
Each adapter is independently importable; the application wires them together
in main.py via dependency injection into the service layer.
"""

from aumos_content_provenance.adapters.audit_reporter import (
    AuditManifest,
    AuditRecord,
    AuditScope,
    ComplianceMapping,
    EvidencePackage,
    ExpertWitnessReport,
    ProvenanceAuditReporter,
    ReportFormat,
    TimestampToken,
)
from aumos_content_provenance.adapters.c2pa_client import C2PAClient
from aumos_content_provenance.adapters.chain_of_custody import (
    AccessLogEntry,
    ChainOfCustody,
    CustodyAttestation,
    CustodyChain,
    CustodyEventType,
    CustodyRecord,
)
from aumos_content_provenance.adapters.kafka import KafkaEventPublisher
from aumos_content_provenance.adapters.license_checker import (
    AttributionRequirement,
    CompatibilityResult,
    ComplianceCertificate,
    LicenseChecker,
    LicenseFamily,
    LicenseProfile,
    UseCase,
)
from aumos_content_provenance.adapters.lineage_resolver import (
    DerivativeWorkResult,
    ImpactAnalysis,
    LineageEdge,
    LineageGraphResult,
    LineageNode,
    LineageRelationship,
    LineageResolver,
)
from aumos_content_provenance.adapters.metadata_embedder import (
    AUMOS_PROVENANCE_NAMESPACE,
    EmbedFormat,
    EmbedResult,
    ExtractResult,
    MetadataEmbedder,
    ProvenanceMetadata,
)
from aumos_content_provenance.adapters.provenance_tracker import (
    ProvenanceChain,
    ProvenanceSource,
    ProvenanceTracker,
    TamperEvidence,
    TransformationStep,
)
from aumos_content_provenance.adapters.repositories import (
    AuditExportRepository,
    LicenseRepository,
    LineageRepository,
    ProvenanceRepository,
    WatermarkRepository,
)
from aumos_content_provenance.adapters.retention_manager import (
    ExpiryNotification,
    RetentionAuditReport,
    RetentionManager,
    RetentionPolicy,
    RetentionRecord,
    RetentionRegulation,
    RetentionStatus,
)
from aumos_content_provenance.adapters.tamper_detector import (
    TamperDetector,
    TamperIndicator,
    TamperMethod,
    TamperReport,
    TamperSeverity,
)
from aumos_content_provenance.adapters.watermark_engine import WatermarkEngine

__all__ = [
    # C2PA
    "C2PAClient",
    # Watermark
    "WatermarkEngine",
    # Repositories
    "ProvenanceRepository",
    "WatermarkRepository",
    "LineageRepository",
    "LicenseRepository",
    "AuditExportRepository",
    # Kafka
    "KafkaEventPublisher",
    # Provenance Tracker
    "ProvenanceTracker",
    "ProvenanceSource",
    "TransformationStep",
    "ProvenanceChain",
    "TamperEvidence",
    # Tamper Detector
    "TamperDetector",
    "TamperMethod",
    "TamperSeverity",
    "TamperIndicator",
    "TamperReport",
    # Metadata Embedder
    "MetadataEmbedder",
    "EmbedFormat",
    "ProvenanceMetadata",
    "EmbedResult",
    "ExtractResult",
    "AUMOS_PROVENANCE_NAMESPACE",
    # Chain of Custody
    "ChainOfCustody",
    "CustodyEventType",
    "CustodyRecord",
    "CustodyChain",
    "CustodyAttestation",
    "AccessLogEntry",
    # Retention Manager
    "RetentionManager",
    "RetentionRegulation",
    "RetentionStatus",
    "RetentionPolicy",
    "RetentionRecord",
    "ExpiryNotification",
    "RetentionAuditReport",
    # Lineage Resolver
    "LineageResolver",
    "LineageRelationship",
    "LineageNode",
    "LineageEdge",
    "LineageGraphResult",
    "ImpactAnalysis",
    "DerivativeWorkResult",
    # License Checker
    "LicenseChecker",
    "LicenseFamily",
    "UseCase",
    "LicenseProfile",
    "CompatibilityResult",
    "AttributionRequirement",
    "ComplianceCertificate",
    # Audit Reporter
    "ProvenanceAuditReporter",
    "AuditScope",
    "ReportFormat",
    "AuditRecord",
    "TimestampToken",
    "AuditManifest",
    "EvidencePackage",
    "ExpertWitnessReport",
    "ComplianceMapping",
]
