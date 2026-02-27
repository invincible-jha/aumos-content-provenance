"""Retention manager adapter for aumos-content-provenance.

Manages record retention policies for provenance and audit data.
Supports time-based retention rules, legal hold overrides, automated
expiry detection, and compliance regulation mapping. Designed for
GDPR, CCPA, HIPAA, and SOX retention requirements.
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class RetentionRegulation(str, Enum):
    """Applicable regulatory framework driving retention requirements."""

    GDPR = "gdpr"                      # EU: 6 years (art. 17 right to erasure)
    CCPA = "ccpa"                      # California: 3 years for business records
    HIPAA = "hipaa"                    # Health: 6 years from creation
    SOX = "sox"                        # Financial: 7 years audit records
    PCI_DSS = "pci_dss"               # Payment: 1 year online, 3 years paper
    ISO_27001 = "iso_27001"            # Security: per documented policy
    CUSTOM = "custom"                  # Organization-defined


class RetentionStatus(str, Enum):
    """Current status of a retention record."""

    ACTIVE = "active"                  # Within retention period
    EXPIRING_SOON = "expiring_soon"    # Expires within 30 days
    EXPIRED = "expired"                # Past retention period, eligible for purge
    LEGAL_HOLD = "legal_hold"          # Held regardless of expiry
    PURGED = "purged"                  # Data has been deleted


@dataclass
class RetentionPolicy:
    """A retention rule definition for a category of records."""

    policy_id: str
    name: str
    description: str
    regulations: list[RetentionRegulation]
    retention_days: int                # How many days records must be kept
    legal_hold_override: bool          # True = legal holds can override this policy
    auto_purge: bool                   # Whether to schedule automatic deletion
    applies_to: list[str]              # Record types this policy covers
    created_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RetentionRecord:
    """Tracking record linking a data item to its retention policy."""

    retention_id: str
    asset_id: str                      # ID of the record under retention management
    asset_type: str                    # Type: "provenance", "audit", "watermark", etc.
    policy_id: str
    tenant_id: str
    acquired_at: datetime              # When data was first recorded
    expires_at: datetime               # When retention period ends
    status: RetentionStatus
    legal_hold: bool
    legal_hold_reason: str | None
    legal_hold_placed_at: datetime | None
    legal_hold_released_at: datetime | None
    purged_at: datetime | None
    extended_until: datetime | None    # For retention period extensions
    last_reviewed_at: datetime | None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExpiryNotification:
    """Notification that a record is approaching or past its expiry."""

    notification_id: str
    asset_id: str
    asset_type: str
    tenant_id: str
    expires_at: datetime
    days_until_expiry: int             # Negative means already expired
    status: RetentionStatus
    policy_name: str
    legal_hold: bool
    requires_action: bool


@dataclass
class RetentionAuditReport:
    """Summary report of retention compliance status."""

    report_id: str
    tenant_id: str
    generated_at: datetime
    total_records: int
    active_records: int
    expiring_soon_count: int
    expired_count: int
    legal_hold_count: int
    purged_count: int
    by_regulation: dict[str, int]      # Regulation -> count of records subject to it
    policy_breakdown: dict[str, int]   # Policy name -> count of records
    compliance_score: float            # 0.0–1.0; 1.0 = all records in compliance


# Default regulation retention requirements (in days)
_REGULATION_RETENTION_DAYS: dict[RetentionRegulation, int] = {
    RetentionRegulation.GDPR: 6 * 365,        # 6 years
    RetentionRegulation.CCPA: 3 * 365,        # 3 years
    RetentionRegulation.HIPAA: 6 * 365,       # 6 years
    RetentionRegulation.SOX: 7 * 365,         # 7 years
    RetentionRegulation.PCI_DSS: 365,         # 1 year (online)
    RetentionRegulation.ISO_27001: 3 * 365,   # 3 years (recommended)
    RetentionRegulation.CUSTOM: 365,          # 1 year default for custom
}


class RetentionManager:
    """Manage data retention policies and compliance for provenance records.

    Supports:
    - Policy creation with multi-regulation requirements
    - Automatic expiry calculation and tracking
    - Legal hold placement and release
    - Retention period extensions
    - Compliance reporting with regulation-level breakdown

    In production, retention records are stored in the database via
    a repository adapter. This implementation uses in-memory storage
    for testability.
    """

    def __init__(self) -> None:
        self._policies: dict[str, RetentionPolicy] = {}
        self._records: dict[str, RetentionRecord] = {}
        self._built_in_policies: dict[str, RetentionPolicy] = {}
        self._initialize_built_in_policies()

    def _initialize_built_in_policies(self) -> None:
        """Seed built-in policies for common regulations."""
        now = datetime.now(UTC)

        for regulation in RetentionRegulation:
            if regulation == RetentionRegulation.CUSTOM:
                continue

            days = _REGULATION_RETENTION_DAYS[regulation]
            policy_id = f"builtin-{regulation.value}"
            policy = RetentionPolicy(
                policy_id=policy_id,
                name=f"{regulation.value.upper()} Default",
                description=f"Built-in {regulation.value.upper()} retention policy ({days} days)",
                regulations=[regulation],
                retention_days=days,
                legal_hold_override=True,
                auto_purge=False,
                applies_to=["provenance", "audit", "lineage", "license"],
                created_at=now,
            )
            self._built_in_policies[policy_id] = policy

    async def create_policy(
        self,
        name: str,
        description: str,
        regulations: list[RetentionRegulation],
        retention_days: int | None = None,
        auto_purge: bool = False,
        legal_hold_override: bool = True,
        applies_to: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> RetentionPolicy:
        """Define a new retention policy.

        If retention_days is not specified, uses the maximum required duration
        across all listed regulations.

        Args:
            name: Human-readable policy name.
            description: Description of the policy's purpose.
            regulations: Applicable regulations (determines minimum duration).
            retention_days: Override retention duration in days.
            auto_purge: Whether to schedule automatic deletion on expiry.
            legal_hold_override: Whether legal holds can block purging.
            applies_to: Record type labels this policy applies to.
            metadata: Additional policy metadata.

        Returns:
            The created RetentionPolicy.
        """
        if retention_days is None:
            regulation_days = [
                _REGULATION_RETENTION_DAYS.get(reg, 365)
                for reg in regulations
            ]
            retention_days = max(regulation_days) if regulation_days else 365

        policy = RetentionPolicy(
            policy_id=str(uuid.uuid4()),
            name=name,
            description=description,
            regulations=regulations,
            retention_days=retention_days,
            legal_hold_override=legal_hold_override,
            auto_purge=auto_purge,
            applies_to=applies_to or ["provenance", "audit"],
            created_at=datetime.now(UTC),
            metadata=metadata or {},
        )

        self._policies[policy.policy_id] = policy

        logger.info(
            "Retention policy created",
            policy_id=policy.policy_id,
            name=name,
            retention_days=retention_days,
            regulations=[r.value for r in regulations],
        )

        return policy

    async def register_record(
        self,
        asset_id: str,
        asset_type: str,
        tenant_id: str,
        policy_id: str,
        acquired_at: datetime | None = None,
    ) -> RetentionRecord:
        """Register a data record under a retention policy.

        Args:
            asset_id: The record/asset identifier to track.
            asset_type: Category label (e.g., "provenance", "audit").
            tenant_id: The owning tenant.
            policy_id: The retention policy to apply.
            acquired_at: When the data was created; defaults to now.

        Returns:
            The created RetentionRecord.

        Raises:
            ValueError: If the policy does not exist.
        """
        policy = self._policies.get(policy_id) or self._built_in_policies.get(policy_id)
        if policy is None:
            raise ValueError(f"Retention policy '{policy_id}' not found")

        resolved_acquired_at = acquired_at or datetime.now(UTC)
        expires_at = resolved_acquired_at + timedelta(days=policy.retention_days)
        now = datetime.now(UTC)

        record = RetentionRecord(
            retention_id=str(uuid.uuid4()),
            asset_id=asset_id,
            asset_type=asset_type,
            policy_id=policy_id,
            tenant_id=tenant_id,
            acquired_at=resolved_acquired_at,
            expires_at=expires_at,
            status=RetentionStatus.ACTIVE,
            legal_hold=False,
            legal_hold_reason=None,
            legal_hold_placed_at=None,
            legal_hold_released_at=None,
            purged_at=None,
            extended_until=None,
            last_reviewed_at=now,
        )

        self._records[asset_id] = record

        logger.info(
            "Retention record registered",
            asset_id=asset_id,
            asset_type=asset_type,
            policy_name=policy.name,
            expires_at=expires_at.isoformat(),
        )

        return record

    async def place_legal_hold(
        self,
        asset_id: str,
        reason: str,
        authorized_by: str,
    ) -> RetentionRecord:
        """Place a legal hold on a record, preventing expiry-based purging.

        A legal hold supersedes any retention expiry and must be explicitly
        released before automated purging can proceed.

        Args:
            asset_id: The asset to place on hold.
            reason: Legal reason for the hold (e.g., litigation reference).
            authorized_by: Who authorized this hold.

        Returns:
            Updated RetentionRecord with legal_hold=True.

        Raises:
            ValueError: If no retention record exists for this asset.
        """
        record = self._records.get(asset_id)
        if record is None:
            raise ValueError(f"No retention record found for asset '{asset_id}'")

        record.legal_hold = True
        record.legal_hold_reason = reason
        record.legal_hold_placed_at = datetime.now(UTC)
        record.status = RetentionStatus.LEGAL_HOLD
        record.legal_hold_released_at = None

        logger.info(
            "Legal hold placed",
            asset_id=asset_id,
            reason=reason,
            authorized_by=authorized_by,
        )

        return record

    async def release_legal_hold(
        self,
        asset_id: str,
        released_by: str,
        release_reason: str,
    ) -> RetentionRecord:
        """Release a legal hold and restore normal retention rules.

        After release, the record status is recalculated based on its
        current expiry date.

        Args:
            asset_id: The asset to release from hold.
            released_by: Who is releasing the hold.
            release_reason: Reason for releasing (e.g., "litigation settled").

        Returns:
            Updated RetentionRecord with legal_hold=False.

        Raises:
            ValueError: If no retention record exists or record is not on hold.
        """
        record = self._records.get(asset_id)
        if record is None:
            raise ValueError(f"No retention record found for asset '{asset_id}'")
        if not record.legal_hold:
            raise ValueError(f"Asset '{asset_id}' is not currently under legal hold")

        record.legal_hold = False
        record.legal_hold_released_at = datetime.now(UTC)
        record.metadata["release_reason"] = release_reason
        record.metadata["released_by"] = released_by

        # Recalculate current status
        record.status = self._compute_status(record)

        logger.info(
            "Legal hold released",
            asset_id=asset_id,
            released_by=released_by,
            new_status=record.status.value,
        )

        return record

    async def extend_retention(
        self,
        asset_id: str,
        extension_days: int,
        reason: str,
        authorized_by: str,
    ) -> RetentionRecord:
        """Extend the retention period for a specific record.

        Extension is additive from the current expires_at, allowing
        incremental extensions without resetting the clock.

        Args:
            asset_id: The asset to extend retention for.
            extension_days: Number of additional days to retain.
            reason: Business or legal reason for the extension.
            authorized_by: Who authorized this extension.

        Returns:
            Updated RetentionRecord with new expires_at.

        Raises:
            ValueError: If no retention record exists.
        """
        record = self._records.get(asset_id)
        if record is None:
            raise ValueError(f"No retention record found for asset '{asset_id}'")

        current_expiry = record.extended_until or record.expires_at
        new_expiry = current_expiry + timedelta(days=extension_days)
        record.extended_until = new_expiry
        record.expires_at = new_expiry
        record.status = self._compute_status(record)
        record.metadata.setdefault("extension_history", []).append(
            {
                "extended_by_days": extension_days,
                "new_expiry": new_expiry.isoformat(),
                "reason": reason,
                "authorized_by": authorized_by,
                "extended_at": datetime.now(UTC).isoformat(),
            }
        )

        logger.info(
            "Retention extended",
            asset_id=asset_id,
            extension_days=extension_days,
            new_expiry=new_expiry.isoformat(),
        )

        return record

    async def detect_expiring_records(
        self,
        tenant_id: str,
        warning_days: int = 30,
    ) -> list[ExpiryNotification]:
        """Detect records that are expiring soon or already expired.

        Args:
            tenant_id: The tenant to check records for.
            warning_days: Days before expiry to begin notification.

        Returns:
            List of ExpiryNotification for records needing attention.
        """
        now = datetime.now(UTC)
        notifications: list[ExpiryNotification] = []

        for record in self._records.values():
            if record.tenant_id != tenant_id:
                continue
            if record.status == RetentionStatus.PURGED:
                continue

            effective_expiry = record.extended_until or record.expires_at
            days_remaining = (effective_expiry - now).days

            if days_remaining <= warning_days:
                policy = self._policies.get(record.policy_id) or self._built_in_policies.get(record.policy_id)
                policy_name = policy.name if policy else record.policy_id

                notifications.append(
                    ExpiryNotification(
                        notification_id=str(uuid.uuid4()),
                        asset_id=record.asset_id,
                        asset_type=record.asset_type,
                        tenant_id=record.tenant_id,
                        expires_at=effective_expiry,
                        days_until_expiry=days_remaining,
                        status=record.status,
                        policy_name=policy_name,
                        legal_hold=record.legal_hold,
                        requires_action=days_remaining <= 0 and not record.legal_hold,
                    )
                )

        notifications.sort(key=lambda n: n.days_until_expiry)

        logger.info(
            "Expiry detection complete",
            tenant_id=tenant_id,
            notifications_generated=len(notifications),
            requires_action=sum(1 for n in notifications if n.requires_action),
        )

        return notifications

    async def schedule_purge(self, asset_id: str, purged_by: str) -> RetentionRecord:
        """Mark a record as purged after data deletion.

        This method should be called after actual data deletion is confirmed.
        It does not delete data — it records that deletion has occurred.

        Args:
            asset_id: The asset that has been purged.
            purged_by: System or user that performed the deletion.

        Returns:
            Updated RetentionRecord with status=PURGED.

        Raises:
            ValueError: If record is under legal hold or not yet expired.
        """
        record = self._records.get(asset_id)
        if record is None:
            raise ValueError(f"No retention record found for asset '{asset_id}'")

        if record.legal_hold:
            raise ValueError(
                f"Cannot purge asset '{asset_id}': active legal hold prevents deletion"
            )

        now = datetime.now(UTC)
        effective_expiry = record.extended_until or record.expires_at

        if now < effective_expiry:
            raise ValueError(
                f"Cannot purge asset '{asset_id}': retention period has not expired "
                f"(expires {effective_expiry.isoformat()})"
            )

        record.status = RetentionStatus.PURGED
        record.purged_at = now
        record.metadata["purged_by"] = purged_by

        logger.info(
            "Record marked as purged",
            asset_id=asset_id,
            purged_by=purged_by,
            retention_id=record.retention_id,
        )

        return record

    async def generate_audit_report(self, tenant_id: str) -> RetentionAuditReport:
        """Generate a comprehensive retention compliance audit report.

        Args:
            tenant_id: The tenant to report on.

        Returns:
            RetentionAuditReport with compliance statistics.
        """
        tenant_records = [r for r in self._records.values() if r.tenant_id == tenant_id]

        status_counts: dict[str, int] = {s.value: 0 for s in RetentionStatus}
        regulation_counts: dict[str, int] = {}
        policy_counts: dict[str, int] = {}

        for record in tenant_records:
            current_status = self._compute_status(record)
            status_counts[current_status.value] = status_counts.get(current_status.value, 0) + 1

            policy = self._policies.get(record.policy_id) or self._built_in_policies.get(record.policy_id)
            if policy:
                policy_counts[policy.name] = policy_counts.get(policy.name, 0) + 1
                for regulation in policy.regulations:
                    regulation_counts[regulation.value] = regulation_counts.get(regulation.value, 0) + 1

        total = len(tenant_records)
        compliant = (
            status_counts.get(RetentionStatus.ACTIVE.value, 0)
            + status_counts.get(RetentionStatus.LEGAL_HOLD.value, 0)
        )
        compliance_score = compliant / max(total, 1)

        return RetentionAuditReport(
            report_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            generated_at=datetime.now(UTC),
            total_records=total,
            active_records=status_counts.get(RetentionStatus.ACTIVE.value, 0),
            expiring_soon_count=status_counts.get(RetentionStatus.EXPIRING_SOON.value, 0),
            expired_count=status_counts.get(RetentionStatus.EXPIRED.value, 0),
            legal_hold_count=status_counts.get(RetentionStatus.LEGAL_HOLD.value, 0),
            purged_count=status_counts.get(RetentionStatus.PURGED.value, 0),
            by_regulation=regulation_counts,
            policy_breakdown=policy_counts,
            compliance_score=round(compliance_score, 4),
        )

    def _compute_status(self, record: RetentionRecord) -> RetentionStatus:
        """Compute the current retention status for a record.

        Args:
            record: The retention record to evaluate.

        Returns:
            Current RetentionStatus based on dates and holds.
        """
        if record.status == RetentionStatus.PURGED:
            return RetentionStatus.PURGED

        if record.legal_hold:
            return RetentionStatus.LEGAL_HOLD

        now = datetime.now(UTC)
        effective_expiry = record.extended_until or record.expires_at

        if now > effective_expiry:
            return RetentionStatus.EXPIRED

        days_remaining = (effective_expiry - now).days
        if days_remaining <= 30:
            return RetentionStatus.EXPIRING_SOON

        return RetentionStatus.ACTIVE


__all__ = [
    "RetentionRegulation",
    "RetentionStatus",
    "RetentionPolicy",
    "RetentionRecord",
    "ExpiryNotification",
    "RetentionAuditReport",
    "RetentionManager",
]
