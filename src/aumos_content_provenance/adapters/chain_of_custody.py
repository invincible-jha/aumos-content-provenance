"""Chain of custody adapter for aumos-content-provenance.

Tracks ownership, transfers, and access events for content assets.
Produces cryptographically signed custody attestations suitable for
legal proceedings and regulatory audits. Supports shared/multi-party
ownership and gap-free custody chain validation.
"""

import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class CustodyEventType(str, Enum):
    """Type of custody event in the chain."""

    ACQUISITION = "acquisition"        # Initial ownership established
    TRANSFER = "transfer"              # Ownership transferred to new party
    ACCESS = "access"                  # Read-only access event (logged not owner change)
    HOLD_PLACED = "hold_placed"        # Legal or regulatory hold applied
    HOLD_RELEASED = "hold_released"    # Hold lifted
    SHARED = "shared"                  # Shared with additional party
    SURRENDERED = "surrendered"        # Ownership surrendered (no new owner)


@dataclass
class CustodyRecord:
    """A single event in the chain of custody."""

    record_id: str
    asset_id: str
    event_type: CustodyEventType
    owner_id: str                      # Current owner at time of event
    previous_owner_id: str | None      # Previous owner (for transfers)
    purpose: str                       # Business purpose for this event
    authorized_by: str                 # Who authorized this event
    timestamp: datetime
    metadata: dict[str, Any]
    previous_record_id: str | None     # Linked list pointer (None = first event)
    chain_hash: str                    # HMAC-SHA256 commitment over this record + previous hash
    shared_owners: list[str] = field(default_factory=list)   # Co-owners for shared custody


@dataclass
class CustodyChain:
    """Complete chain of custody for an asset."""

    asset_id: str
    current_owner_id: str
    shared_owners: list[str]
    records: list[CustodyRecord]
    is_valid: bool                     # Hash chain integrity check passed
    has_gaps: bool                     # False = continuous chain, True = missing events
    chain_length: int
    first_acquisition_at: datetime | None
    last_event_at: datetime | None


@dataclass
class CustodyAttestation:
    """Signed attestation proving custody state at a point in time."""

    attestation_id: str
    asset_id: str
    attesting_owner_id: str
    custody_state: str                 # JSON summary of current custody
    chain_hash: str                    # Terminal hash of the custody chain
    signature: str                     # HMAC-SHA256 using attestation signing key
    attested_at: datetime
    expires_at: datetime               # Attestations expire (use fresh one for court)
    chain_length: int


@dataclass
class AccessLogEntry:
    """A single access event (non-ownership read access)."""

    log_id: str
    asset_id: str
    accessor_id: str
    purpose: str
    access_granted_by: str
    accessed_at: datetime
    metadata: dict[str, Any]


class ChainOfCustody:
    """Track ownership and transfer history for content assets.

    Implements a cryptographically linked custody chain where each event
    commits to the previous via HMAC-SHA256. Validates chain continuity
    and produces signed attestations for legal use.

    The chain signing key should be injected from the secrets vault
    in production deployments. For development, a random key is generated.
    """

    def __init__(self, signing_key: bytes | None = None) -> None:
        # In production: inject from aumos-secrets-vault
        self._signing_key = signing_key or secrets.token_bytes(32)
        self._chains: dict[str, list[CustodyRecord]] = {}
        self._access_logs: dict[str, list[AccessLogEntry]] = {}

    async def create_custody(
        self,
        asset_id: str,
        owner_id: str,
        purpose: str,
        authorized_by: str,
        metadata: dict[str, Any] | None = None,
    ) -> CustodyRecord:
        """Establish initial custody of an asset (first ownership record).

        This is the root of the custody chain — there must be no prior
        records for this asset_id.

        Args:
            asset_id: The asset being placed under custody management.
            owner_id: The initial owner identifier.
            purpose: Business purpose for acquiring custody.
            authorized_by: Identity that authorized this custody establishment.
            metadata: Additional context (contract reference, jurisdiction, etc.).

        Returns:
            The root CustodyRecord.

        Raises:
            ValueError: If custody already exists for this asset.
        """
        if asset_id in self._chains and self._chains[asset_id]:
            raise ValueError(
                f"Custody chain already exists for asset '{asset_id}'. "
                "Use transfer_custody() to change ownership."
            )

        record_id = str(uuid.uuid4())
        timestamp = datetime.now(UTC)

        chain_hash = self._compute_chain_hash(
            record_id=record_id,
            asset_id=asset_id,
            event_type=CustodyEventType.ACQUISITION,
            owner_id=owner_id,
            timestamp=timestamp,
            previous_hash=None,
        )

        record = CustodyRecord(
            record_id=record_id,
            asset_id=asset_id,
            event_type=CustodyEventType.ACQUISITION,
            owner_id=owner_id,
            previous_owner_id=None,
            purpose=purpose,
            authorized_by=authorized_by,
            timestamp=timestamp,
            metadata=metadata or {},
            previous_record_id=None,
            chain_hash=chain_hash,
            shared_owners=[],
        )

        self._chains[asset_id] = [record]
        self._access_logs.setdefault(asset_id, [])

        logger.info(
            "Custody established",
            asset_id=asset_id,
            owner_id=owner_id,
            record_id=record_id,
        )

        return record

    async def transfer_custody(
        self,
        asset_id: str,
        new_owner_id: str,
        purpose: str,
        authorized_by: str,
        metadata: dict[str, Any] | None = None,
    ) -> CustodyRecord:
        """Transfer custody of an asset to a new owner.

        Appends a transfer event to the chain. The previous owner
        is recorded from the current chain state.

        Args:
            asset_id: The asset being transferred.
            new_owner_id: The new owner identifier.
            purpose: Business reason for the transfer.
            authorized_by: Who authorized this transfer.
            metadata: Additional context (transaction ID, legal refs, etc.).

        Returns:
            The new CustodyRecord with event_type=TRANSFER.

        Raises:
            ValueError: If no custody chain exists for this asset.
        """
        records = self._chains.get(asset_id)
        if not records:
            raise ValueError(
                f"No custody chain found for asset '{asset_id}'. "
                "Call create_custody() first."
            )

        last_record = records[-1]
        current_owner = last_record.owner_id
        record_id = str(uuid.uuid4())
        timestamp = datetime.now(UTC)

        chain_hash = self._compute_chain_hash(
            record_id=record_id,
            asset_id=asset_id,
            event_type=CustodyEventType.TRANSFER,
            owner_id=new_owner_id,
            timestamp=timestamp,
            previous_hash=last_record.chain_hash,
        )

        record = CustodyRecord(
            record_id=record_id,
            asset_id=asset_id,
            event_type=CustodyEventType.TRANSFER,
            owner_id=new_owner_id,
            previous_owner_id=current_owner,
            purpose=purpose,
            authorized_by=authorized_by,
            timestamp=timestamp,
            metadata=metadata or {},
            previous_record_id=last_record.record_id,
            chain_hash=chain_hash,
            shared_owners=last_record.shared_owners.copy(),
        )

        self._chains[asset_id].append(record)

        logger.info(
            "Custody transferred",
            asset_id=asset_id,
            from_owner=current_owner,
            to_owner=new_owner_id,
            record_id=record_id,
        )

        return record

    async def add_shared_custody(
        self,
        asset_id: str,
        shared_owner_id: str,
        purpose: str,
        authorized_by: str,
    ) -> CustodyRecord:
        """Add a co-owner to the current custody record.

        Shared custody means multiple parties simultaneously hold
        oversight responsibility (e.g., joint legal discovery hold).

        Args:
            asset_id: The asset to add shared custody for.
            shared_owner_id: The additional owner to add.
            purpose: Reason for establishing shared custody.
            authorized_by: Who authorized this.

        Returns:
            New CustodyRecord with updated shared_owners list.

        Raises:
            ValueError: If no custody chain exists.
        """
        records = self._chains.get(asset_id)
        if not records:
            raise ValueError(f"No custody chain found for asset '{asset_id}'")

        last_record = records[-1]
        updated_shared = list(last_record.shared_owners)

        if shared_owner_id not in updated_shared:
            updated_shared.append(shared_owner_id)

        record_id = str(uuid.uuid4())
        timestamp = datetime.now(UTC)

        chain_hash = self._compute_chain_hash(
            record_id=record_id,
            asset_id=asset_id,
            event_type=CustodyEventType.SHARED,
            owner_id=last_record.owner_id,
            timestamp=timestamp,
            previous_hash=last_record.chain_hash,
        )

        record = CustodyRecord(
            record_id=record_id,
            asset_id=asset_id,
            event_type=CustodyEventType.SHARED,
            owner_id=last_record.owner_id,
            previous_owner_id=None,
            purpose=purpose,
            authorized_by=authorized_by,
            timestamp=timestamp,
            metadata={"added_shared_owner": shared_owner_id},
            previous_record_id=last_record.record_id,
            chain_hash=chain_hash,
            shared_owners=updated_shared,
        )

        self._chains[asset_id].append(record)

        logger.info(
            "Shared custody added",
            asset_id=asset_id,
            shared_owner_id=shared_owner_id,
            total_shared_owners=len(updated_shared),
        )

        return record

    async def log_access(
        self,
        asset_id: str,
        accessor_id: str,
        purpose: str,
        access_granted_by: str,
        metadata: dict[str, Any] | None = None,
    ) -> AccessLogEntry:
        """Log a read-only access event without changing custody.

        Access events are stored separately from the custody chain
        but are included in full custody reports.

        Args:
            asset_id: The asset being accessed.
            accessor_id: Who accessed the asset.
            purpose: Purpose of access.
            access_granted_by: Who authorized the access.
            metadata: Additional access context.

        Returns:
            The created AccessLogEntry.
        """
        entry = AccessLogEntry(
            log_id=str(uuid.uuid4()),
            asset_id=asset_id,
            accessor_id=accessor_id,
            purpose=purpose,
            access_granted_by=access_granted_by,
            accessed_at=datetime.now(UTC),
            metadata=metadata or {},
        )

        self._access_logs.setdefault(asset_id, []).append(entry)

        logger.info(
            "Access logged",
            asset_id=asset_id,
            accessor_id=accessor_id,
            purpose=purpose,
        )

        return entry

    async def validate_chain(self, asset_id: str) -> CustodyChain:
        """Retrieve and validate the full custody chain for an asset.

        Verifies hash linkage at every step and checks for gaps in the chain.

        Args:
            asset_id: The asset to validate.

        Returns:
            CustodyChain with validation results.
        """
        records = self._chains.get(asset_id, [])

        if not records:
            return CustodyChain(
                asset_id=asset_id,
                current_owner_id="",
                shared_owners=[],
                records=[],
                is_valid=False,
                has_gaps=True,
                chain_length=0,
                first_acquisition_at=None,
                last_event_at=None,
            )

        is_valid = True
        has_gaps = False
        previous_hash: str | None = None
        previous_record_id: str | None = None

        for index, record in enumerate(records):
            # Verify chain hash
            expected_hash = self._compute_chain_hash(
                record_id=record.record_id,
                asset_id=record.asset_id,
                event_type=record.event_type,
                owner_id=record.owner_id,
                timestamp=record.timestamp,
                previous_hash=previous_hash,
            )

            if expected_hash != record.chain_hash:
                logger.warning(
                    "Custody chain hash mismatch",
                    asset_id=asset_id,
                    record_index=index,
                    record_id=record.record_id,
                )
                is_valid = False

            # Check for pointer gaps
            if index > 0 and record.previous_record_id != previous_record_id:
                logger.warning(
                    "Custody chain gap detected",
                    asset_id=asset_id,
                    record_index=index,
                    expected_previous=previous_record_id,
                    found_previous=record.previous_record_id,
                )
                has_gaps = True

            previous_hash = record.chain_hash
            previous_record_id = record.record_id

        last_record = records[-1]
        first_record = records[0]

        return CustodyChain(
            asset_id=asset_id,
            current_owner_id=last_record.owner_id,
            shared_owners=last_record.shared_owners,
            records=records,
            is_valid=is_valid,
            has_gaps=has_gaps,
            chain_length=len(records),
            first_acquisition_at=first_record.timestamp,
            last_event_at=last_record.timestamp,
        )

    async def generate_attestation(
        self,
        asset_id: str,
        attesting_owner_id: str,
        validity_hours: int = 24,
    ) -> CustodyAttestation:
        """Generate a signed custody attestation for legal use.

        Produces a tamper-evident attestation document that certifies
        the current custody state at the time of generation. Attestations
        should be regenerated for each legal submission.

        Args:
            asset_id: The asset to attest custody for.
            attesting_owner_id: The owner generating the attestation.
            validity_hours: How long the attestation is valid (default 24h).

        Returns:
            CustodyAttestation with HMAC signature.

        Raises:
            ValueError: If no custody chain exists or chain is invalid.
        """
        chain = await self.validate_chain(asset_id)

        if not chain.records:
            raise ValueError(f"No custody records found for asset '{asset_id}'")

        if not chain.is_valid:
            raise ValueError(
                f"Cannot attest custody for asset '{asset_id}': "
                "chain integrity validation failed"
            )

        attested_at = datetime.now(UTC)
        from datetime import timedelta
        expires_at = datetime.fromtimestamp(
            attested_at.timestamp() + validity_hours * 3600, tz=UTC
        )

        custody_state = json.dumps(
            {
                "asset_id": asset_id,
                "current_owner": chain.current_owner_id,
                "shared_owners": chain.shared_owners,
                "chain_length": chain.chain_length,
                "terminal_hash": chain.records[-1].chain_hash,
                "first_acquisition_at": chain.first_acquisition_at.isoformat() if chain.first_acquisition_at else None,
                "last_event_at": chain.last_event_at.isoformat() if chain.last_event_at else None,
                "attested_at": attested_at.isoformat(),
            },
            sort_keys=True,
        )

        signature = hmac.new(
            self._signing_key,
            custody_state.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        attestation = CustodyAttestation(
            attestation_id=str(uuid.uuid4()),
            asset_id=asset_id,
            attesting_owner_id=attesting_owner_id,
            custody_state=custody_state,
            chain_hash=chain.records[-1].chain_hash,
            signature=signature,
            attested_at=attested_at,
            expires_at=expires_at,
            chain_length=chain.chain_length,
        )

        logger.info(
            "Custody attestation generated",
            asset_id=asset_id,
            attestation_id=attestation.attestation_id,
            chain_length=chain.chain_length,
            expires_at=expires_at.isoformat(),
        )

        return attestation

    async def get_custody_timeline(self, asset_id: str) -> dict[str, Any]:
        """Export custody timeline data for visualization.

        Produces a chronological event list with ownership annotations
        suitable for timeline rendering tools.

        Args:
            asset_id: The asset to export timeline for.

        Returns:
            Dict with timeline events and summary statistics.
        """
        records = self._chains.get(asset_id, [])
        access_logs = self._access_logs.get(asset_id, [])

        timeline_events: list[dict[str, Any]] = []

        for record in records:
            timeline_events.append(
                {
                    "timestamp": record.timestamp.isoformat(),
                    "event_id": record.record_id,
                    "event_type": record.event_type.value,
                    "owner_id": record.owner_id,
                    "previous_owner_id": record.previous_owner_id,
                    "shared_owners": record.shared_owners,
                    "purpose": record.purpose,
                    "authorized_by": record.authorized_by,
                    "chain_hash_prefix": record.chain_hash[:16] + "...",
                }
            )

        for log_entry in access_logs:
            timeline_events.append(
                {
                    "timestamp": log_entry.accessed_at.isoformat(),
                    "event_id": log_entry.log_id,
                    "event_type": "access",
                    "accessor_id": log_entry.accessor_id,
                    "purpose": log_entry.purpose,
                    "access_granted_by": log_entry.access_granted_by,
                }
            )

        timeline_events.sort(key=lambda e: e["timestamp"])

        return {
            "asset_id": asset_id,
            "total_events": len(timeline_events),
            "custody_events": len(records),
            "access_events": len(access_logs),
            "timeline": timeline_events,
        }

    def _compute_chain_hash(
        self,
        record_id: str,
        asset_id: str,
        event_type: CustodyEventType,
        owner_id: str,
        timestamp: datetime,
        previous_hash: str | None,
    ) -> str:
        """Compute HMAC-SHA256 chain hash for a custody record.

        Commits to all identity fields of the record plus the previous
        hash to form a tamper-evident chain.

        Args:
            record_id: Unique ID of this record.
            asset_id: Asset being tracked.
            event_type: Type of custody event.
            owner_id: Owner at time of this event.
            timestamp: Event timestamp.
            previous_hash: Chain hash of the prior record, or None for root.

        Returns:
            HMAC-SHA256 hex digest.
        """
        payload = json.dumps(
            {
                "record_id": record_id,
                "asset_id": asset_id,
                "event_type": event_type.value,
                "owner_id": owner_id,
                "timestamp": timestamp.isoformat(),
                "previous_hash": previous_hash or "GENESIS",
            },
            sort_keys=True,
        )

        return hmac.new(
            self._signing_key,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


__all__ = [
    "CustodyEventType",
    "CustodyRecord",
    "CustodyChain",
    "CustodyAttestation",
    "AccessLogEntry",
    "ChainOfCustody",
]
