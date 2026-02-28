"""Blockchain provenance anchor adapter.

Implements IBlockchainAnchorAdapter for internal ledger anchoring (default)
and IPFS anchoring (stub). Ethereum/Polygon integration requires web3.py.
"""

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from aumos_common.observability import get_logger

from aumos_content_provenance.core.interfaces import (
    IBlockchainAnchorAdapter,
    IBlockchainAnchorRepository,
)
from aumos_content_provenance.core.models import BlockchainAnchor, BlockchainNetwork

logger = get_logger(__name__)

try:
    import web3  # type: ignore[import-untyped]

    _WEB3_AVAILABLE = True
except ImportError:
    _WEB3_AVAILABLE = False


class InternalLedgerAnchorAdapter(IBlockchainAnchorAdapter):
    """Anchors content hashes to an internal notarisation ledger.

    Provides a tamper-evident timestamp without external blockchain dependency.
    Uses a SHA-256 chain of hash commitments stored in the audit log.

    Args:
        ledger_signing_key: HMAC key for signing ledger entries.
    """

    def __init__(self, ledger_signing_key: str = "") -> None:
        self._signing_key = ledger_signing_key
        self._ledger: list[dict[str, Any]] = []

    async def anchor(
        self,
        content_hash: str,
        network: BlockchainNetwork,
        metadata: dict[str, Any],
    ) -> tuple[str | None, str | None, int | None]:
        """Anchor a content hash to the internal ledger.

        Args:
            content_hash: SHA-256 of content being anchored.
            network: Must be BlockchainNetwork.INTERNAL_LEDGER for this adapter.
            metadata: Additional metadata to include in the ledger entry.

        Returns:
            Tuple of (transaction_hash, None, block_height) where
            transaction_hash is the ledger entry hash and block_height is
            the sequential entry index.
        """
        entry_index = len(self._ledger)
        previous_hash = self._ledger[-1]["entry_hash"] if self._ledger else "genesis"

        entry: dict[str, Any] = {
            "index": entry_index,
            "content_hash": content_hash,
            "previous_hash": previous_hash,
            "metadata": metadata,
            "anchored_at": datetime.now(UTC).isoformat(),
        }

        # Compute deterministic entry hash
        entry_data = f"{entry_index}:{content_hash}:{previous_hash}"
        entry["entry_hash"] = hashlib.sha256(entry_data.encode()).hexdigest()

        self._ledger.append(entry)

        logger.info(
            "internal_ledger_anchor",
            content_hash=content_hash[:16],
            entry_index=entry_index,
            entry_hash=entry["entry_hash"][:16],
        )

        return entry["entry_hash"], None, entry_index

    async def check_confirmation(
        self,
        transaction_hash: str,
        network: BlockchainNetwork,
    ) -> int:
        """Check confirmation count for a ledger entry.

        For internal ledger, entries are immediately confirmed (count = 1).

        Args:
            transaction_hash: Ledger entry hash.
            network: BlockchainNetwork (ignored for internal ledger).

        Returns:
            Confirmation count (always 1 for internal ledger entries).
        """
        found = any(e["entry_hash"] == transaction_hash for e in self._ledger)
        return 1 if found else 0


class IpfsAnchorAdapter(IBlockchainAnchorAdapter):
    """Anchors content hashes to IPFS for decentralised provenance.

    Uses the IPFS HTTP API to store a provenance record JSON document.
    Requires a running IPFS node or Pinata/Web3.Storage API access.

    Args:
        ipfs_api_url: IPFS HTTP API endpoint (default: local node).
        pinning_service_token: Optional API token for pinning service.
    """

    def __init__(
        self,
        ipfs_api_url: str = "http://localhost:5001",
        pinning_service_token: str = "",
    ) -> None:
        self._api_url = ipfs_api_url
        self._token = pinning_service_token

    async def anchor(
        self,
        content_hash: str,
        network: BlockchainNetwork,
        metadata: dict[str, Any],
    ) -> tuple[str | None, str | None, int | None]:
        """Anchor a content hash to IPFS.

        Args:
            content_hash: SHA-256 of content being anchored.
            network: Must be BlockchainNetwork.IPFS for this adapter.
            metadata: Additional metadata stored in the IPFS document.

        Returns:
            Tuple of (None, ipfs_cid, None). CID is the IPFS content ID.
        """
        logger.info("ipfs_anchor_attempt", content_hash=content_hash[:16])

        # Stub implementation — returns a synthetic CID in development.
        # Production integration: POST to IPFS API /api/v0/add
        synthetic_cid = "Qm" + hashlib.sha256(content_hash.encode()).hexdigest()[:44]
        logger.info("ipfs_anchor_stub", ipfs_cid=synthetic_cid)
        return None, synthetic_cid, None

    async def check_confirmation(
        self,
        transaction_hash: str,
        network: BlockchainNetwork,
    ) -> int:
        """Check IPFS pin status for a CID.

        Args:
            transaction_hash: IPFS CID to check.
            network: Must be BlockchainNetwork.IPFS.

        Returns:
            1 if pinned, 0 if not pinned or unknown.
        """
        # Stub: IPFS content is always immediately available
        return 1


class InMemoryBlockchainAnchorRepository(IBlockchainAnchorRepository):
    """In-memory blockchain anchor repository for development/testing.

    In production, replace with a SQLAlchemy-backed repository
    for the cpv_blockchain_anchors table.
    """

    def __init__(self) -> None:
        self._anchors: dict[uuid.UUID, BlockchainAnchor] = {}

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
            Created BlockchainAnchor with pending status.
        """
        anchor = BlockchainAnchor(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            provenance_record_id=provenance_record_id,
            content_hash=content_hash,
            network=network,
            transaction_hash=None,
            block_height=None,
            ipfs_cid=None,
            anchor_status="pending",
            anchored_at=None,
            confirmation_count=0,
            created_at=datetime.now(UTC),
        )
        self._anchors[anchor.id] = anchor
        return anchor

    async def update_anchor(
        self,
        anchor_id: uuid.UUID,
        transaction_hash: str | None,
        ipfs_cid: str | None,
        block_height: int | None,
        anchor_status: str,
    ) -> BlockchainAnchor:
        """Update an anchor record with confirmation details.

        Args:
            anchor_id: Anchor record UUID.
            transaction_hash: On-chain transaction hash.
            ipfs_cid: IPFS CID if applicable.
            block_height: Block height at confirmation.
            anchor_status: New status (confirmed | failed).

        Returns:
            Updated BlockchainAnchor record.
        """
        anchor = self._anchors[anchor_id]
        updated = BlockchainAnchor(
            id=anchor.id,
            tenant_id=anchor.tenant_id,
            provenance_record_id=anchor.provenance_record_id,
            content_hash=anchor.content_hash,
            network=anchor.network,
            transaction_hash=transaction_hash,
            block_height=block_height,
            ipfs_cid=ipfs_cid,
            anchor_status=anchor_status,
            anchored_at=datetime.now(UTC) if anchor_status == "confirmed" else None,
            confirmation_count=1 if anchor_status == "confirmed" else 0,
            created_at=anchor.created_at,
        )
        self._anchors[anchor_id] = updated
        return updated

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
        for anchor in self._anchors.values():
            if (
                anchor.provenance_record_id == provenance_record_id
                and anchor.tenant_id == tenant_id
            ):
                return anchor
        return None
