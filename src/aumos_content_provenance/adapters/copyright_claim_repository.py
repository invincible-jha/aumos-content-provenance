"""In-memory copyright claim repository for development.

In production, this would be backed by a PostgreSQL table (cpv_copyright_claims).
For now, provides a working implementation for integration testing without
requiring an additional database migration.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from aumos_common.observability import get_logger

from aumos_content_provenance.core.interfaces import ICopyrightClaimRepository
from aumos_content_provenance.core.models import (
    CopyrightClaim,
    CopyrightClaimStatus,
)

logger = get_logger(__name__)


class InMemoryCopyrightClaimRepository(ICopyrightClaimRepository):
    """In-memory copyright claim repository for development/testing.

    Stores claim records in an instance-level dict. Not suitable for
    production multi-process deployments — replace with a SQLAlchemy
    backed implementation when the cpv_copyright_claims table is migrated.
    """

    def __init__(self) -> None:
        self._claims: dict[uuid.UUID, CopyrightClaim] = {}

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
        """Create a new copyright claim record.

        Args:
            claim_reference: External case number or claim ID.
            claimant_name: Copyright holder or plaintiff.
            defendant_name: Defendant company/model name.
            content_description: Description of the claimed content.
            content_identifiers: Hashes, URLs, or dataset names.
            status: Initial claim status.
            jurisdiction: Legal jurisdiction.
            filed_at: Filing date.
            source_url: Public court filing URL.
            tags: Classification tags.

        Returns:
            The created CopyrightClaim record.
        """
        claim = CopyrightClaim(
            id=uuid.uuid4(),
            claim_reference=claim_reference,
            claimant_name=claimant_name,
            defendant_name=defendant_name,
            content_description=content_description,
            content_identifiers=content_identifiers,
            status=status,
            jurisdiction=jurisdiction,
            filed_at=filed_at,
            resolved_at=None,
            source_url=source_url,
            tags=tags,
            created_at=datetime.now(UTC),
        )
        self._claims[claim.id] = claim
        logger.info(
            "copyright_claim_created",
            claim_id=str(claim.id),
            claim_reference=claim_reference,
            claimant=claimant_name,
        )
        return claim

    async def search(
        self,
        content_identifiers: list[str],
        tags: list[str] | None,
        status: CopyrightClaimStatus | None,
    ) -> list[CopyrightClaim]:
        """Search copyright claims by content identifier cross-reference.

        Args:
            content_identifiers: Hashes or dataset names to cross-reference.
            tags: Optional tag filter.
            status: Optional status filter.

        Returns:
            List of matching CopyrightClaim records.
        """
        identifier_set = set(content_identifiers)
        results: list[CopyrightClaim] = []

        for claim in self._claims.values():
            if status and claim.status != status:
                continue
            if tags and not any(t in claim.tags for t in tags):
                continue
            if any(ci in identifier_set for ci in claim.content_identifiers):
                results.append(claim)

        return results

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
        all_claims = [
            c for c in self._claims.values()
            if status is None or c.status == status
        ]
        all_claims.sort(key=lambda c: c.created_at, reverse=True)
        start = (page - 1) * page_size
        return all_claims[start: start + page_size]
