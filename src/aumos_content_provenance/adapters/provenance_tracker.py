"""Provenance tracker adapter for aumos-content-provenance.

Tracks the full data source and transformation chain for content assets.
Records origin metadata, transformation steps, and provides chain integrity
verification via hash-linked event lists. Suitable for reconstructing
complete provenance in legal proceedings.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


@dataclass
class ProvenanceSource:
    """A registered source asset with origin metadata."""

    asset_id: str
    origin_url: str | None
    origin_timestamp: datetime
    content_hash: str                   # SHA-256 of raw source bytes
    media_type: str
    actor: str                          # Who/what registered this source
    metadata: dict[str, Any]
    registered_at: datetime
    source_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class TransformationStep:
    """A single transformation applied to an asset."""

    step_id: str
    asset_id: str
    operation: str                      # e.g., "crop", "resize", "translate", "summarize"
    parameters: dict[str, Any]
    actor: str                          # System or user that performed the operation
    input_hash: str                     # SHA-256 of input bytes before transformation
    output_hash: str                    # SHA-256 of output bytes after transformation
    previous_step_id: str | None       # Linked list pointer
    chain_hash: str                    # SHA-256 of (previous_chain_hash + step fields)
    performed_at: datetime


@dataclass
class ProvenanceChain:
    """Full provenance chain for a single asset."""

    asset_id: str
    source: ProvenanceSource
    steps: list[TransformationStep]
    chain_valid: bool
    chain_length: int
    terminal_hash: str                  # Hash of the last link in the chain


@dataclass
class TamperEvidence:
    """Result of chain integrity verification."""

    asset_id: str
    is_valid: bool
    broken_at_step: int | None         # 0-indexed step index where chain breaks
    broken_step_id: str | None
    reason: str
    verified_at: datetime


class ProvenanceTracker:
    """Track data source and transformation chains for content assets.

    Maintains an append-only linked-list of provenance events where each
    step records its hash commitment over the previous step, producing
    a tamper-evident chain suitable for legal discovery.

    Storage is in-memory in this adapter; production deployments wire
    this to the repository layer via the IProvenanceTrackerRepository
    Protocol defined in interfaces.py.
    """

    def __init__(self) -> None:
        # In production these are repository calls; here we use in-process dicts
        # to enable the full domain logic without a database dependency.
        self._sources: dict[str, ProvenanceSource] = {}
        self._steps: dict[str, list[TransformationStep]] = {}  # asset_id -> steps

    async def register_source(
        self,
        asset_id: str,
        media_type: str,
        actor: str,
        content_bytes: bytes,
        origin_url: str | None = None,
        origin_timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceSource:
        """Register a source asset and record its origin metadata.

        Computes a SHA-256 content hash and stores the source record as
        the root of the provenance chain for this asset.

        Args:
            asset_id: Stable identifier for this asset.
            media_type: MIME type of the content.
            actor: Identifier for who/what is registering the source.
            content_bytes: Raw bytes of the source content.
            origin_url: URL where the content was obtained, if known.
            origin_timestamp: When the content was originally created/obtained.
            metadata: Additional origin metadata (author, dataset name, etc.).

        Returns:
            The created ProvenanceSource record.
        """
        content_hash = hashlib.sha256(content_bytes).hexdigest()
        resolved_timestamp = origin_timestamp or datetime.now(UTC)

        source = ProvenanceSource(
            asset_id=asset_id,
            origin_url=origin_url,
            origin_timestamp=resolved_timestamp,
            content_hash=content_hash,
            media_type=media_type,
            actor=actor,
            metadata=metadata or {},
            registered_at=datetime.now(UTC),
        )

        self._sources[asset_id] = source
        self._steps.setdefault(asset_id, [])

        logger.info(
            "Source asset registered",
            asset_id=asset_id,
            content_hash=content_hash[:16],
            actor=actor,
            has_origin_url=origin_url is not None,
        )

        return source

    async def record_transformation(
        self,
        asset_id: str,
        operation: str,
        actor: str,
        input_bytes: bytes,
        output_bytes: bytes,
        parameters: dict[str, Any] | None = None,
    ) -> TransformationStep:
        """Record a transformation step in the asset's provenance chain.

        Computes input and output hashes, then builds a chain hash that
        commits to the entire history up to this point.

        Args:
            asset_id: The asset being transformed.
            operation: Name of the transformation (e.g., "crop", "translate").
            actor: System or user performing the transformation.
            input_bytes: Raw bytes before the transformation.
            output_bytes: Raw bytes after the transformation.
            parameters: Transformation parameters (model version, crop coords, etc.).

        Returns:
            The created TransformationStep.

        Raises:
            ValueError: If no source has been registered for this asset.
        """
        if asset_id not in self._sources:
            raise ValueError(
                f"No source registered for asset '{asset_id}'. "
                "Call register_source() before recording transformations."
            )

        input_hash = hashlib.sha256(input_bytes).hexdigest()
        output_hash = hashlib.sha256(output_bytes).hexdigest()

        existing_steps = self._steps.get(asset_id, [])
        previous_step_id: str | None = None
        previous_chain_hash: str = self._sources[asset_id].content_hash

        if existing_steps:
            last_step = existing_steps[-1]
            previous_step_id = last_step.step_id
            previous_chain_hash = last_step.chain_hash

        step_id = str(uuid.uuid4())
        performed_at = datetime.now(UTC)

        # Chain hash commits to: previous hash + step data
        chain_input = json.dumps(
            {
                "previous_chain_hash": previous_chain_hash,
                "step_id": step_id,
                "asset_id": asset_id,
                "operation": operation,
                "actor": actor,
                "input_hash": input_hash,
                "output_hash": output_hash,
                "performed_at": performed_at.isoformat(),
                "parameters": parameters or {},
            },
            sort_keys=True,
        )
        chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()

        step = TransformationStep(
            step_id=step_id,
            asset_id=asset_id,
            operation=operation,
            parameters=parameters or {},
            actor=actor,
            input_hash=input_hash,
            output_hash=output_hash,
            previous_step_id=previous_step_id,
            chain_hash=chain_hash,
            performed_at=performed_at,
        )

        self._steps[asset_id].append(step)

        logger.info(
            "Transformation step recorded",
            asset_id=asset_id,
            operation=operation,
            step_id=step_id,
            chain_depth=len(self._steps[asset_id]),
        )

        return step

    async def get_provenance_chain(self, asset_id: str) -> ProvenanceChain:
        """Retrieve and verify the full provenance chain for an asset.

        Reconstructs the chain and validates hash linkage at every step.

        Args:
            asset_id: The asset to retrieve the chain for.

        Returns:
            ProvenanceChain with validation result and all steps.

        Raises:
            ValueError: If no source has been registered for this asset.
        """
        if asset_id not in self._sources:
            raise ValueError(f"No provenance data found for asset '{asset_id}'")

        source = self._sources[asset_id]
        steps = self._steps.get(asset_id, [])
        evidence = await self.verify_chain_integrity(asset_id)

        terminal_hash = steps[-1].chain_hash if steps else source.content_hash

        return ProvenanceChain(
            asset_id=asset_id,
            source=source,
            steps=steps,
            chain_valid=evidence.is_valid,
            chain_length=len(steps),
            terminal_hash=terminal_hash,
        )

    async def verify_chain_integrity(self, asset_id: str) -> TamperEvidence:
        """Verify hash chain integrity for an asset's provenance chain.

        Re-derives each chain hash from scratch and compares to the stored
        value. Any mismatch indicates tampering or data corruption.

        Args:
            asset_id: The asset to verify.

        Returns:
            TamperEvidence with verification result and, if invalid,
            the index and ID of the broken step.
        """
        if asset_id not in self._sources:
            return TamperEvidence(
                asset_id=asset_id,
                is_valid=False,
                broken_at_step=None,
                broken_step_id=None,
                reason="No source registered for this asset",
                verified_at=datetime.now(UTC),
            )

        source = self._sources[asset_id]
        steps = self._steps.get(asset_id, [])

        if not steps:
            return TamperEvidence(
                asset_id=asset_id,
                is_valid=True,
                broken_at_step=None,
                broken_step_id=None,
                reason="Source-only chain — no transformation steps (valid)",
                verified_at=datetime.now(UTC),
            )

        current_chain_hash = source.content_hash

        for index, step in enumerate(steps):
            chain_input = json.dumps(
                {
                    "previous_chain_hash": current_chain_hash,
                    "step_id": step.step_id,
                    "asset_id": step.asset_id,
                    "operation": step.operation,
                    "actor": step.actor,
                    "input_hash": step.input_hash,
                    "output_hash": step.output_hash,
                    "performed_at": step.performed_at.isoformat(),
                    "parameters": step.parameters,
                },
                sort_keys=True,
            )
            expected_hash = hashlib.sha256(chain_input.encode()).hexdigest()

            if expected_hash != step.chain_hash:
                logger.warning(
                    "Chain integrity violation detected",
                    asset_id=asset_id,
                    broken_at_step=index,
                    step_id=step.step_id,
                    expected_hash=expected_hash[:16],
                    stored_hash=step.chain_hash[:16],
                )
                return TamperEvidence(
                    asset_id=asset_id,
                    is_valid=False,
                    broken_at_step=index,
                    broken_step_id=step.step_id,
                    reason=(
                        f"Hash mismatch at step {index} (id={step.step_id}): "
                        f"expected {expected_hash[:16]}... got {step.chain_hash[:16]}..."
                    ),
                    verified_at=datetime.now(UTC),
                )

            current_chain_hash = step.chain_hash

        return TamperEvidence(
            asset_id=asset_id,
            is_valid=True,
            broken_at_step=None,
            broken_step_id=None,
            reason=f"All {len(steps)} steps verified — chain intact",
            verified_at=datetime.now(UTC),
        )

    async def merge_provenance_chains(
        self,
        primary_asset_id: str,
        contributing_asset_ids: list[str],
        output_asset_id: str,
        merge_operation: str,
        actor: str,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceSource:
        """Record a merge of multiple asset provenance chains into a new asset.

        Used when an output is derived from multiple source assets (e.g., a
        dataset created by combining multiple sources). The merged asset's
        source record references all contributing chains.

        Args:
            primary_asset_id: The primary/dominant source asset.
            contributing_asset_ids: Additional assets that contributed.
            output_asset_id: The new asset produced by the merge.
            merge_operation: Description of the merge (e.g., "dataset_union").
            actor: Who performed the merge.
            metadata: Additional merge metadata.

        Returns:
            ProvenanceSource for the merged output asset.

        Raises:
            ValueError: If primary or any contributing asset is not registered.
        """
        missing = [
            aid
            for aid in [primary_asset_id, *contributing_asset_ids]
            if aid not in self._sources
        ]
        if missing:
            raise ValueError(
                f"The following assets are not registered: {missing}. "
                "Register all source assets before merging."
            )

        contributing_hashes = {
            aid: self._sources[aid].content_hash
            for aid in [primary_asset_id, *contributing_asset_ids]
        }

        combined_hash_input = json.dumps(contributing_hashes, sort_keys=True)
        combined_hash = hashlib.sha256(combined_hash_input.encode()).hexdigest()

        merge_metadata: dict[str, Any] = {
            "merge_operation": merge_operation,
            "primary_asset_id": primary_asset_id,
            "contributing_asset_ids": contributing_asset_ids,
            "contributing_hashes": contributing_hashes,
            **(metadata or {}),
        }

        merged_source = ProvenanceSource(
            asset_id=output_asset_id,
            origin_url=None,
            origin_timestamp=datetime.now(UTC),
            content_hash=combined_hash,
            media_type="application/octet-stream",
            actor=actor,
            metadata=merge_metadata,
            registered_at=datetime.now(UTC),
        )

        self._sources[output_asset_id] = merged_source
        self._steps.setdefault(output_asset_id, [])

        logger.info(
            "Provenance chains merged",
            output_asset_id=output_asset_id,
            contributing_count=len(contributing_asset_ids) + 1,
            combined_hash=combined_hash[:16],
        )

        return merged_source

    async def export_chain_visualization(self, asset_id: str) -> dict[str, Any]:
        """Export provenance chain data for visualization (e.g., DAG rendering).

        Produces a nodes-and-edges representation suitable for graph
        visualization tools (D3.js, Mermaid, Graphviz).

        Args:
            asset_id: The asset to export visualization data for.

        Returns:
            Dict with "nodes" and "edges" lists for graph rendering.

        Raises:
            ValueError: If no source has been registered for this asset.
        """
        if asset_id not in self._sources:
            raise ValueError(f"No provenance data found for asset '{asset_id}'")

        source = self._sources[asset_id]
        steps = self._steps.get(asset_id, [])

        nodes: list[dict[str, Any]] = [
            {
                "id": source.source_id,
                "type": "source",
                "label": f"Source: {asset_id}",
                "asset_id": asset_id,
                "content_hash": source.content_hash[:16] + "...",
                "actor": source.actor,
                "timestamp": source.registered_at.isoformat(),
                "metadata": source.metadata,
            }
        ]

        edges: list[dict[str, Any]] = []
        previous_node_id = source.source_id

        for step in steps:
            node_id = step.step_id
            nodes.append(
                {
                    "id": node_id,
                    "type": "transformation",
                    "label": step.operation,
                    "asset_id": step.asset_id,
                    "operation": step.operation,
                    "actor": step.actor,
                    "input_hash": step.input_hash[:16] + "...",
                    "output_hash": step.output_hash[:16] + "...",
                    "timestamp": step.performed_at.isoformat(),
                    "parameters": step.parameters,
                }
            )
            edges.append(
                {
                    "source": previous_node_id,
                    "target": node_id,
                    "label": step.operation,
                    "chain_hash": step.chain_hash[:16] + "...",
                }
            )
            previous_node_id = node_id

        return {
            "asset_id": asset_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
        }


__all__ = [
    "ProvenanceSource",
    "TransformationStep",
    "ProvenanceChain",
    "TamperEvidence",
    "ProvenanceTracker",
]
