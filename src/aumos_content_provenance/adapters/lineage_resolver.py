"""Lineage resolver adapter for aumos-content-provenance.

Resolves training data lineage graphs for AI models and datasets.
Tracks dataset-to-model relationships, contribution fractions, and
derivative works. Supports graph traversal, impact analysis, and
export in standard graph serialization formats (JSON-LD, RDF Turtle).
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from aumos_common.observability import get_logger

from aumos_content_provenance.core.models import LineageEntry, LineageNodeType

logger = get_logger(__name__)


class LineageRelationship(str, Enum):
    """Standard relationship types between lineage nodes."""

    TRAINED_ON = "trained_on"
    FINE_TUNED_ON = "fine_tuned_on"
    GENERATED_BY = "generated_by"
    DERIVED_FROM = "derived_from"
    EVALUATED_ON = "evaluated_on"
    CONTRIBUTED_TO = "contributed_to"
    MERGED_FROM = "merged_from"


@dataclass
class LineageNode:
    """A node in the training data lineage graph."""

    node_id: str
    node_type: LineageNodeType
    label: str
    tenant_id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    registered_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class LineageEdge:
    """A directed edge in the lineage graph."""

    edge_id: str
    parent_node_id: str
    child_node_id: str
    relationship: LineageRelationship
    contribution_fraction: float       # 0.0–1.0; fraction of child derived from parent
    tenant_id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class LineageGraphResult:
    """A subgraph of the lineage graph centered on a query node."""

    root_node_id: str
    direction: str                     # "upstream" | "downstream" | "both"
    nodes: list[LineageNode]
    edges: list[LineageEdge]
    depth_reached: int
    has_cycles: bool


@dataclass
class ImpactAnalysis:
    """Result of an upstream source change impact analysis."""

    source_node_id: str
    affected_node_ids: list[str]
    affected_count: int
    affected_by_type: dict[str, int]   # NodeType -> count
    max_depth_affected: int
    analysis_performed_at: datetime


@dataclass
class DerivativeWorkResult:
    """Result of derivative work detection for a content item."""

    query_node_id: str
    is_derivative: bool
    direct_parents: list[str]
    full_ancestor_chain: list[str]
    contributing_sources: list[dict[str, Any]]  # {node_id, node_type, contribution_fraction}
    detection_confidence: float


class LineageResolver:
    """Resolve training data lineage graphs for AI models and datasets.

    Maintains an in-memory directed graph of lineage relationships and
    provides traversal, impact analysis, and standard format export.

    The graph supports:
    - Dataset -> Model training relationships
    - Model -> Fine-tuned model refinement chains
    - Model -> Output generation attribution
    - Dataset -> Derived dataset transformation tracking
    - Cycle detection (prevents infinite traversal)

    In production, this is backed by a graph database (Neo4j) or a
    recursive CTE query in Postgres via the ILineageRepository interface.
    """

    def __init__(self, max_traversal_depth: int = 15) -> None:
        self._nodes: dict[str, LineageNode] = {}
        self._edges: list[LineageEdge] = []
        self._max_depth = max_traversal_depth

    async def register_node(
        self,
        node_id: str,
        node_type: LineageNodeType,
        label: str,
        tenant_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> LineageNode:
        """Register a node in the lineage graph (dataset, model, output, etc.).

        Args:
            node_id: Stable identifier for the node.
            node_type: Classification of the node.
            label: Human-readable display label.
            tenant_id: Owning tenant.
            metadata: Additional node properties (version, size, format, etc.).

        Returns:
            The registered LineageNode.
        """
        node = LineageNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            tenant_id=tenant_id,
            metadata=metadata or {},
        )

        self._nodes[node_id] = node

        logger.info(
            "Lineage node registered",
            node_id=node_id,
            node_type=node_type.value,
            label=label,
        )

        return node

    async def record_contribution(
        self,
        parent_node_id: str,
        child_node_id: str,
        relationship: LineageRelationship,
        tenant_id: str,
        contribution_fraction: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> LineageEdge:
        """Record a lineage edge (parent contributed to child).

        Args:
            parent_node_id: The source/upstream node.
            child_node_id: The derived/downstream node.
            relationship: Type of relationship between nodes.
            tenant_id: Owning tenant.
            contribution_fraction: Fraction of child content from this parent.
            metadata: Edge metadata (training config, data split, etc.).

        Returns:
            The created LineageEdge.

        Raises:
            ValueError: If contribution_fraction is outside [0.0, 1.0].
        """
        if not 0.0 <= contribution_fraction <= 1.0:
            raise ValueError(
                f"contribution_fraction must be between 0.0 and 1.0, got {contribution_fraction}"
            )

        edge = LineageEdge(
            edge_id=str(uuid.uuid4()),
            parent_node_id=parent_node_id,
            child_node_id=child_node_id,
            relationship=relationship,
            contribution_fraction=contribution_fraction,
            tenant_id=tenant_id,
            metadata=metadata or {},
        )

        self._edges.append(edge)

        logger.info(
            "Lineage edge recorded",
            parent=parent_node_id,
            child=child_node_id,
            relationship=relationship.value,
            contribution=contribution_fraction,
        )

        return edge

    async def get_upstream_graph(
        self,
        node_id: str,
        tenant_id: str,
        max_depth: int | None = None,
    ) -> LineageGraphResult:
        """Traverse the lineage graph upstream from a node (ancestors).

        Walks from the given node toward its original data sources,
        collecting all ancestor nodes and edges up to max_depth.

        Args:
            node_id: Starting node (e.g., a model or output).
            tenant_id: The owning tenant for access control.
            max_depth: Maximum traversal depth. Uses instance default if None.

        Returns:
            LineageGraphResult with all upstream nodes and edges.
        """
        resolved_depth = min(max_depth or self._max_depth, self._max_depth)
        visited_nodes: set[str] = set()
        visited_edges: set[str] = set()
        result_nodes: list[LineageNode] = []
        result_edges: list[LineageEdge] = []
        has_cycles = False
        max_depth_reached = 0

        def traverse_upstream(current_id: str, depth: int) -> None:
            nonlocal has_cycles, max_depth_reached

            if depth > resolved_depth:
                return
            if current_id in visited_nodes:
                has_cycles = True
                return

            visited_nodes.add(current_id)
            max_depth_reached = max(max_depth_reached, depth)

            if current_id in self._nodes:
                node = self._nodes[current_id]
                if node.tenant_id == tenant_id and node not in result_nodes:
                    result_nodes.append(node)

            parent_edges = [
                edge for edge in self._edges
                if edge.child_node_id == current_id and edge.tenant_id == tenant_id
                and edge.edge_id not in visited_edges
            ]

            for edge in parent_edges:
                visited_edges.add(edge.edge_id)
                result_edges.append(edge)
                traverse_upstream(edge.parent_node_id, depth + 1)

        traverse_upstream(node_id, 0)

        return LineageGraphResult(
            root_node_id=node_id,
            direction="upstream",
            nodes=result_nodes,
            edges=result_edges,
            depth_reached=max_depth_reached,
            has_cycles=has_cycles,
        )

    async def get_downstream_graph(
        self,
        node_id: str,
        tenant_id: str,
        max_depth: int | None = None,
    ) -> LineageGraphResult:
        """Traverse the lineage graph downstream from a node (descendants).

        Walks from the given node toward its derived artifacts, useful for
        impact analysis when a source dataset changes or has a license issue.

        Args:
            node_id: Starting node (e.g., a source dataset).
            tenant_id: The owning tenant.
            max_depth: Maximum traversal depth.

        Returns:
            LineageGraphResult with all downstream nodes and edges.
        """
        resolved_depth = min(max_depth or self._max_depth, self._max_depth)
        visited_nodes: set[str] = set()
        visited_edges: set[str] = set()
        result_nodes: list[LineageNode] = []
        result_edges: list[LineageEdge] = []
        has_cycles = False
        max_depth_reached = 0

        def traverse_downstream(current_id: str, depth: int) -> None:
            nonlocal has_cycles, max_depth_reached

            if depth > resolved_depth:
                return
            if current_id in visited_nodes:
                has_cycles = True
                return

            visited_nodes.add(current_id)
            max_depth_reached = max(max_depth_reached, depth)

            if current_id in self._nodes:
                node = self._nodes[current_id]
                if node.tenant_id == tenant_id and node not in result_nodes:
                    result_nodes.append(node)

            child_edges = [
                edge for edge in self._edges
                if edge.parent_node_id == current_id and edge.tenant_id == tenant_id
                and edge.edge_id not in visited_edges
            ]

            for edge in child_edges:
                visited_edges.add(edge.edge_id)
                result_edges.append(edge)
                traverse_downstream(edge.child_node_id, depth + 1)

        traverse_downstream(node_id, 0)

        return LineageGraphResult(
            root_node_id=node_id,
            direction="downstream",
            nodes=result_nodes,
            edges=result_edges,
            depth_reached=max_depth_reached,
            has_cycles=has_cycles,
        )

    async def analyze_impact(
        self,
        source_node_id: str,
        tenant_id: str,
    ) -> ImpactAnalysis:
        """Analyze which nodes would be affected if a source node changes.

        Performs a full downstream traversal and categorizes all affected
        nodes by type. Essential for license risk propagation analysis.

        Args:
            source_node_id: The source node that may change.
            tenant_id: The owning tenant.

        Returns:
            ImpactAnalysis with counts and categorization.
        """
        downstream = await self.get_downstream_graph(
            node_id=source_node_id,
            tenant_id=tenant_id,
        )

        # Exclude the source node itself
        affected_nodes = [n for n in downstream.nodes if n.node_id != source_node_id]
        affected_ids = [n.node_id for n in affected_nodes]

        affected_by_type: dict[str, int] = {}
        for node in affected_nodes:
            type_key = node.node_type.value
            affected_by_type[type_key] = affected_by_type.get(type_key, 0) + 1

        logger.info(
            "Impact analysis complete",
            source_node_id=source_node_id,
            affected_count=len(affected_nodes),
            max_depth=downstream.depth_reached,
        )

        return ImpactAnalysis(
            source_node_id=source_node_id,
            affected_node_ids=affected_ids,
            affected_count=len(affected_nodes),
            affected_by_type=affected_by_type,
            max_depth_affected=downstream.depth_reached,
            analysis_performed_at=datetime.now(UTC),
        )

    async def detect_derivative_work(
        self,
        node_id: str,
        tenant_id: str,
    ) -> DerivativeWorkResult:
        """Detect whether a node is a derivative of other works.

        Traverses the upstream graph to identify all contributing source
        nodes and their contribution fractions.

        Args:
            node_id: The node to analyze for derivative status.
            tenant_id: The owning tenant.

        Returns:
            DerivativeWorkResult with full ancestry and contribution data.
        """
        upstream = await self.get_upstream_graph(node_id=node_id, tenant_id=tenant_id)

        direct_parent_edges = [e for e in upstream.edges if e.child_node_id == node_id]
        direct_parents = [e.parent_node_id for e in direct_parent_edges]

        ancestor_ids = [n.node_id for n in upstream.nodes if n.node_id != node_id]

        contributing_sources: list[dict[str, Any]] = []
        for edge in upstream.edges:
            parent_node = self._nodes.get(edge.parent_node_id)
            contributing_sources.append(
                {
                    "node_id": edge.parent_node_id,
                    "node_type": parent_node.node_type.value if parent_node else "unknown",
                    "label": parent_node.label if parent_node else edge.parent_node_id,
                    "relationship": edge.relationship.value,
                    "contribution_fraction": edge.contribution_fraction,
                    "to_node": edge.child_node_id,
                }
            )

        is_derivative = len(direct_parents) > 0
        confidence = min(len(contributing_sources) / 5.0, 1.0) if is_derivative else 0.0

        return DerivativeWorkResult(
            query_node_id=node_id,
            is_derivative=is_derivative,
            direct_parents=direct_parents,
            full_ancestor_chain=ancestor_ids,
            contributing_sources=contributing_sources,
            detection_confidence=confidence,
        )

    async def export_json_ld(self, tenant_id: str) -> dict[str, Any]:
        """Export the full lineage graph as JSON-LD for semantic web use.

        Produces W3C PROV-O compliant JSON-LD output suitable for
        knowledge graph integration and standard provenance tooling.

        Args:
            tenant_id: The tenant whose graph to export.

        Returns:
            JSON-LD document dict.
        """
        tenant_nodes = [n for n in self._nodes.values() if n.tenant_id == tenant_id]
        tenant_edges = [e for e in self._edges if e.tenant_id == tenant_id]

        graph: list[dict[str, Any]] = []

        for node in tenant_nodes:
            prov_type_map = {
                LineageNodeType.TRAINING_DATASET: "prov:Collection",
                LineageNodeType.MODEL: "prov:Plan",
                LineageNodeType.FINE_TUNED_MODEL: "prov:Plan",
                LineageNodeType.OUTPUT: "prov:Entity",
                LineageNodeType.DERIVED_DATASET: "prov:Collection",
            }

            graph.append(
                {
                    "@id": f"urn:aumos:lineage:{node.node_id}",
                    "@type": prov_type_map.get(node.node_type, "prov:Entity"),
                    "rdfs:label": node.label,
                    "aumos:nodeType": node.node_type.value,
                    "aumos:registeredAt": node.registered_at.isoformat(),
                    "aumos:metadata": node.metadata,
                }
            )

        for edge in tenant_edges:
            relationship_map = {
                LineageRelationship.TRAINED_ON: "prov:wasDerivedFrom",
                LineageRelationship.FINE_TUNED_ON: "prov:wasDerivedFrom",
                LineageRelationship.GENERATED_BY: "prov:wasGeneratedBy",
                LineageRelationship.DERIVED_FROM: "prov:wasDerivedFrom",
                LineageRelationship.EVALUATED_ON: "prov:used",
                LineageRelationship.CONTRIBUTED_TO: "prov:wasInfluencedBy",
                LineageRelationship.MERGED_FROM: "prov:wasDerivedFrom",
            }

            graph.append(
                {
                    "@id": f"urn:aumos:lineage:edge:{edge.edge_id}",
                    "@type": "prov:Derivation",
                    relationship_map.get(edge.relationship, "prov:wasDerivedFrom"): {
                        "@id": f"urn:aumos:lineage:{edge.parent_node_id}"
                    },
                    "prov:entity": {"@id": f"urn:aumos:lineage:{edge.child_node_id}"},
                    "aumos:contributionFraction": edge.contribution_fraction,
                    "aumos:relationship": edge.relationship.value,
                    "aumos:createdAt": edge.created_at.isoformat(),
                }
            )

        return {
            "@context": {
                "prov": "http://www.w3.org/ns/prov#",
                "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
                "aumos": "https://aumos.ai/lineage/1.0/",
            },
            "@graph": graph,
            "aumos:exportedAt": datetime.now(UTC).isoformat(),
            "aumos:tenantId": tenant_id,
            "aumos:nodeCount": len(tenant_nodes),
            "aumos:edgeCount": len(tenant_edges),
        }

    async def export_rdf_turtle(self, tenant_id: str) -> str:
        """Export the lineage graph as RDF Turtle format.

        Produces a standard RDF/Turtle serialization for interoperability
        with triple stores (Apache Jena, Amazon Neptune, Stardog).

        Args:
            tenant_id: The tenant whose graph to export.

        Returns:
            RDF Turtle string.
        """
        tenant_nodes = [n for n in self._nodes.values() if n.tenant_id == tenant_id]
        tenant_edges = [e for e in self._edges if e.tenant_id == tenant_id]

        lines: list[str] = [
            "@prefix prov: <http://www.w3.org/ns/prov#> .",
            "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .",
            "@prefix aumos: <https://aumos.ai/lineage/1.0/> .",
            "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .",
            "",
        ]

        for node in tenant_nodes:
            node_uri = f"<urn:aumos:lineage:{node.node_id}>"
            lines.append(f"{node_uri}")
            lines.append(f"    a prov:Entity ;")
            lines.append(f'    rdfs:label "{node.label}" ;')
            lines.append(f'    aumos:nodeType "{node.node_type.value}" ;')
            lines.append(f'    aumos:registeredAt "{node.registered_at.isoformat()}"^^xsd:dateTime .')
            lines.append("")

        for edge in tenant_edges:
            parent_uri = f"<urn:aumos:lineage:{edge.parent_node_id}>"
            child_uri = f"<urn:aumos:lineage:{edge.child_node_id}>"
            lines.append(f"{child_uri}")
            lines.append(f"    prov:wasDerivedFrom {parent_uri} ;")
            lines.append(f'    aumos:relationship "{edge.relationship.value}" ;')
            lines.append(f"    aumos:contributionFraction {edge.contribution_fraction} .")
            lines.append("")

        return "\n".join(lines)

    async def query_lineage(
        self,
        tenant_id: str,
        node_type_filter: LineageNodeType | None = None,
        relationship_filter: LineageRelationship | None = None,
    ) -> dict[str, Any]:
        """Query the lineage graph with optional filters.

        Args:
            tenant_id: The tenant to query.
            node_type_filter: Optional filter by node type.
            relationship_filter: Optional filter by edge relationship.

        Returns:
            Dict with filtered nodes and edges.
        """
        tenant_nodes = [n for n in self._nodes.values() if n.tenant_id == tenant_id]
        tenant_edges = [e for e in self._edges if e.tenant_id == tenant_id]

        if node_type_filter is not None:
            tenant_nodes = [n for n in tenant_nodes if n.node_type == node_type_filter]

        if relationship_filter is not None:
            tenant_edges = [e for e in tenant_edges if e.relationship == relationship_filter]

        return {
            "tenant_id": tenant_id,
            "node_count": len(tenant_nodes),
            "edge_count": len(tenant_edges),
            "nodes": [
                {
                    "node_id": n.node_id,
                    "node_type": n.node_type.value,
                    "label": n.label,
                    "registered_at": n.registered_at.isoformat(),
                    "metadata": n.metadata,
                }
                for n in tenant_nodes
            ],
            "edges": [
                {
                    "edge_id": e.edge_id,
                    "parent_node_id": e.parent_node_id,
                    "child_node_id": e.child_node_id,
                    "relationship": e.relationship.value,
                    "contribution_fraction": e.contribution_fraction,
                    "created_at": e.created_at.isoformat(),
                }
                for e in tenant_edges
            ],
        }


__all__ = [
    "LineageRelationship",
    "LineageNode",
    "LineageEdge",
    "LineageGraphResult",
    "ImpactAnalysis",
    "DerivativeWorkResult",
    "LineageResolver",
]
