"""Kafka event publisher adapter for aumos-content-provenance.

Publishes domain events to Kafka topics using the aiokafka async client.
Events are serialized as JSON (Protobuf migration planned).

Topics:
- aumos.provenance.signed    — Content signed with C2PA manifest
- aumos.provenance.verified  — Manifest verification result
- aumos.watermark.embedded   — Watermark embedded in content
- aumos.lineage.recorded     — Lineage edge recorded
- aumos.license.checked      — License compliance check completed
- aumos.audit.exported       — Audit trail export generated
"""

import json
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class KafkaEventPublisher:
    """Async Kafka publisher for content provenance domain events.

    Uses aiokafka with JSON serialization. Messages include a standard
    envelope with event_type, tenant_id, and timestamp for consumer routing.
    """

    def __init__(
        self,
        bootstrap_servers: str,
        client_id: str = "aumos-content-provenance",
    ) -> None:
        self._bootstrap_servers = bootstrap_servers
        self._client_id = client_id
        self._producer: Any = None

    async def start(self) -> None:
        """Initialize and start the Kafka producer.

        Called during application startup in the lifespan context manager.
        """
        try:
            from aiokafka import AIOKafkaProducer  # type: ignore[import-not-found]

            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                client_id=self._client_id,
                value_serializer=lambda value: json.dumps(value).encode("utf-8"),
                key_serializer=lambda key: key.encode("utf-8") if isinstance(key, str) else key,
            )
            await self._producer.start()
            logger.info(
                "Kafka producer started",
                bootstrap_servers=self._bootstrap_servers,
                client_id=self._client_id,
            )
        except ImportError:
            logger.warning("aiokafka not available — Kafka publishing disabled")
        except Exception as exc:
            logger.error("Failed to start Kafka producer", error=str(exc))

    async def stop(self) -> None:
        """Flush and stop the Kafka producer.

        Called during application shutdown in the lifespan context manager.
        """
        if self._producer is not None:
            await self._producer.stop()
            logger.info("Kafka producer stopped")

    async def publish(
        self,
        topic: str,
        key: str,
        value: dict[str, Any],
    ) -> None:
        """Publish an event to a Kafka topic.

        Args:
            topic: Kafka topic name.
            key: Partition key (typically tenant_id).
            value: Event payload dict (will be JSON-serialized).
        """
        if self._producer is None:
            logger.debug(
                "Kafka producer not available — skipping event publish",
                topic=topic,
                key=key,
            )
            return

        try:
            await self._producer.send_and_wait(topic=topic, key=key, value=value)
            logger.debug("Event published", topic=topic, key=key, event_type=value.get("event_type"))
        except Exception as exc:
            logger.error(
                "Failed to publish Kafka event",
                topic=topic,
                key=key,
                error=str(exc),
            )


__all__ = ["KafkaEventPublisher"]
