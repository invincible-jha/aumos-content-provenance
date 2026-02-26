"""AumOS Content Provenance service entry point.

Initializes the content provenance service at startup:
1. Opens database connection pool
2. Verifies C2PA signing key access (if configured)
3. Pre-warms watermark engine (loads ML model if RivaGAN enabled)
4. Starts Kafka event publisher

Port: 8000
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from aumos_common.app import create_app
from aumos_common.database import init_database
from aumos_common.observability import get_logger

from aumos_content_provenance.api.router import router
from aumos_content_provenance.settings import Settings

logger = get_logger(__name__)
settings = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle.

    Args:
        app: The FastAPI application instance.

    Yields:
        None
    """
    logger.info("Starting aumos-content-provenance", version="0.1.0")

    # Initialize database connection pool
    init_database(settings.database)
    logger.info("Database initialized")

    # Initialize Kafka publisher
    from aumos_content_provenance.adapters.kafka import KafkaEventPublisher

    kafka_publisher = KafkaEventPublisher(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        client_id="aumos-content-provenance",
    )
    await kafka_publisher.start()
    app.state.kafka_publisher = kafka_publisher
    logger.info("Kafka publisher initialized")

    # Verify C2PA signing key access
    if settings.enable_c2pa_signing:
        import os

        if os.path.exists(settings.c2pa_signing_key_path):
            logger.info("C2PA signing key found", path=settings.c2pa_signing_key_path)
        else:
            logger.warning(
                "C2PA signing key not found — running in stub mode",
                path=settings.c2pa_signing_key_path,
            )

    logger.info(
        "aumos-content-provenance startup complete",
        c2pa_enabled=settings.enable_c2pa_signing,
        watermark_enabled=settings.enable_watermarking,
        lineage_enabled=settings.enable_lineage_tracking,
    )

    yield

    # Shutdown
    logger.info("Shutting down aumos-content-provenance")
    await kafka_publisher.stop()


app: FastAPI = create_app(
    service_name="aumos-content-provenance",
    version="0.1.0",
    settings=settings,
    lifespan=lifespan,
    health_checks=[],
)

app.include_router(router, prefix="/api/v1")
