FROM python:3.11-slim AS base

WORKDIR /app

# Install system dependencies for image processing (Pillow)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpng-dev \
    libjpeg-dev \
    libopenjp2-7 \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install build dependencies for wheels
FROM base AS builder

RUN pip install --no-cache-dir hatchling

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir --prefix=/install ".[dev]" 2>/dev/null || \
    pip install --no-cache-dir --prefix=/install .

# Production image
FROM base AS production

COPY --from=builder /install /usr/local

WORKDIR /app
COPY src/ ./src/

# Non-root user for security
RUN useradd -r -s /bin/false aumos
USER aumos

EXPOSE 8000

CMD ["uvicorn", "aumos_content_provenance.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "2", "--log-config", "/dev/null"]
