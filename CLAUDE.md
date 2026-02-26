# aumos-content-provenance — Build Instructions

## Purpose
AI content provenance with C2PA cryptographic tracking, invisible watermarking, training data lineage, license compliance (51 copyright lawsuits context), and court-admissible audit trails.

## Package Info
- Package name: `aumos_content_provenance`
- Table prefix: `cpv_`
- Env prefix: `AUMOS_PROVENANCE_`
- Port: 8000

## Architecture
Hexagonal architecture:
- `api/` — FastAPI router and Pydantic schemas
- `core/` — Domain models, interfaces (Protocol), and services
- `adapters/` — SQLAlchemy repositories, C2PA client, watermark engine, Kafka publisher

## Database Tables
```sql
cpv_provenance_records  — C2PA signed manifests + content hashes
cpv_watermarks          — Watermark metadata (method, payload hash, strength)
cpv_lineage_entries     — Directed graph edges: parent_node → child_node
cpv_license_checks      — License risk assessments per training data item
cpv_audit_exports       — Generated audit trail packages with SHA-256 hashes
```

## Key Dependencies
- `c2pa-python` — C2PA SDK (stub mode when not installed)
- `invisible-watermark` — DWT+DCT and RivaGAN watermarking (stub when not installed)
- `Pillow` + `numpy` — Image processing for watermarking
- `cryptography` — Hash utilities and key handling
- `aiokafka` — Async Kafka event publishing

## API Endpoints
```
POST   /api/v1/provenance/sign               Sign content with C2PA
GET    /api/v1/provenance/verify/{id}         Verify C2PA manifest
GET    /api/v1/provenance                     List provenance records
POST   /api/v1/watermark/embed               Embed invisible watermark
POST   /api/v1/watermark/detect              Detect watermark and extract payload
GET    /api/v1/lineage/{content_id}           Get training data lineage graph
POST   /api/v1/lineage                        Record a lineage edge
POST   /api/v1/license/check                  Check license compliance
GET    /api/v1/license/reports                License compliance reports
POST   /api/v1/audit/export                   Export court-admissible audit trail
```

## Stub Mode
Both C2PA and watermark engines fall back to stub implementations when their
respective libraries are not installed. Stubs produce valid response structures
for integration testing but do not perform real cryptographic operations.

## Development
```bash
make install    # pip install -e ".[dev]"
make dev        # uvicorn with --reload on port 8000
make test       # pytest with coverage
make lint       # ruff check
make typecheck  # mypy
make docker-up  # start postgres + kafka + service
```
