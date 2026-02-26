# aumos-content-provenance

AI content provenance with C2PA cryptographic tracking, invisible watermarking, training data lineage, license compliance, and court-admissible audit trails.

Part of the [AumOS Enterprise](https://aumos.ai) platform.

## Overview

As 51+ copyright lawsuits target AI companies for training data practices, `aumos-content-provenance` provides the legal infrastructure to demonstrate content origin, verify AI-generated material, and produce court-admissible audit evidence.

### Core Capabilities

| Capability | Technology | Use Case |
|------------|------------|----------|
| C2PA Signing | c2pa-python, ECDSA-P256 | Cryptographically bind content to its metadata |
| Invisible Watermarking | DWT+DCT, RivaGAN | Track AI-generated images through distribution |
| Training Data Lineage | Recursive CTE graph | Map dataset → model → output chains |
| License Compliance | SPDX risk matrix | Flag high-risk training data (CC-BY-NC, UNKNOWN) |
| Audit Exports | SHA-256 tamper evidence | Court-admissible provenance packages |

## API

```
POST   /api/v1/provenance/sign               Sign content with C2PA manifest
GET    /api/v1/provenance/verify/{id}         Verify content provenance
GET    /api/v1/provenance                     List provenance records (paginated)
POST   /api/v1/watermark/embed               Embed invisible watermark
POST   /api/v1/watermark/detect              Detect and extract watermark payload
GET    /api/v1/lineage/{content_id}           Get full training data lineage graph
POST   /api/v1/lineage                        Record a lineage edge
POST   /api/v1/license/check                  Check license compliance risk
GET    /api/v1/license/reports                License compliance reports
POST   /api/v1/audit/export                   Export court-admissible audit trail
```

## Quick Start

```bash
git clone https://github.com/MuVeraAI/aumos-content-provenance
cd aumos-content-provenance
make install
cp .env.example .env
make docker-up
make dev
```

Service runs at `http://localhost:8000`. API docs at `http://localhost:8000/docs`.

## Configuration

All settings use the `AUMOS_PROVENANCE_` prefix. See `.env.example` for the full list.

Key settings:

```env
AUMOS_PROVENANCE_C2PA_SIGNING_KEY_PATH=/run/secrets/c2pa_signing_key.pem
AUMOS_PROVENANCE_WATERMARK_METHOD=dwtDct
AUMOS_PROVENANCE_WATERMARK_STRENGTH=0.3
AUMOS_PROVENANCE_AUDIT_EXPORT_BUCKET=aumos-audit-trails
```

## C2PA Integration

The service implements the [C2PA Specification v2.0](https://c2pa.org) for AI content provenance. Manifests include:

- Content hash (SHA-256)
- Claim generator identity (tenant + system)
- Custom assertions (AI model used, generation parameters, license information)
- ECDSA-P256 cryptographic signature

```python
# Sign AI-generated content
POST /api/v1/provenance/sign
{
    "content_id": "img-abc123",
    "content_type": "image/jpeg",
    "content_base64": "<base64-encoded-bytes>",
    "assertions": [
        {"label": "c2pa.ai.generated", "data": {"model": "stable-diffusion-xl"}}
    ]
}
```

## Invisible Watermarking

Uses frequency-domain watermarking (DWT+DCT) that survives JPEG compression and moderate resizing:

```python
# Embed watermark
POST /api/v1/watermark/embed
{
    "content_id": "img-abc123",
    "content_base64": "<base64-bytes>",
    "method": "dwtDct",
    "strength": 0.3
}

# Detect watermark (attribution)
POST /api/v1/watermark/detect
{
    "content_base64": "<base64-bytes>",
    "method": "dwtDct"
}
```

## License Compliance

Assesses training data license risk against the SPDX license risk matrix:

| Risk Level | Examples | Recommendation |
|------------|----------|----------------|
| LOW | MIT, Apache-2.0, CC0 | Safe for commercial training |
| MEDIUM | GPL, CC-BY-SA | Review copyleft terms |
| HIGH | CC-BY-NC, CC-BY-ND | NOT safe for commercial training |
| CRITICAL | UNKNOWN (no license) | Stop use immediately |

## Audit Exports

Generates tamper-evident JSON packages for legal proceedings:

```python
POST /api/v1/audit/export
{
    "export_type": "full",  # provenance | lineage | license | full
    "filter_params": {}
}
# Returns: export_url + export_hash (SHA-256 for tamper evidence)
```

## Architecture

```
src/aumos_content_provenance/
├── main.py              FastAPI lifespan, app setup
├── settings.py          AUMOS_PROVENANCE_ environment config
├── api/
│   ├── router.py        All 10 API endpoints
│   └── schemas.py       Pydantic request/response models
├── core/
│   ├── models.py        Pure Python domain models
│   ├── interfaces.py    Protocol interfaces for DI
│   └── services.py      C2PAService, WatermarkService, LineageService,
│                        LicenseComplianceService, AuditExportService
└── adapters/
    ├── repositories.py  SQLAlchemy implementations (5 repos)
    ├── c2pa_client.py   C2PA SDK + stub adapter
    ├── watermark_engine.py  invisible-watermark + stub adapter
    └── kafka.py         aiokafka event publisher
```

## Database Schema

Tables use the `cpv_` prefix:

```sql
cpv_provenance_records  -- C2PA manifests, content hashes, signing status
cpv_watermarks          -- Watermark metadata per content item
cpv_lineage_entries     -- Directed graph: parent_node -> child_node edges
cpv_license_checks      -- License risk assessments with SPDX lookup
cpv_audit_exports       -- Export job records with tamper-evidence hashes
```

## License

Apache 2.0 — see [LICENSE](LICENSE)
