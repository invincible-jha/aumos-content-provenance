# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Report security vulnerabilities to: security@muveraai.com

Do NOT create public GitHub issues for security vulnerabilities.

## Security Considerations

### C2PA Signing Keys
- Private signing keys are mounted as Docker secrets, never baked into images
- Key rotation follows the C2PA specification for revocation via CRL/OCSP
- All signing operations log the key ID used (never the key material)

### Audit Trail Integrity
- Audit packages include SHA-256 hashes computed server-side for tamper evidence
- Export packages are stored in S3 with versioning enabled
- All audit actions are logged with tenant_id and timestamp

### Multi-Tenant Isolation
- Every SQL query is scoped by tenant_id
- RLS (Row Level Security) enforced at the database level
- No cross-tenant data access possible via API

### Watermark Security
- Watermark payloads include tenant_id to enable attribution
- Payload values are hashed in the database (SHA-256) — raw payloads not stored if configured
- Detection endpoints require authentication — cannot be used to mass-scan without authorization
