# Changelog

All notable changes to `aumos-content-provenance` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-02-26

### Added
- C2PA content signing via `POST /api/v1/provenance/sign` with ECDSA-P256 manifests
- C2PA manifest verification via `GET /api/v1/provenance/verify/{id}` with hash + crypto checks
- Provenance record listing via `GET /api/v1/provenance`
- Invisible watermark embedding via `POST /api/v1/watermark/embed` (DWT+DCT, DWT+DCT+SVD, RivaGAN)
- Watermark detection and payload extraction via `POST /api/v1/watermark/detect`
- Training data lineage graph traversal via `GET /api/v1/lineage/{content_id}` (recursive CTE)
- Lineage edge recording via `POST /api/v1/lineage`
- License compliance check via `POST /api/v1/license/check` with SPDX risk matrix (LOW/MEDIUM/HIGH/CRITICAL)
- License compliance reports via `GET /api/v1/license/reports` with risk aggregation
- Court-admissible audit trail export via `POST /api/v1/audit/export` with SHA-256 tamper evidence
- Five database tables with `cpv_` prefix: provenance_records, watermarks, lineage_entries, license_checks, audit_exports
- Stub adapters for C2PA and watermark engines (graceful fallback when libraries not installed)
- Kafka event publishing for all domain events
- Multi-tenant isolation via tenant_id scoping on all queries
