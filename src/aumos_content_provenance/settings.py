"""Service-specific settings extending AumOS base config.

All standard AumOS configuration is inherited from AumOSSettings.
Content provenance settings use the AUMOS_PROVENANCE_ env prefix.

Key settings:
- C2PA_SIGNING_KEY_PATH: Path to C2PA signing private key (PEM format)
- C2PA_CERT_CHAIN_PATH: Path to certificate chain for C2PA manifests
- WATERMARK_STRENGTH: Invisibility/robustness tradeoff (0.0–1.0)
- AUDIT_EXPORT_BUCKET: S3-compatible bucket for court-admissible audit exports
"""

from pydantic_settings import SettingsConfigDict

from aumos_common.config import AumOSSettings


class Settings(AumOSSettings):
    """Settings for aumos-content-provenance.

    Inherits all standard AumOS settings (database, kafka, keycloak, etc.)
    and adds content-provenance-specific configuration.

    Environment variable prefix: AUMOS_PROVENANCE_
    """

    service_name: str = "aumos-content-provenance"

    # C2PA signing — paths to private key and certificate chain (PEM)
    c2pa_signing_key_path: str = "/run/secrets/c2pa_signing_key.pem"
    c2pa_cert_chain_path: str = "/run/secrets/c2pa_cert_chain.pem"
    c2pa_signing_algorithm: str = "Es256"  # ES256 ECDSA

    # Watermarking — invisibility vs. robustness tradeoff (0.0 = invisible, 1.0 = robust)
    watermark_strength: float = 0.3
    watermark_method: str = "dwtDct"  # DWT+DCT invisible watermark

    # Audit export — S3-compatible bucket for court-admissible trails
    audit_export_bucket: str = ""
    audit_export_prefix: str = "aumos-audit-trails/"
    audit_export_format: str = "json"  # json or csv

    # License compliance — threshold for flagging suspicious license types
    license_risk_threshold: float = 0.7

    # Lineage — maximum depth for lineage chain traversal
    lineage_max_depth: int = 10

    # Feature flags
    enable_c2pa_signing: bool = True
    enable_watermarking: bool = True
    enable_lineage_tracking: bool = True

    model_config = SettingsConfigDict(env_prefix="AUMOS_PROVENANCE_")
