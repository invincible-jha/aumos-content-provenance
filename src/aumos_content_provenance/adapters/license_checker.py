"""License checker adapter for aumos-content-provenance.

Performs license compliance analysis for training data, models, and
generated content. Detects license types, analyzes compatibility,
extracts attribution requirements, and generates compliance certificates.

Context: 51+ active copyright lawsuits against AI companies as of 2026.
This module is designed to provide defensible legal documentation.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class LicenseFamily(str, Enum):
    """High-level license family classification."""

    PERMISSIVE = "permissive"          # MIT, Apache, BSD, CC0
    COPYLEFT_WEAK = "copyleft_weak"   # LGPL, MPL, CC-BY-SA
    COPYLEFT_STRONG = "copyleft_strong"  # GPL, AGPL
    NON_COMMERCIAL = "non_commercial"  # CC-BY-NC variants
    NO_DERIVATIVES = "no_derivatives"  # CC-BY-ND variants
    PROPRIETARY = "proprietary"       # All rights reserved
    UNKNOWN = "unknown"               # No license detected


class UseCase(str, Enum):
    """Intended use case for license compatibility check."""

    AI_TRAINING = "ai_training"
    AI_FINE_TUNING = "ai_fine_tuning"
    COMMERCIAL_PRODUCT = "commercial_product"
    RESEARCH_ONLY = "research_only"
    INTERNAL_USE = "internal_use"
    REDISTRIBUTION = "redistribution"
    DERIVATIVE_WORK = "derivative_work"


@dataclass
class LicenseProfile:
    """Full profile of a known license including all its attributes."""

    spdx_id: str
    full_name: str
    family: LicenseFamily
    allows_commercial: bool
    allows_derivatives: bool
    allows_sublicensing: bool
    allows_ai_training: bool           # Whether training use is permitted
    requires_attribution: bool
    requires_share_alike: bool
    requires_patent_grant: bool
    osi_approved: bool
    fsf_approved: bool
    risk_score: float                  # 0.0–1.0 composite litigation risk
    attribution_template: str | None  # Template for required attribution
    url: str                          # License text URL


@dataclass
class CompatibilityResult:
    """Result of checking compatibility between two licenses."""

    license_a: str
    license_b: str
    compatible: bool
    reason: str
    combining_allowed: bool            # Can works under both licenses be combined?
    restrictions_apply: list[str]     # Any restrictions on combination
    confidence: float                  # 0.0–1.0


@dataclass
class AttributionRequirement:
    """Attribution requirements extracted from a license."""

    content_id: str
    license_spdx: str
    requires_attribution: bool
    attribution_text: str | None       # Pre-formatted attribution string
    copyright_holders: list[str]
    must_retain_notices: bool
    must_link_license: bool
    must_state_changes: bool


@dataclass
class ComplianceCertificate:
    """Certificate of license compliance for a collection of content."""

    certificate_id: str
    tenant_id: str
    scope: str                         # What this certificate covers
    issued_at: datetime
    valid_until: datetime              # Certificates expire (re-run for current state)
    content_ids: list[str]
    all_compliant: bool
    violations: list[dict[str, Any]]
    risk_summary: dict[str, Any]
    certification_hash: str            # SHA-256 of the certificate data
    issuer: str


# Comprehensive SPDX license database
_LICENSE_DATABASE: dict[str, LicenseProfile] = {
    "MIT": LicenseProfile(
        spdx_id="MIT", full_name="MIT License",
        family=LicenseFamily.PERMISSIVE,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=True,
        allows_ai_training=True, requires_attribution=True, requires_share_alike=False,
        requires_patent_grant=False, osi_approved=True, fsf_approved=True,
        risk_score=0.05,
        attribution_template="Copyright (c) {year} {holder}. MIT License.",
        url="https://spdx.org/licenses/MIT.html",
    ),
    "Apache-2.0": LicenseProfile(
        spdx_id="Apache-2.0", full_name="Apache License 2.0",
        family=LicenseFamily.PERMISSIVE,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=True,
        allows_ai_training=True, requires_attribution=True, requires_share_alike=False,
        requires_patent_grant=True, osi_approved=True, fsf_approved=True,
        risk_score=0.05,
        attribution_template="Licensed under the Apache License, Version 2.0. Copyright {year} {holder}.",
        url="https://spdx.org/licenses/Apache-2.0.html",
    ),
    "BSD-2-Clause": LicenseProfile(
        spdx_id="BSD-2-Clause", full_name="BSD 2-Clause 'Simplified' License",
        family=LicenseFamily.PERMISSIVE,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=True,
        allows_ai_training=True, requires_attribution=True, requires_share_alike=False,
        requires_patent_grant=False, osi_approved=True, fsf_approved=True,
        risk_score=0.08,
        attribution_template="Copyright {year} {holder}. BSD 2-Clause License.",
        url="https://spdx.org/licenses/BSD-2-Clause.html",
    ),
    "BSD-3-Clause": LicenseProfile(
        spdx_id="BSD-3-Clause", full_name="BSD 3-Clause 'New' or 'Revised' License",
        family=LicenseFamily.PERMISSIVE,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=True,
        allows_ai_training=True, requires_attribution=True, requires_share_alike=False,
        requires_patent_grant=False, osi_approved=True, fsf_approved=True,
        risk_score=0.08,
        attribution_template="Copyright {year} {holder}. BSD 3-Clause License.",
        url="https://spdx.org/licenses/BSD-3-Clause.html",
    ),
    "CC0-1.0": LicenseProfile(
        spdx_id="CC0-1.0", full_name="Creative Commons Zero v1.0 Universal",
        family=LicenseFamily.PERMISSIVE,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=True,
        allows_ai_training=True, requires_attribution=False, requires_share_alike=False,
        requires_patent_grant=False, osi_approved=False, fsf_approved=True,
        risk_score=0.02,
        attribution_template=None,
        url="https://spdx.org/licenses/CC0-1.0.html",
    ),
    "Unlicense": LicenseProfile(
        spdx_id="Unlicense", full_name="The Unlicense",
        family=LicenseFamily.PERMISSIVE,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=True,
        allows_ai_training=True, requires_attribution=False, requires_share_alike=False,
        requires_patent_grant=False, osi_approved=True, fsf_approved=True,
        risk_score=0.03,
        attribution_template=None,
        url="https://spdx.org/licenses/Unlicense.html",
    ),
    "GPL-2.0": LicenseProfile(
        spdx_id="GPL-2.0", full_name="GNU General Public License v2.0",
        family=LicenseFamily.COPYLEFT_STRONG,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=False,
        allows_ai_training=False, requires_attribution=True, requires_share_alike=True,
        requires_patent_grant=False, osi_approved=True, fsf_approved=True,
        risk_score=0.55,
        attribution_template="This software is licensed under the GNU GPL v2. Source code must be provided.",
        url="https://spdx.org/licenses/GPL-2.0.html",
    ),
    "GPL-3.0": LicenseProfile(
        spdx_id="GPL-3.0", full_name="GNU General Public License v3.0",
        family=LicenseFamily.COPYLEFT_STRONG,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=False,
        allows_ai_training=False, requires_attribution=True, requires_share_alike=True,
        requires_patent_grant=True, osi_approved=True, fsf_approved=True,
        risk_score=0.55,
        attribution_template="This software is licensed under the GNU GPL v3. Source must be provided.",
        url="https://spdx.org/licenses/GPL-3.0.html",
    ),
    "AGPL-3.0": LicenseProfile(
        spdx_id="AGPL-3.0", full_name="GNU Affero General Public License v3.0",
        family=LicenseFamily.COPYLEFT_STRONG,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=False,
        allows_ai_training=False, requires_attribution=True, requires_share_alike=True,
        requires_patent_grant=True, osi_approved=True, fsf_approved=True,
        risk_score=0.70,
        attribution_template="This software is licensed under AGPL-3.0. Network use triggers copyleft.",
        url="https://spdx.org/licenses/AGPL-3.0.html",
    ),
    "LGPL-2.1": LicenseProfile(
        spdx_id="LGPL-2.1", full_name="GNU Lesser General Public License v2.1",
        family=LicenseFamily.COPYLEFT_WEAK,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=False,
        allows_ai_training=True, requires_attribution=True, requires_share_alike=True,
        requires_patent_grant=False, osi_approved=True, fsf_approved=True,
        risk_score=0.35,
        attribution_template="This software uses LGPL-2.1 licensed components.",
        url="https://spdx.org/licenses/LGPL-2.1.html",
    ),
    "CC-BY-4.0": LicenseProfile(
        spdx_id="CC-BY-4.0", full_name="Creative Commons Attribution 4.0 International",
        family=LicenseFamily.PERMISSIVE,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=True,
        allows_ai_training=True, requires_attribution=True, requires_share_alike=False,
        requires_patent_grant=False, osi_approved=False, fsf_approved=False,
        risk_score=0.20,
        attribution_template="{holder}, licensed under CC BY 4.0. https://creativecommons.org/licenses/by/4.0/",
        url="https://spdx.org/licenses/CC-BY-4.0.html",
    ),
    "CC-BY-SA-4.0": LicenseProfile(
        spdx_id="CC-BY-SA-4.0", full_name="Creative Commons Attribution-ShareAlike 4.0",
        family=LicenseFamily.COPYLEFT_WEAK,
        allows_commercial=True, allows_derivatives=True, allows_sublicensing=False,
        allows_ai_training=True, requires_attribution=True, requires_share_alike=True,
        requires_patent_grant=False, osi_approved=False, fsf_approved=False,
        risk_score=0.45,
        attribution_template="{holder}, CC BY-SA 4.0. Derivatives must use same license.",
        url="https://spdx.org/licenses/CC-BY-SA-4.0.html",
    ),
    "CC-BY-NC-4.0": LicenseProfile(
        spdx_id="CC-BY-NC-4.0", full_name="Creative Commons Attribution-NonCommercial 4.0",
        family=LicenseFamily.NON_COMMERCIAL,
        allows_commercial=False, allows_derivatives=True, allows_sublicensing=False,
        allows_ai_training=False, requires_attribution=True, requires_share_alike=False,
        requires_patent_grant=False, osi_approved=False, fsf_approved=False,
        risk_score=0.80,
        attribution_template="{holder}, CC BY-NC 4.0. NON-COMMERCIAL USE ONLY.",
        url="https://spdx.org/licenses/CC-BY-NC-4.0.html",
    ),
    "CC-BY-NC-SA-4.0": LicenseProfile(
        spdx_id="CC-BY-NC-SA-4.0",
        full_name="Creative Commons Attribution-NonCommercial-ShareAlike 4.0",
        family=LicenseFamily.NON_COMMERCIAL,
        allows_commercial=False, allows_derivatives=True, allows_sublicensing=False,
        allows_ai_training=False, requires_attribution=True, requires_share_alike=True,
        requires_patent_grant=False, osi_approved=False, fsf_approved=False,
        risk_score=0.85,
        attribution_template="{holder}, CC BY-NC-SA 4.0. NON-COMMERCIAL, SHARE-ALIKE.",
        url="https://spdx.org/licenses/CC-BY-NC-SA-4.0.html",
    ),
    "CC-BY-ND-4.0": LicenseProfile(
        spdx_id="CC-BY-ND-4.0", full_name="Creative Commons Attribution-NoDerivatives 4.0",
        family=LicenseFamily.NO_DERIVATIVES,
        allows_commercial=True, allows_derivatives=False, allows_sublicensing=False,
        allows_ai_training=False, requires_attribution=True, requires_share_alike=False,
        requires_patent_grant=False, osi_approved=False, fsf_approved=False,
        risk_score=0.80,
        attribution_template="{holder}, CC BY-ND 4.0. NO DERIVATIVES PERMITTED.",
        url="https://spdx.org/licenses/CC-BY-ND-4.0.html",
    ),
}

# License compatibility matrix: compatible[a][b] = True means a and b can be combined
_COMPATIBILITY_MATRIX: dict[str, dict[str, bool]] = {
    "MIT": {"MIT": True, "Apache-2.0": True, "BSD-2-Clause": True, "BSD-3-Clause": True,
             "CC0-1.0": True, "Unlicense": True, "GPL-2.0": True, "GPL-3.0": True,
             "LGPL-2.1": True, "CC-BY-4.0": False, "CC-BY-SA-4.0": False},
    "Apache-2.0": {"MIT": True, "Apache-2.0": True, "BSD-2-Clause": True, "BSD-3-Clause": True,
                    "CC0-1.0": True, "GPL-2.0": False, "GPL-3.0": True, "LGPL-2.1": True},
    "GPL-2.0": {"GPL-2.0": True, "LGPL-2.1": True, "MIT": True, "BSD-2-Clause": True,
                 "Apache-2.0": False, "GPL-3.0": False},
    "GPL-3.0": {"GPL-3.0": True, "LGPL-2.1": True, "Apache-2.0": True, "MIT": True,
                 "BSD-2-Clause": True, "GPL-2.0": False},
    "CC-BY-4.0": {"CC-BY-4.0": True, "CC-BY-SA-4.0": True, "CC0-1.0": True},
    "CC-BY-SA-4.0": {"CC-BY-SA-4.0": True, "CC0-1.0": True, "CC-BY-4.0": False},
    "CC-BY-NC-4.0": {"CC-BY-NC-4.0": True, "CC-BY-NC-SA-4.0": False},
    "CC-BY-NC-SA-4.0": {"CC-BY-NC-SA-4.0": True},
}


class LicenseChecker:
    """Analyze license compliance for content and training data.

    Provides:
    - License type detection and profile lookup
    - Compatibility analysis between multiple licenses
    - Attribution requirement generation
    - Commercial use and derivative work verification
    - Violation detection and compliance certificate generation

    Backed by the SPDX license list and a curated compatibility matrix.
    Use case-specific rules account for AI training restrictions.
    """

    def __init__(self, organization_name: str = "AumOS") -> None:
        self._organization_name = organization_name
        self._db = _LICENSE_DATABASE
        self._compat = _COMPATIBILITY_MATRIX

    async def detect_license(
        self,
        content_id: str,
        license_identifier: str,
        copyright_holders: list[str] | None = None,
    ) -> LicenseProfile | None:
        """Look up a license profile by SPDX identifier.

        Args:
            content_id: The content being analyzed (for logging).
            license_identifier: SPDX identifier (e.g., "MIT", "CC-BY-4.0").
            copyright_holders: Known copyright holders for the content.

        Returns:
            LicenseProfile if recognized, None if unknown.
        """
        normalized = license_identifier.strip()
        profile = self._db.get(normalized)

        logger.info(
            "License detection",
            content_id=content_id,
            license=normalized,
            recognized=profile is not None,
            holders=copyright_holders or [],
        )

        return profile

    async def check_compatibility(
        self,
        license_a: str,
        license_b: str,
        use_case: UseCase = UseCase.AI_TRAINING,
    ) -> CompatibilityResult:
        """Check whether two licenses can be combined for the given use case.

        Args:
            license_a: First SPDX license identifier.
            license_b: Second SPDX license identifier.
            use_case: Intended use of the combined works.

        Returns:
            CompatibilityResult with combination verdict and restrictions.
        """
        profile_a = self._db.get(license_a)
        profile_b = self._db.get(license_b)

        # If either is unknown, incompatible by default
        if profile_a is None or profile_b is None:
            unknown = license_a if profile_a is None else license_b
            return CompatibilityResult(
                license_a=license_a,
                license_b=license_b,
                compatible=False,
                reason=f"License '{unknown}' is not recognized — assuming incompatible",
                combining_allowed=False,
                restrictions_apply=["unrecognized_license"],
                confidence=0.5,
            )

        # Check matrix
        matrix_entry = self._compat.get(license_a, {})
        matrix_compat = matrix_entry.get(license_b)

        restrictions: list[str] = []

        # Use case-specific checks
        if use_case == UseCase.AI_TRAINING:
            if not profile_a.allows_ai_training:
                restrictions.append(f"{license_a} prohibits AI training use")
            if not profile_b.allows_ai_training:
                restrictions.append(f"{license_b} prohibits AI training use")

        if use_case in (UseCase.COMMERCIAL_PRODUCT, UseCase.AI_TRAINING):
            if not profile_a.allows_commercial:
                restrictions.append(f"{license_a} prohibits commercial use")
            if not profile_b.allows_commercial:
                restrictions.append(f"{license_b} prohibits commercial use")

        if use_case == UseCase.DERIVATIVE_WORK:
            if not profile_a.allows_derivatives:
                restrictions.append(f"{license_a} prohibits derivative works")
            if not profile_b.allows_derivatives:
                restrictions.append(f"{license_b} prohibits derivative works")

        # Share-alike conflict detection
        if profile_a.requires_share_alike and profile_b.requires_share_alike:
            if license_a != license_b:
                restrictions.append(
                    f"Both licenses require share-alike but have different requirements — conflicting copyleft"
                )

        # Determine overall compatibility
        if restrictions:
            compatible = False
            reason = f"Incompatible for {use_case.value}: " + "; ".join(restrictions)
        elif matrix_compat is False:
            compatible = False
            reason = f"Known incompatibility: {license_a} and {license_b} cannot be combined"
        elif matrix_compat is True:
            compatible = True
            reason = f"Compatible for {use_case.value} use"
        else:
            # Not in matrix — use heuristics
            both_permissive = (
                profile_a.family == LicenseFamily.PERMISSIVE
                and profile_b.family == LicenseFamily.PERMISSIVE
            )
            compatible = both_permissive
            reason = (
                "Both licenses are permissive — likely compatible"
                if both_permissive
                else "Compatibility unknown — consult legal counsel"
            )

        return CompatibilityResult(
            license_a=license_a,
            license_b=license_b,
            compatible=compatible,
            reason=reason,
            combining_allowed=compatible,
            restrictions_apply=restrictions,
            confidence=0.9 if matrix_compat is not None else 0.6,
        )

    async def extract_attribution(
        self,
        content_id: str,
        license_spdx: str,
        copyright_holders: list[str],
        year: int | None = None,
    ) -> AttributionRequirement:
        """Generate attribution text required by a license.

        Args:
            content_id: The content to generate attribution for.
            license_spdx: SPDX license identifier.
            copyright_holders: List of copyright holder names.
            year: Copyright year (defaults to current year).

        Returns:
            AttributionRequirement with generated attribution text.
        """
        profile = self._db.get(license_spdx)
        resolved_year = year or datetime.now(UTC).year
        holder_str = ", ".join(copyright_holders) if copyright_holders else "Unknown"

        if profile is None:
            return AttributionRequirement(
                content_id=content_id,
                license_spdx=license_spdx,
                requires_attribution=True,
                attribution_text=f"Copyright {resolved_year} {holder_str}. License: {license_spdx}.",
                copyright_holders=copyright_holders,
                must_retain_notices=True,
                must_link_license=True,
                must_state_changes=False,
            )

        if not profile.requires_attribution:
            return AttributionRequirement(
                content_id=content_id,
                license_spdx=license_spdx,
                requires_attribution=False,
                attribution_text=None,
                copyright_holders=copyright_holders,
                must_retain_notices=False,
                must_link_license=False,
                must_state_changes=False,
            )

        attribution_text: str | None = None
        if profile.attribution_template:
            attribution_text = profile.attribution_template.format(
                holder=holder_str,
                year=resolved_year,
            )
        else:
            attribution_text = f"Copyright {resolved_year} {holder_str}. Licensed under {license_spdx}."

        return AttributionRequirement(
            content_id=content_id,
            license_spdx=license_spdx,
            requires_attribution=profile.requires_attribution,
            attribution_text=attribution_text,
            copyright_holders=copyright_holders,
            must_retain_notices=True,
            must_link_license=profile.family in (LicenseFamily.COPYLEFT_WEAK, LicenseFamily.COPYLEFT_STRONG),
            must_state_changes=profile.requires_share_alike,
        )

    async def check_commercial_use(
        self,
        license_spdx: str,
        content_id: str,
    ) -> tuple[bool, str]:
        """Check whether commercial use of this content is permitted.

        Args:
            license_spdx: SPDX license identifier.
            content_id: The content being checked.

        Returns:
            Tuple of (commercial_use_allowed, reason_message).
        """
        profile = self._db.get(license_spdx)

        if profile is None:
            return (
                False,
                f"License '{license_spdx}' not recognized — commercial use prohibited by default",
            )

        if profile.allows_commercial:
            return (
                True,
                f"Commercial use permitted under {license_spdx}",
            )

        return (
            False,
            f"Commercial use PROHIBITED under {license_spdx} ({profile.family.value}). "
            f"Content ID: {content_id}",
        )

    async def check_derivative_permission(
        self,
        license_spdx: str,
        content_id: str,
    ) -> tuple[bool, str, bool]:
        """Check whether derivative works are permitted and if share-alike applies.

        Args:
            license_spdx: SPDX identifier.
            content_id: The content to check.

        Returns:
            Tuple of (derivatives_allowed, reason, share_alike_required).
        """
        profile = self._db.get(license_spdx)

        if profile is None:
            return (
                False,
                f"License '{license_spdx}' not recognized — derivative works prohibited by default",
                False,
            )

        if not profile.allows_derivatives:
            return (
                False,
                f"Derivative works PROHIBITED under {license_spdx}. Content: {content_id}",
                False,
            )

        return (
            True,
            f"Derivative works permitted under {license_spdx}"
            + (" (share-alike required)" if profile.requires_share_alike else ""),
            profile.requires_share_alike,
        )

    async def detect_violations(
        self,
        content_licenses: list[dict[str, Any]],
        use_case: UseCase,
    ) -> list[dict[str, Any]]:
        """Detect license violations across a collection of content items.

        Args:
            content_licenses: List of dicts with "content_id" and "license" keys.
            use_case: Intended use to check violations against.

        Returns:
            List of violation dicts (empty if compliant).
        """
        violations: list[dict[str, Any]] = []

        for item in content_licenses:
            content_id = item.get("content_id", "unknown")
            license_spdx = item.get("license", "UNKNOWN")
            profile = self._db.get(license_spdx)

            if profile is None:
                violations.append(
                    {
                        "content_id": content_id,
                        "license": license_spdx,
                        "violation_type": "unknown_license",
                        "severity": "critical",
                        "description": "License not recognized — copyright assumed",
                    }
                )
                continue

            if use_case == UseCase.AI_TRAINING and not profile.allows_ai_training:
                violations.append(
                    {
                        "content_id": content_id,
                        "license": license_spdx,
                        "violation_type": "ai_training_prohibited",
                        "severity": "high",
                        "description": f"{license_spdx} explicitly prohibits AI training use",
                    }
                )

            if use_case in (UseCase.COMMERCIAL_PRODUCT, UseCase.AI_TRAINING) and not profile.allows_commercial:
                violations.append(
                    {
                        "content_id": content_id,
                        "license": license_spdx,
                        "violation_type": "commercial_use_prohibited",
                        "severity": "high",
                        "description": f"{license_spdx} prohibits commercial use",
                    }
                )

            if use_case == UseCase.DERIVATIVE_WORK and not profile.allows_derivatives:
                violations.append(
                    {
                        "content_id": content_id,
                        "license": license_spdx,
                        "violation_type": "derivatives_prohibited",
                        "severity": "high",
                        "description": f"{license_spdx} prohibits derivative works (no-derivatives clause)",
                    }
                )

        logger.info(
            "Violation detection complete",
            total_items=len(content_licenses),
            violations_found=len(violations),
            use_case=use_case.value,
        )

        return violations

    async def generate_compliance_certificate(
        self,
        tenant_id: str,
        content_ids: list[str],
        licenses: dict[str, str],         # content_id -> license_spdx
        use_case: UseCase,
        scope_description: str,
        valid_days: int = 90,
    ) -> ComplianceCertificate:
        """Generate a compliance certificate for a collection of content.

        Args:
            tenant_id: The owning tenant.
            content_ids: List of content IDs covered by the certificate.
            licenses: Mapping of content_id to SPDX license.
            use_case: The use case being certified.
            scope_description: Human-readable scope of this certificate.
            valid_days: Certificate validity period in days.

        Returns:
            ComplianceCertificate with cryptographic hash for integrity.
        """
        content_license_list = [
            {"content_id": cid, "license": licenses.get(cid, "UNKNOWN")}
            for cid in content_ids
        ]

        violations = await self.detect_violations(content_license_list, use_case)
        all_compliant = len(violations) == 0

        risk_by_family: dict[str, int] = {}
        for item in content_license_list:
            profile = self._db.get(item["license"])
            family = profile.family.value if profile else LicenseFamily.UNKNOWN.value
            risk_by_family[family] = risk_by_family.get(family, 0) + 1

        issued_at = datetime.now(UTC)
        from datetime import timedelta
        valid_until = issued_at + timedelta(days=valid_days)

        cert_data = {
            "tenant_id": tenant_id,
            "scope": scope_description,
            "content_count": len(content_ids),
            "use_case": use_case.value,
            "all_compliant": all_compliant,
            "violation_count": len(violations),
            "issued_at": issued_at.isoformat(),
            "valid_until": valid_until.isoformat(),
        }
        certification_hash = hashlib.sha256(
            json.dumps(cert_data, sort_keys=True).encode()
        ).hexdigest()

        certificate = ComplianceCertificate(
            certificate_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            scope=scope_description,
            issued_at=issued_at,
            valid_until=valid_until,
            content_ids=content_ids,
            all_compliant=all_compliant,
            violations=violations,
            risk_summary={
                "by_license_family": risk_by_family,
                "violation_count": len(violations),
                "compliant_count": len(content_ids) - len(violations),
            },
            certification_hash=certification_hash,
            issuer=f"{self._organization_name}/LicenseChecker",
        )

        logger.info(
            "Compliance certificate generated",
            certificate_id=certificate.certificate_id,
            content_count=len(content_ids),
            all_compliant=all_compliant,
            violation_count=len(violations),
        )

        return certificate


__all__ = [
    "LicenseFamily",
    "UseCase",
    "LicenseProfile",
    "CompatibilityResult",
    "AttributionRequirement",
    "ComplianceCertificate",
    "LicenseChecker",
]
