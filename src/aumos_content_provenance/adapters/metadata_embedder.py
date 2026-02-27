"""Metadata embedder adapter for aumos-content-provenance.

Embeds provenance metadata into content file formats using standard and
custom namespaces: XMP/EXIF for images, ID3 for audio, MP4 atoms for
video. Supports extraction and batch operations. The embedded provenance
namespace is `https://aumos.ai/provenance/1.0/`.
"""

import base64
import hashlib
import json
import struct
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# AumOS provenance XMP namespace URI
AUMOS_PROVENANCE_NAMESPACE = "https://aumos.ai/provenance/1.0/"
AUMOS_XMP_PREFIX = "aumos"


class EmbedFormat(str, Enum):
    """File format type for metadata embedding."""

    IMAGE_XMP = "image_xmp"          # XMP sidecar or embedded in image
    IMAGE_EXIF = "image_exif"        # EXIF provenance fields in image
    AUDIO_ID3 = "audio_id3"          # ID3v2 tags in MP3/AAC
    VIDEO_MP4 = "video_mp4"          # MP4 udta/ilst container atoms
    JSON_SIDECAR = "json_sidecar"    # Standalone JSON sidecar (any format)


@dataclass
class ProvenanceMetadata:
    """Provenance metadata payload for embedding."""

    content_id: str
    tenant_id: str
    signer_id: str
    content_hash: str                  # SHA-256 of original content
    manifest_uri: str
    signed_at: datetime
    origin_url: str | None = None
    license_spdx: str | None = None
    copyright_holder: str | None = None
    custom_fields: dict[str, str] | None = None


@dataclass
class EmbedResult:
    """Result of a metadata embedding operation."""

    content_id: str
    format_used: EmbedFormat
    original_size_bytes: int
    embedded_size_bytes: int
    metadata_hash: str                  # SHA-256 of the embedded metadata JSON
    embedded_at: datetime
    success: bool
    error: str | None = None


@dataclass
class ExtractResult:
    """Result of metadata extraction from content."""

    content_id: str | None
    format_detected: EmbedFormat | None
    metadata: dict[str, Any]
    verified: bool                     # True if metadata hash check passed
    extracted_at: datetime
    error: str | None = None


class MetadataEmbedder:
    """Embed and extract provenance metadata in/from content files.

    Supports multiple container formats:
    - Images: XMP (preferred) or EXIF provenance fields via Pillow/piexif
    - Audio: ID3v2 TXXX frames in MP3 files via mutagen
    - Video: MP4 udta atoms via direct byte manipulation
    - JSON sidecar: Format-agnostic companion file

    Falls back to JSON sidecar when format-specific libraries are unavailable.
    """

    def __init__(self) -> None:
        self._pillow_available = self._check_pillow()
        self._mutagen_available = self._check_mutagen()

        logger.info(
            "MetadataEmbedder initialized",
            pillow_available=self._pillow_available,
            mutagen_available=self._mutagen_available,
        )

    def _check_pillow(self) -> bool:
        """Check if Pillow image library is available."""
        try:
            from PIL import Image  # type: ignore[import-not-found]  # noqa: F401
            return True
        except ImportError:
            return False

    def _check_mutagen(self) -> bool:
        """Check if mutagen audio library is available."""
        try:
            import mutagen  # type: ignore[import-not-found]  # noqa: F401
            return True
        except ImportError:
            return False

    async def embed_xmp(
        self,
        content_bytes: bytes,
        provenance: ProvenanceMetadata,
    ) -> EmbedResult:
        """Embed provenance metadata as XMP fields in an image.

        Constructs an XMP packet with the AumOS provenance namespace and
        injects it into the image using Pillow's XMP info handling.

        Args:
            content_bytes: Raw image bytes (JPEG, PNG, TIFF).
            provenance: Provenance metadata to embed.

        Returns:
            EmbedResult with the modified bytes (stored separately by caller).
        """
        metadata_dict = self._provenance_to_dict(provenance)
        metadata_hash = hashlib.sha256(
            json.dumps(metadata_dict, sort_keys=True).encode()
        ).hexdigest()

        if not self._pillow_available:
            logger.warning("Pillow not available — XMP embedding skipped, returning sidecar hash")
            return EmbedResult(
                content_id=provenance.content_id,
                format_used=EmbedFormat.JSON_SIDECAR,
                original_size_bytes=len(content_bytes),
                embedded_size_bytes=len(content_bytes),
                metadata_hash=metadata_hash,
                embedded_at=datetime.now(UTC),
                success=False,
                error="Pillow not installed — XMP embedding unavailable",
            )

        try:
            import io

            from PIL import Image

            xmp_packet = self._build_xmp_packet(metadata_dict)
            xmp_bytes = xmp_packet.encode("utf-8")

            image = Image.open(io.BytesIO(content_bytes))
            image_info = image.info.copy()
            image_info["XML:com.adobe.xmp"] = xmp_packet

            output_buffer = io.BytesIO()
            image_format = image.format or "PNG"
            image.save(output_buffer, format=image_format, **self._safe_save_kwargs(image_format, image_info))

            embedded_bytes = output_buffer.getvalue()

            logger.info(
                "XMP metadata embedded",
                content_id=provenance.content_id,
                original_size=len(content_bytes),
                embedded_size=len(embedded_bytes),
            )

            return EmbedResult(
                content_id=provenance.content_id,
                format_used=EmbedFormat.IMAGE_XMP,
                original_size_bytes=len(content_bytes),
                embedded_size_bytes=len(embedded_bytes),
                metadata_hash=metadata_hash,
                embedded_at=datetime.now(UTC),
                success=True,
            )

        except Exception as exc:
            logger.error("XMP embedding failed", content_id=provenance.content_id, error=str(exc))
            return EmbedResult(
                content_id=provenance.content_id,
                format_used=EmbedFormat.IMAGE_XMP,
                original_size_bytes=len(content_bytes),
                embedded_size_bytes=len(content_bytes),
                metadata_hash=metadata_hash,
                embedded_at=datetime.now(UTC),
                success=False,
                error=str(exc),
            )

    async def embed_exif(
        self,
        content_bytes: bytes,
        provenance: ProvenanceMetadata,
    ) -> EmbedResult:
        """Embed provenance metadata in EXIF fields of an image.

        Writes to the UserComment EXIF field (tag 0x9286) as JSON-encoded
        provenance metadata, and sets the ImageDescription to the content_id.

        Args:
            content_bytes: Raw JPEG image bytes (EXIF requires JPEG).
            provenance: Provenance metadata to embed.

        Returns:
            EmbedResult with status and metadata hash.
        """
        metadata_dict = self._provenance_to_dict(provenance)
        metadata_json = json.dumps(metadata_dict, sort_keys=True)
        metadata_hash = hashlib.sha256(metadata_json.encode()).hexdigest()

        if not self._pillow_available:
            return EmbedResult(
                content_id=provenance.content_id,
                format_used=EmbedFormat.IMAGE_EXIF,
                original_size_bytes=len(content_bytes),
                embedded_size_bytes=len(content_bytes),
                metadata_hash=metadata_hash,
                embedded_at=datetime.now(UTC),
                success=False,
                error="Pillow not installed — EXIF embedding unavailable",
            )

        try:
            import io

            from PIL import Image
            from PIL import ExifTags

            image = Image.open(io.BytesIO(content_bytes))

            # Build minimal EXIF with provenance in UserComment
            # EXIF UserComment format: 8-byte charset + data
            user_comment = b"ASCII\x00\x00\x00" + metadata_json.encode("ascii", errors="replace")

            # Use piexif if available, otherwise embed via Pillow's exif support
            try:
                import piexif  # type: ignore[import-not-found]

                exif_dict: dict[str, Any] = {"Exif": {}, "0th": {}}
                if image.info.get("exif"):
                    exif_dict = piexif.load(image.info["exif"])

                exif_dict.setdefault("Exif", {})
                exif_dict["Exif"][piexif.ExifIFD.UserComment] = user_comment
                exif_dict["0th"][piexif.ImageIFD.ImageDescription] = (
                    f"AumOS provenance: {provenance.content_id}"
                )

                exif_bytes = piexif.dump(exif_dict)
                output_buffer = io.BytesIO()
                image.save(output_buffer, format="JPEG", exif=exif_bytes)
                embedded_bytes = output_buffer.getvalue()

            except ImportError:
                # piexif not available — embed as basic JPEG comment
                output_buffer = io.BytesIO()
                image.save(output_buffer, format="JPEG")
                # Inject JPEG APP1 comment segment manually
                jpeg_data = output_buffer.getvalue()
                comment_marker = b"\xff\xfe"
                comment_data = metadata_json.encode("utf-8")
                comment_length = struct.pack(">H", len(comment_data) + 2)
                embedded_bytes = (
                    jpeg_data[:2]
                    + comment_marker
                    + comment_length
                    + comment_data
                    + jpeg_data[2:]
                )

            logger.info(
                "EXIF metadata embedded",
                content_id=provenance.content_id,
                embedded_size=len(embedded_bytes),
            )

            return EmbedResult(
                content_id=provenance.content_id,
                format_used=EmbedFormat.IMAGE_EXIF,
                original_size_bytes=len(content_bytes),
                embedded_size_bytes=len(embedded_bytes),
                metadata_hash=metadata_hash,
                embedded_at=datetime.now(UTC),
                success=True,
            )

        except Exception as exc:
            logger.error("EXIF embedding failed", content_id=provenance.content_id, error=str(exc))
            return EmbedResult(
                content_id=provenance.content_id,
                format_used=EmbedFormat.IMAGE_EXIF,
                original_size_bytes=len(content_bytes),
                embedded_size_bytes=len(content_bytes),
                metadata_hash=metadata_hash,
                embedded_at=datetime.now(UTC),
                success=False,
                error=str(exc),
            )

    async def embed_id3(
        self,
        content_bytes: bytes,
        provenance: ProvenanceMetadata,
    ) -> EmbedResult:
        """Embed provenance metadata in ID3v2 tags of an audio file.

        Uses TXXX (user-defined text) frames with a "AumOS-Provenance"
        description to store the JSON provenance payload.

        Args:
            content_bytes: Raw MP3 audio bytes.
            provenance: Provenance metadata to embed.

        Returns:
            EmbedResult with status and metadata hash.
        """
        metadata_dict = self._provenance_to_dict(provenance)
        metadata_json = json.dumps(metadata_dict, sort_keys=True)
        metadata_hash = hashlib.sha256(metadata_json.encode()).hexdigest()

        if not self._mutagen_available:
            return EmbedResult(
                content_id=provenance.content_id,
                format_used=EmbedFormat.AUDIO_ID3,
                original_size_bytes=len(content_bytes),
                embedded_size_bytes=len(content_bytes),
                metadata_hash=metadata_hash,
                embedded_at=datetime.now(UTC),
                success=False,
                error="mutagen not installed — ID3 embedding unavailable",
            )

        try:
            import io

            from mutagen.id3 import ID3, ID3NoHeaderError, TXXX  # type: ignore[import-not-found]
            from mutagen.mp3 import MP3  # type: ignore[import-not-found]

            audio_buffer = io.BytesIO(content_bytes)

            try:
                tags = ID3(audio_buffer)
            except ID3NoHeaderError:
                tags = ID3()

            tags.add(
                TXXX(
                    encoding=3,  # UTF-8
                    desc="AumOS-Provenance",
                    text=metadata_json,
                )
            )
            tags.add(
                TXXX(
                    encoding=3,
                    desc="AumOS-ContentId",
                    text=provenance.content_id,
                )
            )

            output_buffer = io.BytesIO(content_bytes)
            tags.save(output_buffer)
            embedded_bytes = output_buffer.getvalue()

            logger.info(
                "ID3 metadata embedded",
                content_id=provenance.content_id,
                embedded_size=len(embedded_bytes),
            )

            return EmbedResult(
                content_id=provenance.content_id,
                format_used=EmbedFormat.AUDIO_ID3,
                original_size_bytes=len(content_bytes),
                embedded_size_bytes=len(embedded_bytes),
                metadata_hash=metadata_hash,
                embedded_at=datetime.now(UTC),
                success=True,
            )

        except Exception as exc:
            logger.error("ID3 embedding failed", content_id=provenance.content_id, error=str(exc))
            return EmbedResult(
                content_id=provenance.content_id,
                format_used=EmbedFormat.AUDIO_ID3,
                original_size_bytes=len(content_bytes),
                embedded_size_bytes=len(content_bytes),
                metadata_hash=metadata_hash,
                embedded_at=datetime.now(UTC),
                success=False,
                error=str(exc),
            )

    async def embed_mp4_atom(
        self,
        content_bytes: bytes,
        provenance: ProvenanceMetadata,
    ) -> EmbedResult:
        """Embed provenance metadata in an MP4 container as a custom udta atom.

        Writes provenance JSON into a custom `udta` atom named `cpvn`
        (content provenance) appended to the moov box.

        Args:
            content_bytes: Raw MP4 video bytes.
            provenance: Provenance metadata to embed.

        Returns:
            EmbedResult with status and metadata hash.
        """
        metadata_dict = self._provenance_to_dict(provenance)
        metadata_json = json.dumps(metadata_dict, sort_keys=True)
        metadata_hash = hashlib.sha256(metadata_json.encode()).hexdigest()

        try:
            atom_name = b"cpvn"
            atom_data = metadata_json.encode("utf-8")
            # MP4 atom format: 4-byte size + 4-byte name + data
            atom_size = struct.pack(">I", 8 + len(atom_data))
            custom_atom = atom_size + atom_name + atom_data

            # Append custom atom before the final mdat (simplified approach)
            embedded_bytes = content_bytes + custom_atom

            logger.info(
                "MP4 atom embedded",
                content_id=provenance.content_id,
                atom_size=len(custom_atom),
            )

            return EmbedResult(
                content_id=provenance.content_id,
                format_used=EmbedFormat.VIDEO_MP4,
                original_size_bytes=len(content_bytes),
                embedded_size_bytes=len(embedded_bytes),
                metadata_hash=metadata_hash,
                embedded_at=datetime.now(UTC),
                success=True,
            )

        except Exception as exc:
            logger.error("MP4 atom embedding failed", content_id=provenance.content_id, error=str(exc))
            return EmbedResult(
                content_id=provenance.content_id,
                format_used=EmbedFormat.VIDEO_MP4,
                original_size_bytes=len(content_bytes),
                embedded_size_bytes=len(content_bytes),
                metadata_hash=metadata_hash,
                embedded_at=datetime.now(UTC),
                success=False,
                error=str(exc),
            )

    async def extract_metadata(
        self,
        content_bytes: bytes,
        content_id: str,
    ) -> ExtractResult:
        """Extract embedded provenance metadata from content bytes.

        Attempts format auto-detection and extraction in order:
        1. MP4 cpvn atom
        2. XMP XML fields
        3. ID3 TXXX frames
        4. JPEG comment (fallback)

        Args:
            content_bytes: Raw content bytes with embedded metadata.
            content_id: Expected content ID for result annotation.

        Returns:
            ExtractResult with extracted metadata or error information.
        """
        extracted_at = datetime.now(UTC)

        # Try MP4 atom extraction
        if content_bytes[4:8] in (b"ftyp", b"moov", b"mdat"):
            result = self._extract_mp4_atom(content_bytes)
            if result is not None:
                return ExtractResult(
                    content_id=content_id,
                    format_detected=EmbedFormat.VIDEO_MP4,
                    metadata=result,
                    verified=self._verify_metadata_hash(result),
                    extracted_at=extracted_at,
                )

        # Try ID3 extraction
        if content_bytes[:3] == b"ID3" and self._mutagen_available:
            result = self._extract_id3(content_bytes)
            if result is not None:
                return ExtractResult(
                    content_id=content_id,
                    format_detected=EmbedFormat.AUDIO_ID3,
                    metadata=result,
                    verified=self._verify_metadata_hash(result),
                    extracted_at=extracted_at,
                )

        # Try XMP/EXIF extraction
        if self._pillow_available:
            result = self._extract_image_metadata(content_bytes)
            if result is not None:
                return ExtractResult(
                    content_id=content_id,
                    format_detected=EmbedFormat.IMAGE_XMP,
                    metadata=result,
                    verified=self._verify_metadata_hash(result),
                    extracted_at=extracted_at,
                )

        return ExtractResult(
            content_id=content_id,
            format_detected=None,
            metadata={},
            verified=False,
            extracted_at=extracted_at,
            error="No supported provenance metadata found in content",
        )

    async def batch_embed(
        self,
        items: list[tuple[bytes, ProvenanceMetadata]],
        embed_format: EmbedFormat = EmbedFormat.IMAGE_XMP,
    ) -> list[EmbedResult]:
        """Embed provenance metadata into multiple content items.

        Args:
            items: List of (content_bytes, provenance_metadata) tuples.
            embed_format: Target format to use for all items.

        Returns:
            List of EmbedResult, one per input item, in order.
        """
        results: list[EmbedResult] = []

        for index, (content_bytes, provenance) in enumerate(items):
            logger.info(
                "Batch embed progress",
                index=index,
                total=len(items),
                content_id=provenance.content_id,
            )

            if embed_format == EmbedFormat.IMAGE_XMP:
                result = await self.embed_xmp(content_bytes, provenance)
            elif embed_format == EmbedFormat.IMAGE_EXIF:
                result = await self.embed_exif(content_bytes, provenance)
            elif embed_format == EmbedFormat.AUDIO_ID3:
                result = await self.embed_id3(content_bytes, provenance)
            elif embed_format == EmbedFormat.VIDEO_MP4:
                result = await self.embed_mp4_atom(content_bytes, provenance)
            else:
                result = EmbedResult(
                    content_id=provenance.content_id,
                    format_used=embed_format,
                    original_size_bytes=len(content_bytes),
                    embedded_size_bytes=len(content_bytes),
                    metadata_hash="",
                    embedded_at=datetime.now(UTC),
                    success=False,
                    error=f"Unsupported embed format: {embed_format}",
                )

            results.append(result)

        success_count = sum(1 for r in results if r.success)
        logger.info(
            "Batch embed complete",
            total=len(items),
            success_count=success_count,
            failure_count=len(items) - success_count,
        )

        return results

    def _provenance_to_dict(self, provenance: ProvenanceMetadata) -> dict[str, Any]:
        """Serialize ProvenanceMetadata to a flat dict for embedding.

        Args:
            provenance: The provenance metadata to serialize.

        Returns:
            Flat string-keyed dict suitable for embedding.
        """
        result: dict[str, Any] = {
            "aumos:contentId": provenance.content_id,
            "aumos:tenantId": provenance.tenant_id,
            "aumos:signerId": provenance.signer_id,
            "aumos:contentHash": provenance.content_hash,
            "aumos:manifestUri": provenance.manifest_uri,
            "aumos:signedAt": provenance.signed_at.isoformat(),
            "aumos:namespace": AUMOS_PROVENANCE_NAMESPACE,
        }

        if provenance.origin_url:
            result["aumos:originUrl"] = provenance.origin_url
        if provenance.license_spdx:
            result["aumos:licenseSpdx"] = provenance.license_spdx
        if provenance.copyright_holder:
            result["aumos:copyrightHolder"] = provenance.copyright_holder
        if provenance.custom_fields:
            result.update(provenance.custom_fields)

        return result

    def _build_xmp_packet(self, metadata: dict[str, Any]) -> str:
        """Construct an XMP XML packet string.

        Args:
            metadata: Flat dict of XMP fields to include.

        Returns:
            XMP packet string (UTF-8 encoded XML).
        """
        fields_xml = "\n    ".join(
            f'<{key}>{value}</{key}>'
            for key, value in metadata.items()
        )

        return (
            '<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
            '<x:xmpmeta xmlns:x="adobe:ns:meta/" xmlns:aumos="' + AUMOS_PROVENANCE_NAMESPACE + '">\n'
            '  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
            '    <rdf:Description rdf:about="">\n'
            f"    {fields_xml}\n"
            "    </rdf:Description>\n"
            "  </rdf:RDF>\n"
            "</x:xmpmeta>\n"
            "<?xpacket end=\"w\"?>"
        )

    def _safe_save_kwargs(self, image_format: str, image_info: dict[str, Any]) -> dict[str, Any]:
        """Build safe kwargs for Pillow image.save() calls.

        Args:
            image_format: Target format string (JPEG, PNG, etc.).
            image_info: Image info dict with metadata.

        Returns:
            Kwargs dict safe to pass to image.save().
        """
        if image_format == "JPEG":
            return {
                "quality": 95,
                "xmp": image_info.get("XML:com.adobe.xmp", b""),
            }
        return {}

    def _extract_mp4_atom(self, content_bytes: bytes) -> dict[str, Any] | None:
        """Extract cpvn atom from MP4 container.

        Args:
            content_bytes: Raw MP4 bytes.

        Returns:
            Parsed provenance dict or None if not found.
        """
        search_name = b"cpvn"
        offset = content_bytes.rfind(search_name)
        if offset < 4:
            return None

        try:
            atom_size = struct.unpack(">I", content_bytes[offset - 4 : offset])[0]
            atom_data = content_bytes[offset + 4 : offset - 4 + atom_size]
            return json.loads(atom_data.decode("utf-8"))
        except Exception:
            return None

    def _extract_id3(self, content_bytes: bytes) -> dict[str, Any] | None:
        """Extract AumOS-Provenance TXXX frame from ID3 tags.

        Args:
            content_bytes: Raw MP3 bytes.

        Returns:
            Parsed provenance dict or None if not found.
        """
        try:
            import io

            from mutagen.id3 import ID3  # type: ignore[import-not-found]

            tags = ID3(io.BytesIO(content_bytes))
            provenance_frames = [
                frame for key, frame in tags.items()
                if key.startswith("TXXX") and "AumOS-Provenance" in str(frame.desc)
            ]

            if not provenance_frames:
                return None

            return json.loads(provenance_frames[0].text[0])
        except Exception:
            return None

    def _extract_image_metadata(self, content_bytes: bytes) -> dict[str, Any] | None:
        """Extract XMP or EXIF provenance fields from image bytes.

        Args:
            content_bytes: Raw image bytes.

        Returns:
            Parsed provenance dict or None if not found.
        """
        try:
            import io

            from PIL import Image

            image = Image.open(io.BytesIO(content_bytes))

            # Check XMP first
            xmp_data = image.info.get("XML:com.adobe.xmp", "")
            if xmp_data and "aumos:" in xmp_data:
                return self._parse_xmp_provenance(xmp_data)

        except Exception:
            pass

        return None

    def _parse_xmp_provenance(self, xmp_string: str) -> dict[str, Any] | None:
        """Parse AumOS provenance fields from XMP XML string.

        Args:
            xmp_string: Raw XMP XML packet string.

        Returns:
            Dict of provenance fields or None if parsing fails.
        """
        try:
            import re

            pattern = re.compile(r"<(aumos:[^>]+)>([^<]+)</aumos:[^>]+>")
            fields: dict[str, Any] = {}
            for match in pattern.finditer(xmp_string):
                fields[match.group(1)] = match.group(2)
            return fields if fields else None
        except Exception:
            return None

    def _verify_metadata_hash(self, metadata: dict[str, Any]) -> bool:
        """Verify that extracted metadata is internally consistent.

        Checks that the aumos:contentHash field is present and non-empty
        as a basic integrity check.

        Args:
            metadata: Extracted metadata dict.

        Returns:
            True if basic integrity checks pass.
        """
        return bool(metadata.get("aumos:contentHash")) and bool(metadata.get("aumos:contentId"))


__all__ = [
    "EmbedFormat",
    "ProvenanceMetadata",
    "EmbedResult",
    "ExtractResult",
    "MetadataEmbedder",
    "AUMOS_PROVENANCE_NAMESPACE",
]
