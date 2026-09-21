"""Extracts metadata from public PDFs, Office documents, and images."""

from __future__ import annotations

import asyncio
import io
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, RiskLevel

logger = logging.getLogger(__name__)

_UTC = timezone.utc
_MAX_FILE_BYTES = 10 * 1024 * 1024   # 10 MB maximum file size
_TIMEOUT = 15.0                        # Request timeout in seconds

# Supported document extensions
_PDF_EXTS    = {".pdf"}
_OFFICE_EXTS = {".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt"}
_IMAGE_EXTS  = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp"}
_ALL_EXTS    = _PDF_EXTS | _OFFICE_EXTS | _IMAGE_EXTS

# Common document paths to probe
_DOC_PATHS = [
    # PDFs
    "sample.pdf", "brochure.pdf", "report.pdf", "invoice.pdf",
    "terms.pdf", "privacy.pdf", "manual.pdf", "whitepaper.pdf",
    # Office docs
    "template.docx", "report.docx", "proposal.docx",
    "budget.xlsx", "financials.xlsx", "contacts.xlsx",
    # Images (EXIF)
    "photo.jpg", "image.jpg", "upload.jpg",
]

_SCHEMES = ["https", "http"]


class MetadataExtractorModule(BaseModule):
    """Downloads public document files and extracts embedded metadata."""

    MODULE_NAME = "metadata_extractor"

    def __init__(
        self,
        timeout: float = _TIMEOUT,
        max_concurrent: int = 8,
        extra_urls: list[str] | None = None,
    ) -> None:
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.extra_urls = extra_urls or []

    async def _run(self, target: str) -> list[Finding]:
        # Build URL list from common document paths
        urls: list[str] = list(self.extra_urls)
        for scheme in _SCHEMES:
            for path in _DOC_PATHS:
                urls.append(f"{scheme}://{target}/{path}")

        tasks = [self._process_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        findings: list[Finding] = []
        for result_list in results:
            findings.extend(result_list)
        return findings

    async def _process_url(self, url: str) -> list[Finding]:
        """Download URL if reachable and extract metadata."""
        async with self._semaphore:
            content, content_type = await self._download(url)

        if content is None:
            return []

        ext = self._detect_ext(url, content_type)
        if ext is None:
            return []

        findings: list[Finding] = []

        if ext in _PDF_EXTS:
            findings.extend(self._extract_pdf(url, content))
        elif ext in _OFFICE_EXTS:
            findings.extend(self._extract_office(url, content, ext))
        elif ext in _IMAGE_EXTS:
            findings.extend(self._extract_image(url, content))

        return findings

    async def _download(self, url: str) -> tuple[bytes | None, str]:
        """Check file size with HEAD then download content with GET."""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, verify=False
            ) as client:
                # HEAD first to check existence and size
                head = await client.head(url)
                if head.status_code != 200:
                    return None, ""

                cl = head.headers.get("content-length", "0")
                try:
                    if int(cl) > _MAX_FILE_BYTES:
                        logger.info("[metadata_extractor] %s too large (%s), skipping", url, cl)
                        return None, ""
                except (ValueError, TypeError):
                    pass

                ct = head.headers.get("content-type", "")

                # Only download file types we can parse
                ext = self._detect_ext(url, ct)
                if ext is None:
                    return None, ""

                # Download the file content
                resp = await client.get(url)
                if resp.status_code != 200:
                    return None, ""

                content = resp.content
                if len(content) > _MAX_FILE_BYTES:
                    logger.info("[metadata_extractor] %s download exceeded size limit, skipping", url)
                    return None, ""

                logger.info("[metadata_extractor] Downloaded %s (%d bytes)", url, len(content))
                return content, ct

        except httpx.TimeoutException:
            logger.debug("[metadata_extractor] Timeout: %s", url)
        except httpx.ConnectError:
            logger.debug("[metadata_extractor] Connect error: %s", url)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[metadata_extractor] Error downloading %s: %s", url, exc)

        return None, ""

    def _extract_pdf(self, url: str, content: bytes) -> list[Finding]:
        try:
            import pypdf
        except ImportError:
            logger.warning("[metadata_extractor] pypdf not installed; skipping PDF %s", url)
            return []

        findings: list[Finding] = []
        try:
            reader = pypdf.PdfReader(io.BytesIO(content))
            meta = reader.metadata
            if meta is None:
                return []

            fields = {
                "/Author":       ("pdf_author",   RiskLevel.MEDIUM, "PDF author field reveals person/org name"),
                "/Creator":      ("pdf_creator",  RiskLevel.LOW,    "PDF creator application"),
                "/Producer":     ("pdf_producer", RiskLevel.INFO,   "PDF producer library/version"),
                "/Title":        ("pdf_title",    RiskLevel.INFO,   "PDF title metadata"),
                "/Subject":      ("pdf_subject",  RiskLevel.INFO,   "PDF subject metadata"),
                "/Keywords":     ("pdf_keywords", RiskLevel.INFO,   "PDF keywords metadata"),
                "/CreationDate": ("pdf_created",  RiskLevel.INFO,   "PDF creation date"),
                "/ModDate":      ("pdf_modified", RiskLevel.LOW,    "PDF last-modified date"),
            }

            for key, (ftype, risk, desc) in fields.items():
                value = meta.get(key)
                if value and str(value).strip():
                    findings.append(Finding(
                        module_name=self.MODULE_NAME,
                        finding_type=ftype,
                        value=str(value).strip(),
                        extra={"url": url, "field": key, "source": "pdf_metadata", "note": desc},
                    ))

        except Exception as exc:  # noqa: BLE001
            logger.debug("[metadata_extractor] PDF parse failed for %s: %s", url, exc)

        return findings

    def _extract_office(self, url: str, content: bytes, ext: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            if ext == ".docx":
                import docx
                doc = docx.Document(io.BytesIO(content))
                props = doc.core_properties
            elif ext in (".xlsx", ".xls"):
                try:
                    import openpyxl
                    wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
                    props = wb.properties
                except ImportError:
                    logger.debug("[metadata_extractor] openpyxl not installed; skipping %s", url)
                    return []
            else:
                return []

            prop_map = {
                "author":           ("office_author",           RiskLevel.MEDIUM, "Document author name"),
                "last_modified_by": ("office_last_modified_by", RiskLevel.MEDIUM, "Last editor username"),
                "title":            ("office_title",            RiskLevel.INFO,   "Document title"),
                "subject":          ("office_subject",          RiskLevel.INFO,   "Document subject"),
                "keywords":         ("office_keywords",         RiskLevel.INFO,   "Document keywords"),
                "revision":         ("office_revision",         RiskLevel.INFO,   "Document revision number"),
            }

            for attr, (ftype, risk, desc) in prop_map.items():
                try:
                    value = getattr(props, attr, None)
                    if value and str(value).strip() and str(value) != "None":
                        findings.append(Finding(
                            module_name=self.MODULE_NAME,
                            finding_type=ftype,
                            value=str(value).strip(),
                            extra={"url": url, "field": attr, "source": "office_metadata", "note": desc},
                        ))
                except Exception:
                    pass

            # Extract company name from the raw XML properties
            try:
                cp_elem = props._element  # lxml element
                ns = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                company_elem = cp_elem.find(f"{{{ns}}}company")
                # Also check the extended app properties (app.xml) namespace
                if company_elem is None:
                    ns2 = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
                    company_elem = cp_elem.find(f"{{{ns2}}}Company")
                if company_elem is not None and company_elem.text and company_elem.text.strip():
                    findings.append(Finding(
                        module_name=self.MODULE_NAME,
                        finding_type="office_company",
                        value=company_elem.text.strip(),
                        extra={"url": url, "field": "company", "source": "office_metadata",
                               "note": "Company name in document properties"},
                    ))
            except Exception:
                pass  # Ignore missing company properties in some OOXML files

        except Exception as exc:  # noqa: BLE001
            logger.debug("[metadata_extractor] Office parse failed for %s: %s", url, exc)

        return findings

    def _extract_image(self, url: str, content: bytes) -> list[Finding]:
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
        except ImportError:
            logger.warning("[metadata_extractor] Pillow not installed; skipping image %s", url)
            return []

        findings: list[Finding] = []
        try:
            img = Image.open(io.BytesIO(content))
            exif_data = img._getexif()  # type: ignore[attr-defined]
            if exif_data is None:
                return []

            decoded: dict[str, Any] = {}
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, str(tag_id))
                decoded[tag] = value

            # GPS coordinates in image EXIF
            if "GPSInfo" in decoded:
                gps_raw = decoded["GPSInfo"]
                gps_decoded = {GPSTAGS.get(k, k): v for k, v in gps_raw.items()}
                lat = self._gps_decimal(
                    gps_decoded.get("GPSLatitude"), gps_decoded.get("GPSLatitudeRef")
                )
                lon = self._gps_decimal(
                    gps_decoded.get("GPSLongitude"), gps_decoded.get("GPSLongitudeRef")
                )
                if lat is not None and lon is not None:
                    findings.append(Finding(
                        module_name=self.MODULE_NAME,
                        finding_type="image_gps_coordinates",
                        value=f"{lat:.6f}, {lon:.6f}",
                        extra={
                            "url": url,
                            "latitude": lat,
                            "longitude": lon,
                            "maps_url": f"https://maps.google.com/?q={lat},{lon}",
                            "source": "image_exif",
                            "note": "GPS coordinates embedded in image",
                        },
                    ))

            # Common EXIF tags
            exif_fields = {
                "Make":             ("image_camera_make",   RiskLevel.INFO,   "Camera manufacturer"),
                "Model":            ("image_camera_model",  RiskLevel.INFO,   "Camera model"),
                "Software":         ("image_software",      RiskLevel.LOW,    "Software used to create/edit image"),
                "Artist":           ("image_artist",        RiskLevel.MEDIUM, "Artist/photographer name (PII)"),
                "Copyright":        ("image_copyright",     RiskLevel.LOW,    "Copyright notice"),
                "DateTimeOriginal": ("image_datetime",      RiskLevel.INFO,   "Original capture date/time"),
                "ImageDescription": ("image_description",   RiskLevel.INFO,   "Image description"),
            }

            for tag, (ftype, risk, desc) in exif_fields.items():
                value = decoded.get(tag)
                if value and str(value).strip():
                    findings.append(Finding(
                        module_name=self.MODULE_NAME,
                        finding_type=ftype,
                        value=str(value).strip(),
                        extra={"url": url, "exif_tag": tag, "source": "image_exif", "note": desc},
                    ))

        except Exception as exc:  # noqa: BLE001
            logger.debug("[metadata_extractor] Image EXIF failed for %s: %s", url, exc)

        return findings

    @staticmethod
    def _detect_ext(url: str, content_type: str) -> str | None:
        """Determine the file extension from URL path or Content-Type header."""
        from pathlib import PurePosixPath
        url_path = url.split("?")[0].split("#")[0]
        ext = PurePosixPath(url_path).suffix.lower()
        if ext in _ALL_EXTS:
            return ext

        # Fall back to Content-Type
        ct = content_type.lower()
        if "pdf" in ct:
            return ".pdf"
        if "jpeg" in ct or "jpg" in ct:
            return ".jpg"
        if "png" in ct:
            return ".png"
        if "word" in ct or "docx" in ct:
            return ".docx"
        if "spreadsheet" in ct or "excel" in ct:
            return ".xlsx"

        return None

    @staticmethod
    def _gps_decimal(coords, ref: str | None) -> float | None:
        """Convert GPS DMS tuple to decimal degrees."""
        if coords is None:
            return None
        try:
            d = float(coords[0])
            m = float(coords[1])
            s = float(coords[2])
            decimal = d + m / 60 + s / 3600
            if ref in ("S", "W"):
                decimal = -decimal
            return decimal
        except Exception:
            return None
