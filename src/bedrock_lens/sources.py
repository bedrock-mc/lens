"""Network source resolvers for Bedrock corpus packages."""

from __future__ import annotations

import json
import ssl
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import certifi

STORE_DOWNLOAD_ENDPOINT = (
    "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured"
)
BDS_DOWNLOAD_API = "https://net-secondary.web.minecraft-services.net/api/v1.0/download/links"
BDS_DOWNLOAD_PAGE = "https://www.minecraft.net/en-us/download/server/bedrock"

_SOAP = "http://www.w3.org/2003/05/soap-envelope"
_ADDRESSING = "http://www.w3.org/2005/08/addressing"
_SECURITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
_UTILITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
_AUTHORIZATION = "http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"
_WU = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"


class SourceResolutionError(RuntimeError):
    """Raised when a package URL cannot be resolved from its upstream source."""


def tls_context() -> ssl.SSLContext:
    """Return public Web PKI roots plus Microsoft's documented Windows Update root."""
    context = ssl.create_default_context(cafile=certifi.where())
    update_root = Path(__file__).with_name("microsoft_root_ca_2011.pem")
    context.load_verify_locations(cafile=update_root)
    return context


def _open(request: Request, *, timeout: float):
    return urlopen(request, timeout=timeout, context=tls_context())


def _tag(namespace: str, name: str) -> str:
    return f"{{{namespace}}}{name}"


def build_store_download_request(update_id: str, *, revision: int = 1) -> bytes:
    """Build a Windows Update request for the files of one Store update."""
    uuid.UUID(update_id)
    if revision < 1:
        raise ValueError("Store revision must be positive")

    ET.register_namespace("s", _SOAP)
    ET.register_namespace("a", _ADDRESSING)
    envelope = ET.Element(_tag(_SOAP, "Envelope"))
    header = ET.SubElement(envelope, _tag(_SOAP, "Header"))
    action = ET.SubElement(header, _tag(_ADDRESSING, "Action"))
    action.set(_tag(_SOAP, "mustUnderstand"), "1")
    action.text = f"{_WU}/GetExtendedUpdateInfo2"
    ET.SubElement(header, _tag(_ADDRESSING, "MessageID")).text = f"urn:uuid:{uuid.uuid4()}"
    target = ET.SubElement(header, _tag(_ADDRESSING, "To"))
    target.set(_tag(_SOAP, "mustUnderstand"), "1")
    target.text = STORE_DOWNLOAD_ENDPOINT

    security = ET.SubElement(header, _tag(_SECURITY, "Security"))
    security.set(_tag(_SOAP, "mustUnderstand"), "1")
    timestamp = ET.SubElement(security, _tag(_UTILITY, "Timestamp"))
    now = datetime.now(UTC)
    ET.SubElement(timestamp, _tag(_UTILITY, "Created")).text = now.isoformat()
    ET.SubElement(timestamp, _tag(_UTILITY, "Expires")).text = (
        now + timedelta(minutes=5)
    ).isoformat()
    tickets = ET.SubElement(security, _tag(_AUTHORIZATION, "WindowsUpdateTicketsToken"))
    tickets.set(_tag(_UTILITY, "id"), "ClientMSA")
    aad = ET.SubElement(tickets, "TicketType")
    aad.set("Name", "AAD")
    aad.set("Version", "1.0")
    aad.set("Policy", "MBI_SSL")

    body = ET.SubElement(envelope, _tag(_SOAP, "Body"))
    operation = ET.SubElement(body, _tag(_WU, "GetExtendedUpdateInfo2"))
    update_ids = ET.SubElement(operation, _tag(_WU, "updateIDs"))
    identity = ET.SubElement(update_ids, _tag(_WU, "UpdateIdentity"))
    ET.SubElement(identity, _tag(_WU, "UpdateID")).text = update_id
    ET.SubElement(identity, _tag(_WU, "RevisionNumber")).text = str(revision)
    info_types = ET.SubElement(operation, _tag(_WU, "infoTypes"))
    ET.SubElement(info_types, _tag(_WU, "XmlUpdateFragmentType")).text = "FileUrl"
    ET.SubElement(operation, _tag(_WU, "deviceAttributes")).text = (
        "E:BranchReadinessLevel=CB&FlightRing=Retail&InstallLanguage=en-US&"
        "OSArchitecture=AMD64&OSVersion=10.0.22621.0&DeviceFamily=Windows.Desktop"
    )
    return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)


def parse_store_download_urls(response: bytes) -> tuple[str, ...]:
    """Extract Microsoft delivery URLs from a GetExtendedUpdateInfo2 response."""
    try:
        root = ET.fromstring(response)
    except ET.ParseError as exc:
        raise SourceResolutionError("Microsoft Store returned invalid XML") from exc

    urls: list[str] = []
    for element in root.iter(_tag(_WU, "Url")):
        if not element.text:
            continue
        parsed = urlparse(element.text)
        host = (parsed.hostname or "").lower()
        if parsed.scheme in {"http", "https"} and host.endswith("delivery.mp.microsoft.com"):
            urls.append(element.text)
    return tuple(urls)


def resolve_store_download_url(
    update_id: str,
    *,
    revision: int = 1,
    timeout: float = 60,
) -> str:
    """Resolve an expiring package URL for one Microsoft Store update identity."""
    request = Request(
        STORE_DOWNLOAD_ENDPOINT,
        data=build_store_download_request(update_id, revision=revision),
        headers={
            "Content-Type": "application/soap+xml; charset=utf-8",
            "User-Agent": "Bedrock-Lens/0.1",
        },
        method="POST",
    )
    with _open(request, timeout=timeout) as response:
        payload = response.read()
    urls = parse_store_download_urls(payload)
    if not urls:
        raise SourceResolutionError(
            f"Microsoft Store returned no package URL for update {update_id} revision {revision}"
        )
    return urls[0]


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = next((value for name, value in attrs if name.lower() == "href"), None)
        if href:
            self.links.append(href)


def parse_bds_download_url(page: str, platform: str) -> str:
    """Select the current official BDS ZIP URL from the Minecraft download page."""
    directory = {"windows": "bin-win", "linux": "bin-linux"}.get(platform)
    if directory is None:
        raise ValueError("BDS platform must be 'windows' or 'linux'")
    parser = _LinkParser()
    parser.feed(page)
    for link in parser.links:
        parsed = urlparse(link)
        if (
            parsed.scheme == "https"
            and parsed.hostname in {"www.minecraft.net", "minecraft.azureedge.net"}
            and f"/{directory}/" in parsed.path
            and parsed.path.lower().endswith(".zip")
        ):
            return link
    raise SourceResolutionError(f"official BDS page has no {platform} download link")


def parse_bds_download_links(response: bytes, platform: str, *, preview: bool = False) -> str:
    """Select a stable or preview BDS URL from Minecraft's official download API."""
    if platform not in {"windows", "linux"}:
        raise ValueError("BDS platform must be 'windows' or 'linux'")
    download_type = "serverBedrock"
    if preview:
        download_type += "Preview"
    download_type += platform.capitalize()
    try:
        payload = json.loads(response)
    except json.JSONDecodeError as exc:
        raise SourceResolutionError("official BDS API returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise SourceResolutionError("official BDS API returned an invalid response object")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise SourceResolutionError("official BDS API returned no result object")
    links = result.get("links", [])
    if not isinstance(links, list):
        raise SourceResolutionError("official BDS API returned no links array")
    for link in links:
        if not isinstance(link, dict) or link.get("downloadType") != download_type:
            continue
        value = link.get("downloadUrl")
        if not isinstance(value, str):
            continue
        parsed = urlparse(value)
        if (
            parsed.scheme == "https"
            and parsed.hostname in {"www.minecraft.net", "minecraft.azureedge.net"}
            and parsed.path.lower().endswith(".zip")
        ):
            return value
    raise SourceResolutionError(
        f"official BDS API has no {'preview ' if preview else ''}{platform} download link"
    )


def resolve_bds_download_url(
    platform: str, *, preview: bool = False, timeout: float = 30
) -> str:
    request = Request(
        BDS_DOWNLOAD_API,
        headers={
            "Accept": "application/json",
            "Accept-Language": "*",
            "User-Agent": "Bedrock-Lens/0.1",
        },
    )
    with _open(request, timeout=timeout) as response:
        payload = response.read()
    return parse_bds_download_links(payload, platform, preview=preview)


def resolve_latest_bds_url(platform: str, *, timeout: float = 30) -> str:
    """Resolve the current stable BDS URL from Microsoft's download service."""
    return resolve_bds_download_url(platform, timeout=timeout)
