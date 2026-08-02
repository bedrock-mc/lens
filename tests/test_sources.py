from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from bedrock_lens.sources import (
    BDS_DOWNLOAD_API,
    STORE_DOWNLOAD_ENDPOINT,
    SourceResolutionError,
    build_store_download_request,
    parse_bds_download_links,
    parse_bds_download_url,
    parse_store_download_urls,
)


def test_store_request_targets_one_exact_update_identity() -> None:
    request = build_store_download_request(
        "cf4bd0ca-bcac-4b31-b09b-7973c61643d1", revision=1
    )
    root = ET.fromstring(request)
    values = [element.text for element in root.iter()]

    assert "cf4bd0ca-bcac-4b31-b09b-7973c61643d1" in values
    assert "1" in values
    assert STORE_DOWNLOAD_ENDPOINT in values


def test_store_response_extracts_only_delivery_urls() -> None:
    response = b'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
        xmlns:wu="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
      <s:Body><wu:GetExtendedUpdateInfo2Response><wu:GetExtendedUpdateInfo2Result>
        <wu:FileLocations>
          <wu:FileLocation><wu:Url>http://tlu.dl.delivery.mp.microsoft.com/a.appx</wu:Url></wu:FileLocation>
          <wu:FileLocation><wu:Url>https://example.invalid/not-store</wu:Url></wu:FileLocation>
        </wu:FileLocations>
      </wu:GetExtendedUpdateInfo2Result></wu:GetExtendedUpdateInfo2Response></s:Body>
    </s:Envelope>'''

    assert parse_store_download_urls(response) == (
        "http://tlu.dl.delivery.mp.microsoft.com/a.appx",
    )


def test_bds_page_parser_selects_the_requested_platform() -> None:
    html = '''
    <a href="https://www.minecraft.net/bedrockdedicatedserver/bin-win/server.zip">Windows</a>
    <a href="https://www.minecraft.net/bedrockdedicatedserver/bin-linux/server.zip">Ubuntu</a>
    '''

    assert parse_bds_download_url(html, "windows").endswith("bin-win/server.zip")
    assert parse_bds_download_url(html, "linux").endswith("bin-linux/server.zip")


def test_bds_api_response_selects_stable_windows_or_linux_link() -> None:
    response = b'''{
      "result": {"links": [
        {"downloadType": "serverBedrockWindows", "downloadUrl": "https://www.minecraft.net/bedrockdedicatedserver/bin-win/bedrock-server-1.26.36.1.zip"},
        {"downloadType": "serverBedrockLinux", "downloadUrl": "https://www.minecraft.net/bedrockdedicatedserver/bin-linux/bedrock-server-1.26.36.1.zip"},
        {"downloadType": "serverBedrockPreviewWindows", "downloadUrl": "https://www.minecraft.net/bedrockdedicatedserver/bin-win-preview/bedrock-server-1.26.50.22.zip"}
      ]}
    }'''

    assert BDS_DOWNLOAD_API.endswith("/api/v1.0/download/links")
    assert parse_bds_download_links(response, "windows").endswith(
        "bin-win/bedrock-server-1.26.36.1.zip"
    )
    assert parse_bds_download_links(response, "linux").endswith(
        "bin-linux/bedrock-server-1.26.36.1.zip"
    )
    assert parse_bds_download_links(response, "windows", preview=True).endswith(
        "bin-win-preview/bedrock-server-1.26.50.22.zip"
    )


@pytest.mark.parametrize("response", [b"[]", b'{"result": null}', b'{"result": {}}'])
def test_bds_api_response_rejects_missing_links(response: bytes) -> None:
    with pytest.raises(SourceResolutionError, match="official BDS API"):
        parse_bds_download_links(response, "windows")
