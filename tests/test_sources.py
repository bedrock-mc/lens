from __future__ import annotations

import xml.etree.ElementTree as ET

from bedrock_lens.sources import (
    STORE_DOWNLOAD_ENDPOINT,
    build_store_download_request,
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
