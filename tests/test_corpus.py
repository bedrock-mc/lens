from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from bedrock_lens.corpus import CorpusFetcher, VerificationError, load_manifest

from .test_pe import write_pe_with_rsds


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fixture_manifest(tmp_path: Path) -> tuple[Path, Path]:
    binary = tmp_path / "source" / "Minecraft.Windows.exe"
    binary.parent.mkdir()
    write_pe_with_rsds(binary)
    archive = tmp_path / "source" / "client.appx"
    with zipfile.ZipFile(archive, "w") as package:
        package.write(binary, "Minecraft.Windows.exe")

    manifest = tmp_path / "corpus.toml"
    manifest.write_text(
        f'''schema = 1

[[artifact]]
id = "client-1.20.40.1-x64"
version = "1.20.40.1"
kind = "client"
channel = "retail"
archive_sha256 = "{_sha256(archive)}"
binary_sha256 = "{_sha256(binary)}"
member = "Minecraft.Windows.exe"
pdb_guid = "603c336c-4fcb-4ec3-b5e2-ecb754278979"

[artifact.source]
type = "url"
url = "{archive.as_uri()}"
''',
        encoding="utf-8",
    )
    return manifest, archive


def test_fetch_verifies_extracts_and_reuses_content_addressed_cache(tmp_path: Path) -> None:
    manifest_path, archive = _fixture_manifest(tmp_path)
    spec = load_manifest(manifest_path).artifact("client-1.20.40.1-x64")
    fetcher = CorpusFetcher(tmp_path / "cache")

    first = fetcher.fetch(spec)

    assert first.binary_path.name == "Minecraft.Windows.exe"
    assert first.binary_path.read_bytes().startswith(b"MZ")
    assert first.archive_path.parent.name == "sha256"
    assert not first.cache_hit

    archive.unlink()
    second = fetcher.fetch(spec)

    assert second.binary_path == first.binary_path
    assert second.cache_hit


def test_fetch_rejects_a_binary_hash_mismatch(tmp_path: Path) -> None:
    manifest_path, _ = _fixture_manifest(tmp_path)
    text = manifest_path.read_text(encoding="utf-8")
    text = text.replace("binary_sha256 = \"", f'binary_sha256 = "{"0" * 64}')
    # Remove the original hash suffix left by the simple replacement.
    lines = text.splitlines()
    lines = [
        f'binary_sha256 = "{"0" * 64}"' if line.startswith("binary_sha256") else line
        for line in lines
    ]
    manifest_path.write_text("\n".join(lines), encoding="utf-8")
    spec = load_manifest(manifest_path).artifacts[0]

    with pytest.raises(VerificationError, match="binary SHA-256"):
        CorpusFetcher(tmp_path / "cache").fetch(spec)


def test_manifest_rejects_non_sha256_digests(tmp_path: Path) -> None:
    manifest = tmp_path / "bad.toml"
    manifest.write_text(
        '''schema = 1
[[artifact]]
id = "bad"
version = "1.0.0"
kind = "client"
archive_sha256 = "abc"
binary_sha256 = "def"
member = "Minecraft.Windows.exe"
[artifact.source]
type = "url"
url = "https://example.invalid/client.appx"
''',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="SHA-256"):
        load_manifest(manifest)


def test_manifest_accepts_a_bds_latest_source(tmp_path: Path) -> None:
    manifest = tmp_path / "bds.toml"
    manifest.write_text(
        '''schema = 1
[[artifact]]
id = "server-latest-windows"
version = "1.26.36.1"
kind = "server"
archive_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
binary_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
member = "bedrock_server.exe"
[artifact.source]
type = "bds_latest"
platform = "windows"
''',
        encoding="utf-8",
    )

    spec = load_manifest(manifest).artifacts[0]
    assert spec.source.type == "bds_latest"
    assert spec.source.platform == "windows"
