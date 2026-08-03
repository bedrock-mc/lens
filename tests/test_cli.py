from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from bedrock_lens.catalog import Catalog
from bedrock_lens.cli import _analysis_project_dir, _parser, main
from bedrock_lens.evidence import FunctionEvidence

from .test_pe import write_pe_with_rsds


def test_default_analysis_project_avoids_hidden_catalog_directory(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    arguments = _parser().parse_args(
        ["--database", str(tmp_path / ".lens" / "lens.db"), "analyze", "1"]
    )

    assert _analysis_project_dir(arguments) == tmp_path / "ghidra-projects"


def test_add_then_list_emits_machine_readable_artifact(tmp_path: Path, capsys) -> None:
    binary = tmp_path / "Minecraft.Windows.exe"
    database = tmp_path / "lens.db"
    write_pe_with_rsds(binary)

    assert (
        main(
            [
                "--database",
                str(database),
                "add",
                str(binary),
                "--version",
                "1.20.40.1",
                "--kind",
                "client",
            ]
        )
        == 0
    )
    added = json.loads(capsys.readouterr().out)

    assert added["version"] == "1.20.40.1"
    assert added["pdb"]["name"] == "Minecraft.Windows.pdb"

    assert main(["--database", str(database), "list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed == [added]


def test_search_emits_versioned_function_hits(tmp_path: Path, capsys) -> None:
    binary = tmp_path / "bedrock_server.exe"
    database = tmp_path / "lens.db"
    write_pe_with_rsds(binary)
    with Catalog(database) as catalog:
        artifact = catalog.register(binary, version="1.20.40.1", kind="server")
        catalog.replace_function_evidence(
            artifact.id,
            [
                FunctionEvidence(
                    rva=0x1870C60,
                    name="CrossbowItem::CrossbowItem",
                    namespace="CrossbowItem",
                    size=173,
                    parameter_count=2,
                )
            ],
        )

    assert main(["--database", str(database), "search", "crossbow"]) == 0
    hits = json.loads(capsys.readouterr().out)

    assert hits[0]["artifact_id"] == artifact.id
    assert hits[0]["version"] == "1.20.40.1"
    assert hits[0]["rva"] == "0x1870c60"
    assert hits[0]["name"] == "CrossbowItem::CrossbowItem"


def test_fetch_registers_a_manifest_artifact(tmp_path: Path, capsys) -> None:
    binary = tmp_path / "source" / "Minecraft.Windows.exe"
    binary.parent.mkdir()
    write_pe_with_rsds(binary)
    package = tmp_path / "source" / "client.appx"
    with zipfile.ZipFile(package, "w") as archive:
        archive.write(binary, binary.name)

    def sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    manifest = tmp_path / "corpus.toml"
    manifest.write_text(
        f'''schema = 1
[[artifact]]
id = "client-test"
version = "1.20.40.1"
kind = "client"
archive_sha256 = "{sha256(package)}"
binary_sha256 = "{sha256(binary)}"
member = "Minecraft.Windows.exe"
[artifact.source]
type = "url"
url = "{package.as_uri()}"
''',
        encoding="utf-8",
    )
    database = tmp_path / "lens.db"

    assert (
        main(
            [
                "--database",
                str(database),
                "fetch",
                "client-test",
                "--manifest",
                str(manifest),
                "--cache-dir",
                str(tmp_path / "cache"),
            ]
        )
        == 0
    )
    fetched = json.loads(capsys.readouterr().out)

    assert fetched["version"] == "1.20.40.1"
    assert fetched["kind"] == "client"
    assert fetched["sha256"] == sha256(binary)
    assert Path(fetched["path"]).is_file()
