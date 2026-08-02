from __future__ import annotations

import json
from pathlib import Path

from bedrock_lens.catalog import Catalog
from bedrock_lens.cli import main
from bedrock_lens.evidence import FunctionEvidence

from .test_pe import write_pe_with_rsds


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
