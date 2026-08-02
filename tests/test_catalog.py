from pathlib import Path

from bedrock_lens.catalog import Catalog

from .test_pe import write_pe_with_rsds


def test_catalog_registers_and_persists_an_artifact(tmp_path: Path) -> None:
    binary = tmp_path / "Minecraft.Windows.exe"
    database = tmp_path / "lens.db"
    write_pe_with_rsds(binary)

    with Catalog(database) as catalog:
        first = catalog.register(binary, version="1.20.40.1", kind="client")
        second = catalog.register(binary, version="1.20.40.1", kind="client")

    assert first.id == second.id
    assert first.version == "1.20.40.1"
    assert first.kind == "client"
    assert first.channel == "retail"
    assert first.identity.pdb is not None
    assert first.identity.pdb.guid == "603c336c-4fcb-4ec3-b5e2-ecb754278979"

    with Catalog(database) as catalog:
        artifacts = catalog.artifacts()

    assert artifacts == [second]
