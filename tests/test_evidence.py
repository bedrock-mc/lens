from pathlib import Path

from bedrock_lens.catalog import Catalog
from bedrock_lens.evidence import FunctionEvidence, StringEvidence

from .test_pe import write_pe_with_rsds


def test_function_and_string_evidence_is_searchable(tmp_path: Path) -> None:
    binary = tmp_path / "bedrock_server.exe"
    write_pe_with_rsds(binary)

    with Catalog(tmp_path / "lens.db") as catalog:
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
                    strings=(StringEvidence(address=0x309A939, value="minecraft:crossbow"),),
                )
            ],
        )

        by_symbol = catalog.search("crossbowitem")
        by_string = catalog.search("minecraft:crossbow")

    assert [(hit.function.rva, hit.matched_by) for hit in by_symbol] == [(0x1870C60, "symbol")]
    assert [(hit.function.rva, hit.matched_by) for hit in by_string] == [(0x1870C60, "string")]


def test_analysis_run_records_tool_version_and_completion(tmp_path: Path) -> None:
    binary = tmp_path / "bedrock_server.exe"
    write_pe_with_rsds(binary)

    with Catalog(tmp_path / "lens.db") as catalog:
        artifact = catalog.register(binary, version="1.20.40.1", kind="server")
        run_id = catalog.start_analysis(artifact.id, backend="ghidra", backend_version="12.1.2")
        catalog.complete_analysis(run_id, function_count=221_721)
        runs = catalog.analysis_runs(artifact.id)

    assert len(runs) == 1
    assert runs[0].status == "complete"
    assert runs[0].backend == "ghidra"
    assert runs[0].backend_version == "12.1.2"
    assert runs[0].function_count == 221_721


def test_failed_analysis_records_the_error(tmp_path: Path) -> None:
    binary = tmp_path / "bedrock_server.exe"
    write_pe_with_rsds(binary)

    with Catalog(tmp_path / "lens.db") as catalog:
        artifact = catalog.register(binary, version="1.20.40.1", kind="server")
        run_id = catalog.start_analysis(artifact.id, backend="ghidra", backend_version="12.1.2")
        catalog.fail_analysis(run_id, error="PDB identity mismatch")
        run = catalog.analysis_runs(artifact.id)[0]

    assert run.status == "failed"
    assert run.error == "PDB identity mismatch"
