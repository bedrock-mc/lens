import json
from pathlib import Path

import pytest

from bedrock_lens.bsim import BSimIndex
from bedrock_lens.catalog import Catalog
from bedrock_lens.cli import main
from bedrock_lens.ghidra import GhidraBackend, find_ghidra_install


@pytest.mark.integration
def test_ghidra_analyzes_and_extracts_a_real_pe(tmp_path: Path) -> None:
    install = find_ghidra_install()
    if install is None:
        pytest.skip("Ghidra is not installed")
    sample = install / "docs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe"
    if not sample.exists():
        pytest.skip("Ghidra WinHelloCPP fixture is not installed")

    backend = GhidraBackend(install, tmp_path / "projects")
    assert backend.version
    result = backend.analyze(sample, timeout=60)

    assert result.ghidra_version
    assert len(result.functions) > 10
    assert any("main" in function.name.lower() for function in result.functions)
    main_function = next(
        function for function in result.functions if "main" in function.name.lower()
    )
    decompilation = backend.decompile(sample, main_function.rva, timeout=30)
    assert decompilation.rva == main_function.rva
    assert "main" in decompilation.name.lower()
    assert "{" in decompilation.code

    index = BSimIndex(install, tmp_path / "bsim" / "lens")
    index.index_project(tmp_path / "projects", result.project_name)
    matches = backend.match(sample, main_function.rva, index.database_path)
    self_match = next(match for match in matches if match.executable == result.program_name)
    assert self_match.similarity == pytest.approx(1.0)
    assert self_match.significance > 0


@pytest.mark.integration
def test_ghidra_timeout_does_not_report_partial_analysis_as_complete(tmp_path: Path) -> None:
    install = find_ghidra_install()
    if install is None:
        pytest.skip("Ghidra is not installed")
    sample = install / "docs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe"
    if not sample.exists():
        pytest.skip("Ghidra WinHelloCPP fixture is not installed")

    with pytest.raises(TimeoutError):
        GhidraBackend(install, tmp_path / "projects").analyze(sample, timeout=0)


@pytest.mark.integration
def test_cli_analysis_flows_into_search(tmp_path: Path, capsys) -> None:
    install = find_ghidra_install()
    if install is None:
        pytest.skip("Ghidra is not installed")
    sample = install / "docs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe"
    if not sample.exists():
        pytest.skip("Ghidra WinHelloCPP fixture is not installed")

    database = tmp_path / "lens.db"
    assert (
        main(
            [
                "--database",
                str(database),
                "add",
                str(sample),
                "--version",
                "ghidra-fixture",
                "--kind",
                "client",
            ]
        )
        == 0
    )
    artifact_id = json.loads(capsys.readouterr().out)["id"]

    assert (
        main(
            [
                "--database",
                str(database),
                "analyze",
                str(artifact_id),
                "--project-dir",
                str(tmp_path / "projects"),
                "--timeout",
                "60",
                "--bsim-database",
                str(tmp_path / "bsim" / "lens"),
            ]
        )
        == 0
    )
    analysis = json.loads(capsys.readouterr().out)
    assert analysis["function_count"] > 10
    with Catalog(database) as catalog:
        runs = catalog.analysis_runs(artifact_id)
    assert len(runs) == 1
    assert runs[0].status == "complete"
    assert runs[0].backend_version == analysis["ghidra_version"]

    assert main(["--database", str(database), "search", "main"]) == 0
    hits = json.loads(capsys.readouterr().out)
    assert any("main" in hit["name"].lower() for hit in hits)
    main_hit = next(hit for hit in hits if "main" in hit["name"].lower())

    assert (
        main(
            [
                "--database",
                str(database),
                "decompile",
                str(artifact_id),
                main_hit["rva"],
                "--project-dir",
                str(tmp_path / "projects"),
            ]
        )
        == 0
    )
    decompilation = json.loads(capsys.readouterr().out)
    assert "main" in decompilation["name"].lower()
    assert "{" in decompilation["code"]

    assert (
        main(
            [
                "--database",
                str(database),
                "match",
                str(artifact_id),
                main_hit["rva"],
                "--project-dir",
                str(tmp_path / "projects"),
                "--bsim-database",
                str(tmp_path / "bsim" / "lens"),
            ]
        )
        == 0
    )
    matches = json.loads(capsys.readouterr().out)
    assert matches[0]["similarity"] == pytest.approx(1.0)
    assert matches[0]["artifact_id"] == artifact_id
    assert matches[0]["version"] == "ghidra-fixture"
    assert matches[0]["rva"] == main_hit["rva"]
