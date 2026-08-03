import json
from pathlib import Path

import pytest

from bedrock_lens.bsim import BSimIndex
from bedrock_lens.catalog import Catalog
from bedrock_lens.cli import main
from bedrock_lens.ghidra import GhidraBackend, _parse_headless_evidence, find_ghidra_install


def test_headless_evidence_parser_preserves_functions_and_strings(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.tsv"
    evidence.write_text(
        "V\t1\n"
        "F\t4096\t32\t2\tdGljaw==\tZ2xvYmFs\n"
        "S\t4096\t8192\taGVsbG8=\n"
        "F\t4352\t8\t0\tdG9jaw==\t\n",
        encoding="utf-8",
    )

    functions = _parse_headless_evidence(evidence)

    assert [(function.rva, function.name) for function in functions] == [
        (4096, "tick"),
        (4352, "tock"),
    ]
    assert functions[0].namespace == "global"
    assert functions[0].parameter_count == 2
    assert [(string.address, string.value) for string in functions[0].strings] == [
        (8192, "hello")
    ]


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


def test_windows_ghidra_commands_are_discovered(tmp_path: Path, monkeypatch) -> None:
    install = tmp_path / "ghidra"
    (install / "Ghidra").mkdir(parents=True)
    (install / "Ghidra" / "application.properties").write_text(
        "application.version=12.0\n", encoding="utf-8"
    )
    support = install / "support"
    support.mkdir()
    (support / "bsim.bat").write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(install))

    assert find_ghidra_install() == install.resolve()
    assert BSimIndex(install, tmp_path / "index")._executable.name == "bsim.bat"


def test_windows_bsim_batch_file_is_invoked_through_cmd(tmp_path: Path, monkeypatch) -> None:
    install = tmp_path / "ghidra"
    (install / "Ghidra").mkdir(parents=True)
    (install / "Ghidra" / "application.properties").write_text(
        "application.version=12.0\n", encoding="utf-8"
    )
    support = install / "support"
    support.mkdir()
    (support / "bsim.bat").write_text("@echo off\n", encoding="utf-8")
    index = BSimIndex(install, tmp_path / "index")
    calls: list[tuple[str, ...]] = []

    class Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(command, **kwargs):
        calls.append(command)
        return Completed()

    monkeypatch.setattr("bedrock_lens.bsim.subprocess.run", fake_run)
    assert index._run("createdatabase", "file:test") == "ok"
    assert calls == [("cmd", "/c", str(support / "bsim.bat"), "createdatabase", "file:test")]
