from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from bedrock_lens.catalog import Catalog
from bedrock_lens.cli import main
from bedrock_lens.ida import IdaBackend, find_ida_install

from .test_pe import write_pe_with_rsds


def _fake_ida(install: Path) -> Path:
    (install / "Ghidra").mkdir(parents=True)
    executable = install / "idat64"
    executable.write_text(
        '''#!/usr/bin/env python3
import json
import sys
from pathlib import Path

if "-v" in sys.argv or "-h" in sys.argv:
    print("IDA: 9.2.0")
    raise SystemExit(0)

script = next(argument for argument in sys.argv if argument.startswith("-S"))
config = Path(script.split(" ", 1)[1])
payload = json.loads(config.read_text())
Path(payload["output"]).write_text(json.dumps(
    {
        "functions": [
            {
                "rva": 4096,
                "name": "main",
                "namespace": "",
                "size": 32,
                "parameter_count": 1,
                "strings": [{"address": 8192, "value": "hello"}],
            }
        ],
        "rva": 4096,
        "name": "main",
        "code": "int main() { return 0; }",
    }
))
for argument in sys.argv:
    if argument.startswith("-o"):
        Path(argument[2:]).touch()
''',
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


def test_find_ida_install_uses_configured_install(tmp_path: Path, monkeypatch) -> None:
    install = tmp_path / "ida"
    _fake_ida(install)
    monkeypatch.setenv("IDA_INSTALL_DIR", str(install))

    assert find_ida_install() == install.resolve()


def test_ida_backend_analyzes_and_decompiles_with_headless_runner(tmp_path: Path) -> None:
    install = tmp_path / "ida"
    _fake_ida(install)
    binary = tmp_path / "Minecraft.Windows.exe"
    binary.write_bytes(b"MZ" + os.urandom(64))
    backend = IdaBackend(install, tmp_path / "projects")

    assert backend.version == "9.2.0"
    analysis = backend.analyze(binary)

    assert analysis.ida_version == "9.2.0"
    assert analysis.functions[0].name == "main"
    assert analysis.functions[0].strings[0].value == "hello"
    assert analysis.database_path.is_file()

    decompilation = backend.decompile(binary, 0x1000)
    assert decompilation.rva == 0x1000
    assert decompilation.name == "main"
    assert "return 0" in decompilation.code


def test_cli_can_select_ida_for_analysis_and_decompilation(tmp_path: Path, capsys) -> None:
    install = tmp_path / "ida"
    _fake_ida(install)
    binary = tmp_path / "Minecraft.Windows.exe"
    write_pe_with_rsds(binary)
    database = tmp_path / "lens.db"

    assert (
        main(
            [
                "--database",
                str(database),
                "add",
                str(binary),
                "--version",
                "test",
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
                "--backend",
                "ida",
                "--ida-install",
                str(install),
                "--project-dir",
                str(tmp_path / "projects"),
            ]
        )
        == 0
    )
    analysis = json.loads(capsys.readouterr().out)
    assert analysis["backend"] == "ida"
    assert analysis["ida_version"] == "9.2.0"
    with Catalog(database) as catalog:
        run = catalog.analysis_runs(artifact_id)[0]
    assert run.backend == "ida"
    assert run.backend_version == "9.2.0"

    assert (
        main(
            [
                "--database",
                str(database),
                "decompile",
                str(artifact_id),
                "0x1000",
                "--backend",
                "ida",
                "--ida-install",
                str(install),
                "--project-dir",
                str(tmp_path / "projects"),
            ]
        )
        == 0
    )
    assert "return 0" in json.loads(capsys.readouterr().out)["code"]
