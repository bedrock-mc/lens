import os
import subprocess
from pathlib import Path

from bedrock_lens.bsim import BSimIndex, ghidra_environment, project_url


def test_bsim_uses_the_platform_launcher(tmp_path: Path, monkeypatch) -> None:
    install = tmp_path / "ghidra"
    support = install / "support"
    support.mkdir(parents=True)
    executable = support / ("bsim.bat" if os.name == "nt" else "bsim")
    executable.write_text("", encoding="utf-8")

    calls: list[tuple[tuple[str, ...], dict]] = []

    def fake_run(command, **kwargs):
        calls.append((tuple(command), kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr("bedrock_lens.bsim.subprocess.run", fake_run)
    index = BSimIndex(install, tmp_path / "bsim" / "lens")

    assert index._run("createdatabase", index.url, "medium_nosize") == "ok\n"
    command = calls[0][0]
    if os.name == "nt":
        assert command[:3] == ("cmd", "/c", str(executable))
    else:
        assert command[0] == str(executable)


def test_project_url_uses_ghidra_local_url_syntax(tmp_path: Path) -> None:
    url = project_url(tmp_path / "project")

    assert url.startswith("ghidra:/")
    assert url.endswith("/project")


def test_windows_ghidra_processes_default_to_parallel_gc(monkeypatch) -> None:
    monkeypatch.delenv("GHIDRA_JAVA_OPTIONS", raising=False)
    monkeypatch.delenv("GHIDRA_BSIM_JAVA_OPTIONS", raising=False)
    monkeypatch.setattr("bedrock_lens.bsim.os.name", "nt")

    environment = ghidra_environment("GHIDRA_BSIM_JAVA_OPTIONS")

    assert environment["GHIDRA_BSIM_JAVA_OPTIONS"] == "-XX:+UseParallelGC"


def test_explicit_ghidra_garbage_collector_is_preserved(monkeypatch) -> None:
    monkeypatch.setenv("GHIDRA_JAVA_OPTIONS", "-XX:+UseSerialGC")
    monkeypatch.setenv("GHIDRA_BSIM_JAVA_OPTIONS", "-Xmx4G")
    monkeypatch.setattr("bedrock_lens.bsim.os.name", "nt")

    environment = ghidra_environment("GHIDRA_BSIM_JAVA_OPTIONS")

    assert environment["GHIDRA_BSIM_JAVA_OPTIONS"] == "-Xmx4G"
