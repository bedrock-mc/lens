import os
import subprocess
from pathlib import Path

from bedrock_lens.bsim import BSimIndex, project_url


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
