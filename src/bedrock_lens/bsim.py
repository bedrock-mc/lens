"""Persistent Ghidra BSim indexing."""

from __future__ import annotations

import subprocess
from pathlib import Path


class BSimError(RuntimeError):
    """Raised when the Ghidra BSim command fails."""


def database_url(path: str | Path) -> str:
    return f"file:{Path(path).expanduser().resolve()}"


def project_url(path: str | Path) -> str:
    normalized = Path(path).expanduser().resolve().as_posix()
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return f"ghidra:{normalized}"


class BSimIndex:
    def __init__(
        self,
        install_dir: str | Path,
        database_path: str | Path,
        *,
        template: str = "medium_nosize",
    ):
        self.install_dir = Path(install_dir).expanduser().resolve()
        self.database_path = Path(database_path).expanduser().resolve()
        self.template = template
        support = self.install_dir / "support"
        unix_executable = support / "bsim"
        windows_executable = support / "bsim.bat"
        self._executable = (
            unix_executable if unix_executable.is_file() else windows_executable
        )
        if not self._executable.is_file():
            raise BSimError(f"BSim executable not found: {self._executable}")

    @property
    def url(self) -> str:
        return database_url(self.database_path)

    def create(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        h2_file = Path(f"{self.database_path}.mv.db")
        if not h2_file.exists():
            self._run("createdatabase", self.url, self.template)

    def index_project(self, project_dir: str | Path, project_name: str) -> None:
        """Generate and commit signatures for every program in a Ghidra project."""
        self.create()
        project = Path(project_dir).expanduser().resolve() / project_name
        self._run("generatesigs", project_url(project), "--bsim", self.url)

    def _run(self, *arguments: str) -> str:
        command = (str(self._executable), *arguments)
        if self._executable.suffix.lower() in {".bat", ".cmd"}:
            command = ("cmd", "/c", *command)
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip()
            raise BSimError(message)
        return completed.stdout
