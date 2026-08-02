"""Persistent Ghidra BSim indexing."""

from __future__ import annotations

import subprocess
from pathlib import Path


class BSimError(RuntimeError):
    """Raised when the Ghidra BSim command fails."""


def database_url(path: str | Path) -> str:
    return f"file:{Path(path).expanduser().resolve()}"


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
        self._executable = self.install_dir / "support/bsim"
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
        self._run("generatesigs", f"ghidra:{project}", "--bsim", self.url)

    def _run(self, *arguments: str) -> str:
        completed = subprocess.run(
            (str(self._executable), *arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip()
            raise BSimError(message)
        return completed.stdout
