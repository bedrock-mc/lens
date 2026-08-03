"""Persistent Ghidra BSim indexing."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

_GC_OPTIONS = (
    "-XX:+UseSerialGC",
    "-XX:+UseParallelGC",
    "-XX:+UseG1GC",
    "-XX:+UseZGC",
    "-XX:+UseShenandoahGC",
    "-XX:+UseEpsilonGC",
)


def ghidra_environment(
    component_options: str, *, default_gc: str = "-XX:+UseParallelGC"
) -> dict[str, str]:
    """Return a stable environment for a standalone Ghidra JVM."""
    environment = os.environ.copy()
    if os.name == "nt":
        configured = " ".join(
            (
                environment.get("GHIDRA_JAVA_OPTIONS", ""),
                environment.get(component_options, ""),
            )
        )
        if not any(option in configured for option in _GC_OPTIONS):
            existing = environment.get(component_options, "")
            environment[component_options] = f"{existing} {default_gc}".strip()
    return environment


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
        candidates = (
            (windows_executable, unix_executable)
            if os.name == "nt"
            else (unix_executable, windows_executable)
        )
        self._executable = next(
            (candidate for candidate in candidates if candidate.is_file()), candidates[0]
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
            env=ghidra_environment(
                "GHIDRA_BSIM_JAVA_OPTIONS", default_gc="-XX:+UseSerialGC"
            ),
            text=True,
            timeout=3600,
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip()
            raise BSimError(message)
        return completed.stdout
