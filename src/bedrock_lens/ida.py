"""Headless IDA Pro analysis backend."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .evidence import FunctionEvidence, StringEvidence

_IDA_EXECUTABLES = (
    "idat64",
    "idat64.exe",
    "ida64",
    "ida64.exe",
    "idat",
    "idat.exe",
    "ida",
    "ida.exe",
)


class IdaUnavailableError(RuntimeError):
    """Raised when a usable IDA Pro installation cannot be found or run."""


@dataclass(frozen=True, slots=True)
class IdaAnalysis:
    ida_version: str
    project_name: str
    program_name: str
    database_path: Path
    functions: tuple[FunctionEvidence, ...]

    @property
    def backend_version(self) -> str:
        return self.ida_version


@dataclass(frozen=True, slots=True)
class Decompilation:
    rva: int
    name: str
    code: str


def _ida_executable(path: Path) -> Path | None:
    if path.is_file() and path.name.lower() in _IDA_EXECUTABLES:
        return path
    for name in _IDA_EXECUTABLES:
        candidate = path / name
        if candidate.is_file():
            return candidate
    return None


def find_ida_install() -> Path | None:
    """Find an IDA Pro installation without starting the IDA GUI."""
    configured = os.environ.get("IDA_INSTALL_DIR") or os.environ.get("IDADIR")
    if configured:
        candidate = Path(configured).expanduser().resolve()
        if _ida_executable(candidate) is not None:
            return candidate if candidate.is_dir() else candidate.parent

    executable = next(
        (shutil.which(name) for name in _IDA_EXECUTABLES),
        None,
    )
    if executable:
        return Path(executable).resolve().parent

    candidates = [
        Path("/Applications/IDA Professional.app/Contents/MacOS"),
        Path("/Applications/IDA Pro.app/Contents/MacOS"),
        Path("/opt/ida"),
        Path("C:/Program Files/IDA Professional"),
        Path("C:/Program Files/IDA Pro"),
    ]
    for parent, patterns in (
        (Path("/Applications"), ("IDA*/ida.app/Contents/MacOS", "IDA*.app/Contents/MacOS")),
        (Path.home(), ("ida-pro*/", "ida*/")),
        (Path("C:/Program Files"), ("IDA*",)),
    ):
        for pattern in patterns:
            candidates.extend(parent.glob(pattern))
    return next(
        (path.resolve() for path in candidates if _ida_executable(path) is not None),
        None,
    )


def _sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _project_coordinates(path: Path) -> tuple[str, str]:
    digest = _sha256(path)
    return f"artifact_{digest[:16]}", f"{path.stem}_{digest[:12]}"


def _analysis_from_payload(payload: dict[str, Any]) -> tuple[FunctionEvidence, ...]:
    functions = payload.get("functions")
    if not isinstance(functions, list):
        raise IdaUnavailableError("IDA worker returned no function evidence")

    result: list[FunctionEvidence] = []
    for item in functions:
        if not isinstance(item, dict):
            raise IdaUnavailableError("IDA worker returned malformed function evidence")
        raw_strings = item.get("strings", [])
        if not isinstance(raw_strings, list):
            raise IdaUnavailableError("IDA worker returned malformed string evidence")
        strings_result: list[StringEvidence] = []
        for string in raw_strings:
            if not isinstance(string, dict) or "address" not in string or "value" not in string:
                raise IdaUnavailableError("IDA worker returned malformed string evidence")
            try:
                strings_result.append(
                    StringEvidence(address=int(string["address"]), value=str(string["value"]))
                )
            except (TypeError, ValueError) as exc:
                raise IdaUnavailableError("IDA worker returned malformed string evidence") from exc
        strings = tuple(strings_result)
        try:
            result.append(
                FunctionEvidence(
                    rva=int(item["rva"]),
                    name=str(item["name"]),
                    namespace=str(item.get("namespace", "")),
                    size=int(item["size"]),
                    parameter_count=int(item.get("parameter_count", 0)),
                    strings=strings,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise IdaUnavailableError("IDA worker returned malformed function evidence") from exc
    return tuple(result)


class IdaBackend:
    """Run IDA's text-mode executable and persist one ``.i64`` per binary."""

    def __init__(self, install_dir: str | Path, project_dir: str | Path):
        configured = Path(install_dir).expanduser().resolve()
        executable = _ida_executable(configured)
        if executable is None:
            raise IdaUnavailableError(f"not an IDA Pro installation: {configured}")
        self.install_dir = configured if configured.is_dir() else configured.parent
        self._executable = executable.resolve()
        self.project_dir = Path(project_dir).expanduser().resolve()
        self._cached_version: str | None = None

    @property
    def version(self) -> str:
        if self._cached_version is None:
            details: list[str] = []
            for option in ("-h", "-v"):
                try:
                    completed = subprocess.run(
                        [str(self._executable), option],
                        check=False,
                        capture_output=True,
                        text=True,
                        errors="replace",
                        timeout=30,
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise IdaUnavailableError(f"could not query IDA version: {exc}") from exc
                output = f"{completed.stdout}\n{completed.stderr}"
                details.append(output)
                match = re.search(r"\b\d+(?:\.\d+){1,3}\b", output)
                if completed.returncode == 0 and match is not None:
                    self._cached_version = match.group(0)
                    break
            if self._cached_version is None:
                detail = "\n".join(details).strip()[-1000:]
                raise IdaUnavailableError(f"could not determine IDA version: {detail}")
        return self._cached_version

    def analyze(self, binary: str | Path, *, timeout: int | None = None) -> IdaAnalysis:
        """Auto-analyze a PE and extract functions, parameters, and referenced strings."""
        binary_path = Path(binary).expanduser().resolve(strict=True)
        project_name, program_name = _project_coordinates(binary_path)
        self.project_dir.mkdir(parents=True, exist_ok=True)
        database_path = self.project_dir / f"{program_name}.i64"
        payload = self._run_worker(
            mode="analyze",
            input_path=database_path if database_path.is_file() else binary_path,
            database_path=database_path,
            timeout=timeout,
        )
        return IdaAnalysis(
            ida_version=self.version,
            project_name=project_name,
            program_name=program_name,
            database_path=database_path,
            functions=_analysis_from_payload(payload),
        )

    def decompile(self, binary: str | Path, rva: int, *, timeout: int = 120) -> Decompilation:
        """Decompile one function from a previously analyzed IDA database."""
        if rva < 0:
            raise ValueError("RVA must not be negative")
        binary_path = Path(binary).expanduser().resolve(strict=True)
        _, program_name = _project_coordinates(binary_path)
        database_path = self.project_dir / f"{program_name}.i64"
        if not database_path.is_file():
            raise FileNotFoundError(
                f"IDA database is missing: {database_path}; run `lens analyze --backend ida` first"
            )
        payload = self._run_worker(
            mode="decompile",
            input_path=database_path,
            database_path=database_path,
            rva=rva,
            timeout=timeout,
        )
        try:
            return Decompilation(
                rva=int(payload["rva"]),
                name=str(payload["name"]),
                code=str(payload["code"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise IdaUnavailableError("IDA worker returned malformed decompilation") from exc

    def _run_worker(
        self,
        *,
        mode: str,
        input_path: Path,
        database_path: Path,
        timeout: int | None,
        rva: int | None = None,
    ) -> dict[str, Any]:
        worker = Path(__file__).with_name("ida_worker.py").resolve(strict=True)
        self.project_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".ida-lens-", dir=self.project_dir) as temp:
            temporary = Path(temp)
            output_path = temporary / "result.json"
            config_path = temporary / "request.json"
            config: dict[str, Any] = {
                "mode": mode,
                "output": str(output_path),
                "database": str(database_path),
            }
            if rva is not None:
                config["rva"] = rva
            config_path.write_text(json.dumps(config), encoding="utf-8")

            command = [
                str(self._executable),
                "-A",
                f"-S{worker} {config_path}",
            ]
            if input_path == database_path and database_path.is_file():
                command.append(str(database_path))
            else:
                command.extend([f"-o{database_path}", str(input_path)])
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    errors="replace",
                    cwd=self.project_dir,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError(f"IDA {mode} exceeded {timeout} seconds") from exc
            except OSError as exc:
                raise IdaUnavailableError(f"could not start IDA: {exc}") from exc

            if completed.returncode != 0:
                detail = f"{completed.stdout}\n{completed.stderr}".strip()[-2000:]
                raise IdaUnavailableError(
                    f"IDA {mode} failed with exit code {completed.returncode}: {detail}"
                )
            if mode == "analyze" and not database_path.is_file():
                raise IdaUnavailableError(
                    f"IDA completed without creating its database: {database_path}"
                )
            if not output_path.is_file():
                detail = f"{completed.stdout}\n{completed.stderr}".strip()[-1000:]
                raise IdaUnavailableError(f"IDA worker produced no result: {detail}")
            try:
                payload = json.loads(output_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise IdaUnavailableError("IDA worker returned invalid JSON") from exc
            if not isinstance(payload, dict):
                raise IdaUnavailableError("IDA worker returned a non-object result")
            if "error" in payload:
                raise IdaUnavailableError(str(payload["error"]))
            return payload
