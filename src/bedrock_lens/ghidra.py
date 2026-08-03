"""Ghidra analysis backend powered by native CPython through PyGhidra."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .bsim import database_url
from .evidence import FunctionEvidence, StringEvidence


class GhidraUnavailableError(RuntimeError):
    """Raised when Ghidra or the optional PyGhidra dependency is unavailable."""


def _is_install(path: Path) -> bool:
    return (path / "Ghidra/application.properties").is_file()


def find_ghidra_install() -> Path | None:
    """Find a Ghidra installation without starting its JVM."""
    configured = os.environ.get("GHIDRA_INSTALL_DIR")
    if configured:
        candidate = Path(configured).expanduser().resolve()
        if _is_install(candidate):
            return candidate

    executable = shutil.which("ghidraRun") or shutil.which("ghidraRun.bat")
    candidates = [
        Path("/opt/homebrew/opt/ghidra/libexec"),
        Path("/usr/local/opt/ghidra/libexec"),
    ]
    if executable:
        resolved = Path(executable).resolve()
        candidates.insert(0, resolved.parent)
        candidates.insert(0, resolved.parent.parent / "libexec")
    return next((path.resolve() for path in candidates if _is_install(path)), None)


def _ghidra_version(install_dir: Path) -> str:
    properties = install_dir / "Ghidra/application.properties"
    for line in properties.read_text(encoding="utf-8").splitlines():
        if line.startswith("application.version="):
            return line.partition("=")[2]
    raise GhidraUnavailableError(f"Ghidra version is missing from {properties}")


@dataclass(frozen=True, slots=True)
class GhidraAnalysis:
    ghidra_version: str
    project_name: str
    program_name: str
    functions: tuple[FunctionEvidence, ...]

    @property
    def backend_version(self) -> str:
        return self.ghidra_version


@dataclass(frozen=True, slots=True)
class Decompilation:
    rva: int
    name: str
    code: str


@dataclass(frozen=True, slots=True)
class BSimMatch:
    executable: str
    md5: str
    function: str
    address: int
    similarity: float
    significance: float


class GhidraBackend:
    def __init__(self, install_dir: str | Path, project_dir: str | Path):
        self.install_dir = Path(install_dir).expanduser().resolve()
        if not _is_install(self.install_dir):
            raise GhidraUnavailableError(f"not a Ghidra installation: {self.install_dir}")
        self.project_dir = Path(project_dir).expanduser().resolve()

    @property
    def version(self) -> str:
        return _ghidra_version(self.install_dir)

    def analyze(self, binary: str | Path, *, timeout: int | None = None) -> GhidraAnalysis:
        """Import, analyze, persist, and extract function evidence from one binary."""
        binary_path = Path(binary).expanduser().resolve(strict=True)
        project_name, program_name = _project_coordinates(binary_path)
        self.project_dir.mkdir(parents=True, exist_ok=True)
        functions = _analyze_headless(
            self.install_dir,
            self.project_dir,
            project_name,
            program_name,
            binary_path,
            timeout=timeout,
        )

        return GhidraAnalysis(
            ghidra_version=self.version,
            project_name=project_name,
            program_name=program_name,
            functions=functions,
        )

    def decompile(self, binary: str | Path, rva: int, *, timeout: int = 120) -> Decompilation:
        """Decompile one function from a previously analyzed artifact."""
        if rva < 0:
            raise ValueError("RVA must not be negative")
        try:
            import pyghidra
        except ImportError as exc:
            raise GhidraUnavailableError(
                "PyGhidra is not installed; run `uv sync --extra analysis`"
            ) from exc

        binary_path = Path(binary).expanduser().resolve(strict=True)
        project_name, program_name = _project_coordinates(binary_path)
        if not pyghidra.started():
            pyghidra.start(install_dir=self.install_dir)

        with (
            pyghidra.open_project(self.project_dir, project_name) as project,
            pyghidra.program_context(project, f"/{program_name}") as program,
        ):
            from ghidra.app.decompiler import DecompInterface

            address = program.getImageBase().add(rva)
            function_manager = program.getFunctionManager()
            function = function_manager.getFunctionAt(address)
            if function is None:
                function = function_manager.getFunctionContaining(address)
            if function is None:
                raise KeyError(f"no function contains RVA 0x{rva:x}")

            decompiler = DecompInterface()
            try:
                if not decompiler.openProgram(program):
                    raise RuntimeError(str(decompiler.getLastMessage()))
                result = decompiler.decompileFunction(function, timeout, pyghidra.task_monitor())
                if not result.decompileCompleted():
                    raise RuntimeError(str(result.getErrorMessage()))
                decompiled = result.getDecompiledFunction()
                if decompiled is None:
                    raise RuntimeError("Ghidra returned no decompilation")
                return Decompilation(
                    rva=int(function.getEntryPoint().subtract(program.getImageBase())),
                    name=str(function.getName()),
                    code=str(decompiled.getC()),
                )
            finally:
                decompiler.dispose()

    def match(
        self,
        binary: str | Path,
        rva: int,
        database_path: str | Path,
        *,
        max_matches: int = 10,
        similarity: float = 0.7,
        significance: float = 0.0,
    ) -> tuple[BSimMatch, ...]:
        """Query a persistent BSim index for functions similar to one source function."""
        try:
            import pyghidra
        except ImportError as exc:
            raise GhidraUnavailableError(
                "PyGhidra is not installed; run `uv sync --extra analysis`"
            ) from exc

        binary_path = Path(binary).expanduser().resolve(strict=True)
        project_name, program_name = _project_coordinates(binary_path)
        if not pyghidra.started():
            pyghidra.start(install_dir=self.install_dir)

        with (
            pyghidra.open_project(self.project_dir, project_name) as project,
            pyghidra.program_context(project, f"/{program_name}") as program,
        ):
            from ghidra.features.bsim.query import BSimClientFactory, GenSignatures
            from ghidra.features.bsim.query.protocol import QueryNearest

            address = program.getImageBase().add(rva)
            function = program.getFunctionManager().getFunctionContaining(address)
            if function is None:
                raise KeyError(f"no function contains RVA 0x{rva:x}")

            url = BSimClientFactory.deriveBSimURL(database_url(database_path))
            database = BSimClientFactory.buildClient(url, False)
            try:
                if not database.initialize():
                    raise RuntimeError(str(database.getLastError().message))
                signatures = GenSignatures(False)
                try:
                    signatures.setVectorFactory(database.getLSHVectorFactory())
                    signatures.openProgram(program, None, None, None, None, None)
                    signatures.scanFunction(function)

                    query = QueryNearest()
                    query.manage = signatures.getDescriptionManager()
                    query.max = max_matches
                    query.thresh = similarity
                    query.signifthresh = significance
                    response = query.execute(database)
                    if response is None:
                        raise RuntimeError(str(database.getLastError().message))

                    matches: list[BSimMatch] = []
                    for result in response.result:
                        for note in result:
                            description = note.getFunctionDescription()
                            executable = description.getExecutableRecord()
                            matches.append(
                                BSimMatch(
                                    executable=str(executable.getNameExec()),
                                    md5=str(executable.getMd5()),
                                    function=str(description.getFunctionName()),
                                    address=int(description.getAddress()),
                                    similarity=float(note.getSimilarity()),
                                    significance=float(note.getSignificance()),
                                )
                            )
                    return tuple(matches)
                finally:
                    signatures.dispose()
            finally:
                database.close()


def _sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _project_coordinates(path: Path) -> tuple[str, str]:
    digest = _sha256(path)
    return f"artifact_{digest[:16]}_v5", path.name


def _headless_executable(install_dir: Path) -> Path:
    support = install_dir / "support"
    candidates = (
        (support / "analyzeHeadless.bat", support / "analyzeHeadless")
        if os.name == "nt"
        else (support / "analyzeHeadless", support / "analyzeHeadless.bat")
    )
    executable = next((candidate for candidate in candidates if candidate.is_file()), None)
    if executable is None:
        raise GhidraUnavailableError(f"analyzeHeadless was not found under {support}")
    return executable


def _analyze_headless(
    install_dir: Path,
    project_dir: Path,
    project_name: str,
    program_name: str,
    binary_path: Path,
    *,
    timeout: int | None,
) -> tuple[FunctionEvidence, ...]:
    """Analyze and extract evidence in Ghidra's standalone headless JVM."""
    if timeout is not None and timeout <= 0:
        raise TimeoutError(f"Ghidra analysis exceeded {timeout} seconds")
    executable = _headless_executable(install_dir)
    script_dir = Path(__file__).with_name("ghidra_scripts").resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="lens-extract-", dir=project_dir) as temporary:
        output_path = Path(temporary) / "evidence.tsv"
        completion_marker = project_dir / f"{project_name}.lens-complete"
        command: tuple[str, ...] = (
            str(executable),
            str(project_dir),
            project_name,
            "-scriptPath",
            str(script_dir),
        )
        project_file = project_dir / f"{project_name}.gpr"
        if not completion_marker.is_file():
            _discard_incomplete_project(project_file)
        if project_file.is_file() and completion_marker.is_file():
            command += ("-process", program_name, "-noanalysis", "-readOnly")
        else:
            command += (
                "-preScript",
                "BedrockLensConfigure.java",
            )
            if project_file.is_file():
                command += ("-process", program_name)
            else:
                command += ("-import", str(binary_path))
            if timeout is not None:
                command += ("-analysisTimeoutPerFile", str(timeout))
        command += (
            "-postScript",
            "BedrockLensExtract.java",
            str(output_path),
        )
        if executable.suffix.lower() in {".bat", ".cmd"}:
            command = ("cmd", "/c", *command)
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            start_new_session=os.name != "nt",
        )
        try:
            stdout, stderr = process.communicate(
                timeout=7200 if timeout is None else timeout + 180
            )
        except subprocess.TimeoutExpired as exc:
            _terminate_process_tree(process)
            process.communicate()
            raise TimeoutError(f"Ghidra evidence extraction exceeded {timeout} seconds") from exc
        if process.returncode != 0:
            detail = f"{stdout}\n{stderr}".strip()[-4000:]
            raise RuntimeError(
                f"Ghidra evidence extraction failed with exit code "
                f"{process.returncode}: {detail}"
            )
        if not output_path.is_file():
            detail = f"{stdout}\n{stderr}".strip()[-4000:]
            raise RuntimeError(f"Ghidra evidence extraction produced no output: {detail}")
        evidence = _parse_headless_evidence(output_path)
        completion_marker.touch()
        return evidence


def _discard_incomplete_project(project_file: Path) -> None:
    shutil.rmtree(project_file.with_suffix(".rep"), ignore_errors=True)
    project_file.unlink(missing_ok=True)
    project_file.with_suffix(".lock").unlink(missing_ok=True)
    project_file.with_suffix(".lock~").unlink(missing_ok=True)


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if os.name == "nt":
        with contextlib.suppress(OSError):
            subprocess.run(
                ("taskkill", "/PID", str(process.pid), "/T", "/F"),
                check=False,
                capture_output=True,
                text=True,
                errors="replace",
            )
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
    if process.poll() is None:
        process.kill()


def _parse_headless_evidence(path: Path) -> tuple[FunctionEvidence, ...]:
    evidence: list[FunctionEvidence] = []
    current: tuple[int, str, str, int, int] | None = None
    strings: list[StringEvidence] = []

    def flush() -> None:
        nonlocal current, strings
        if current is None:
            return
        rva, name, namespace, size, parameter_count = current
        evidence.append(
            FunctionEvidence(
                rva=rva,
                name=name,
                namespace=namespace,
                size=size,
                parameter_count=parameter_count,
                strings=tuple(strings),
            )
        )
        current = None
        strings = []

    with path.open(encoding="utf-8", newline="") as source:
        header = source.readline().rstrip("\r\n")
        if header != "V\t1":
            raise RuntimeError(f"unsupported Ghidra evidence format: {header!r}")
        for line_number, raw_line in enumerate(source, start=2):
            fields = raw_line.rstrip("\r\n").split("\t")
            try:
                if fields[0] == "F" and len(fields) == 6:
                    flush()
                    current = (
                        int(fields[1]),
                        _decode_evidence_text(fields[4]),
                        _decode_evidence_text(fields[5]),
                        int(fields[2]),
                        int(fields[3]),
                    )
                elif fields[0] == "S" and len(fields) == 4 and current is not None:
                    if int(fields[1]) != current[0]:
                        raise ValueError("string function RVA does not match current function")
                    strings.append(
                        StringEvidence(
                            address=int(fields[2]),
                            value=_decode_evidence_text(fields[3]),
                        )
                    )
                else:
                    raise ValueError("unknown or misplaced record")
            except (ValueError, IndexError) as exc:
                raise RuntimeError(
                    f"malformed Ghidra evidence at {path}:{line_number}"
                ) from exc
    flush()
    return tuple(evidence)


def _decode_evidence_text(value: str) -> str:
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid base64 text") from exc
