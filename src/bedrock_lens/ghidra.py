"""Ghidra analysis backend powered by native CPython through PyGhidra."""

from __future__ import annotations

import hashlib
import os
import shutil
from collections import defaultdict
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
        try:
            import pyghidra
        except ImportError as exc:
            raise GhidraUnavailableError(
                "PyGhidra is not installed; run `uv sync --extra analysis`"
            ) from exc

        binary_path = Path(binary).expanduser().resolve(strict=True)
        project_name, program_name = _project_coordinates(binary_path)
        self.project_dir.mkdir(parents=True, exist_ok=True)

        if not pyghidra.started():
            pyghidra.start(install_dir=self.install_dir)
        with pyghidra.open_project(self.project_dir, project_name, create=True) as project:
            project_path = f"/{program_name}"
            if project.getProjectData().getFile(project_path) is None:
                loader = (
                    pyghidra.program_loader()
                    .project(project)
                    .source(str(binary_path))
                    .name(program_name)
                )
                with loader.load() as load_results:
                    load_results.save(pyghidra.task_monitor())

            with pyghidra.program_context(project, project_path) as program:
                from ghidra.program.util import GhidraProgramUtilities

                if GhidraProgramUtilities.shouldAskToAnalyze(program):
                    _analyze_program(pyghidra, program, timeout)
                    program.save("Bedrock Lens analysis", pyghidra.task_monitor())
                functions = _extract_functions(program)

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
    return f"artifact_{digest[:16]}", f"{path.stem}_{digest[:12]}"


def _analyze_program(pyghidra, program, timeout: int | None) -> None:
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.util import GhidraProgramUtilities

    monitor = pyghidra.task_monitor(timeout)
    with pyghidra.transaction(program, "Bedrock Lens analysis"):
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            manager = AutoAnalysisManager.getAnalysisManager(program)
            manager.initializeOptions()
            manager.reAnalyzeAll(None)
            manager.startAnalysis(monitor, True)
            if monitor.isCancelled():
                raise TimeoutError(f"Ghidra analysis exceeded {timeout} seconds")
            GhidraProgramUtilities.markProgramAnalyzed(program)
        finally:
            GhidraScriptUtil.releaseBundleHostReference()


def _extract_functions(program) -> tuple[FunctionEvidence, ...]:
    image_base = program.getImageBase()
    function_manager = program.getFunctionManager()
    reference_manager = program.getReferenceManager()
    strings: dict[int, set[StringEvidence]] = defaultdict(set)

    defined_data = program.getListing().getDefinedData(True)
    while defined_data.hasNext():
        data = defined_data.next()
        if not data.hasStringValue():
            continue
        value = data.getValue()
        if value is None:
            continue
        try:
            address = int(data.getAddress().subtract(image_base))
        except Exception:
            continue
        references = reference_manager.getReferencesTo(data.getAddress())
        while references.hasNext():
            reference = references.next()
            function = function_manager.getFunctionContaining(reference.getFromAddress())
            if function is None or function.isExternal():
                continue
            entry = int(function.getEntryPoint().subtract(image_base))
            strings[entry].add(StringEvidence(address=address, value=str(value)))

    evidence: list[FunctionEvidence] = []
    functions = function_manager.getFunctions(True)
    while functions.hasNext():
        function = functions.next()
        if function.isExternal():
            continue
        try:
            rva = int(function.getEntryPoint().subtract(image_base))
        except Exception:
            continue
        namespace = function.getParentNamespace()
        evidence.append(
            FunctionEvidence(
                rva=rva,
                name=str(function.getName()),
                namespace=str(namespace.getName(True)) if namespace is not None else "",
                size=int(function.getBody().getNumAddresses()),
                parameter_count=int(function.getParameterCount()),
                strings=tuple(
                    sorted(strings.get(rva, ()), key=lambda item: (item.address, item.value))
                ),
            )
        )
    return tuple(evidence)
