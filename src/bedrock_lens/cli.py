"""Bedrock Lens command-line interface."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .bsim import BSimIndex
from .catalog import Artifact, Catalog
from .corpus import ArtifactSpec, CorpusFetcher, FetchResult, load_manifest
from .evidence import SearchHit
from .ghidra import GhidraBackend, GhidraUnavailableError, find_ghidra_install
from .ida import IdaBackend, IdaUnavailableError, find_ida_install


def _default_database() -> Path:
    data_root = os.environ.get("XDG_DATA_HOME")
    if data_root is None and os.name == "nt":
        data_root = os.environ.get("APPDATA")
    data_home = Path(data_root or Path.home() / ".local" / "share")
    return data_home / "bedrock-lens" / "lens.db"


def _default_cache() -> Path:
    cache_root = os.environ.get("XDG_CACHE_HOME")
    if cache_root is None and os.name == "nt":
        cache_root = os.environ.get("LOCALAPPDATA")
    cache_home = Path(cache_root or Path.home() / ".cache")
    return cache_home / "bedrock-lens"


def _default_manifest() -> Path:
    return Path(__file__).with_name("corpus.toml")


def _integer(value: str) -> int:
    return int(value, 0)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lens",
        description="Index and correlate Minecraft Bedrock binaries.",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=Path(os.environ.get("LENS_DATABASE", _default_database())),
        help="SQLite catalog path (default: %(default)s)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    add = commands.add_parser("add", help="register a PE binary")
    add.add_argument("path", type=Path)
    add.add_argument("--version", required=True)
    add.add_argument("--kind", choices=("client", "server"), required=True)
    add.add_argument("--channel", default="retail")

    fetch = commands.add_parser(
        "fetch", help="download, verify, extract, and register a corpus artifact"
    )
    fetch.add_argument("artifact_id")
    fetch.add_argument("--manifest", type=Path, default=_default_manifest())
    fetch.add_argument("--cache-dir", type=Path, default=_default_cache())

    corpus = commands.add_parser("corpus", help="inspect or synchronize a corpus manifest")
    corpus_commands = corpus.add_subparsers(dest="corpus_command", required=True)
    corpus_list = corpus_commands.add_parser("list", help="list available immutable artifacts")
    corpus_list.add_argument("--manifest", type=Path, default=_default_manifest())
    corpus_sync = corpus_commands.add_parser("sync", help="fetch and register every artifact")
    corpus_sync.add_argument("--manifest", type=Path, default=_default_manifest())
    corpus_sync.add_argument("--cache-dir", type=Path, default=_default_cache())

    commands.add_parser("list", help="list registered binaries")

    search = commands.add_parser("search", help="search function names and referenced strings")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=50)

    analyze = commands.add_parser("analyze", help="analyze a registered binary")
    analyze.add_argument("artifact_id", type=int)
    analyze.add_argument("--backend", choices=("ghidra", "ida"), default="ghidra")
    analyze.add_argument("--ghidra-install", type=Path)
    analyze.add_argument("--ida-install", type=Path)
    analyze.add_argument("--project-dir", type=Path)
    analyze.add_argument("--timeout", type=int)
    analyze.add_argument("--bsim-database", type=Path)

    decompile = commands.add_parser("decompile", help="decompile a function by RVA")
    decompile.add_argument("artifact_id", type=int)
    decompile.add_argument("rva", type=_integer)
    decompile.add_argument("--backend", choices=("ghidra", "ida"), default="ghidra")
    decompile.add_argument("--ghidra-install", type=Path)
    decompile.add_argument("--ida-install", type=Path)
    decompile.add_argument("--project-dir", type=Path)
    decompile.add_argument("--timeout", type=int, default=120)

    match = commands.add_parser("match", help="find structurally similar functions with BSim")
    match.add_argument("artifact_id", type=int)
    match.add_argument("rva", type=_integer)
    match.add_argument("--bsim-database", type=Path, required=True)
    match.add_argument("--ghidra-install", type=Path)
    match.add_argument("--project-dir", type=Path)
    match.add_argument("--limit", type=int, default=10)
    match.add_argument("--min-similarity", type=float, default=0.7)
    match.add_argument("--min-significance", type=float, default=0.0)
    return parser


def _artifact_json(artifact: Artifact) -> dict[str, Any]:
    pdb = artifact.identity.pdb
    return {
        "id": artifact.id,
        "version": artifact.version,
        "kind": artifact.kind,
        "channel": artifact.channel,
        "path": str(artifact.path),
        "sha256": artifact.identity.sha256,
        "file_size": artifact.identity.file_size,
        "machine": artifact.identity.machine,
        "timestamp": artifact.identity.timestamp,
        "image_base": artifact.identity.image_base,
        "image_size": artifact.identity.image_size,
        "pdb": (
            {"name": pdb.name, "guid": pdb.guid, "age": pdb.age, "path": pdb.path} if pdb else None
        ),
    }


def _search_hit_json(hit: SearchHit) -> dict[str, Any]:
    function = hit.function
    return {
        "artifact_id": hit.artifact_id,
        "version": hit.version,
        "kind": hit.kind,
        "matched_by": hit.matched_by,
        "rva": f"0x{function.rva:x}",
        "name": function.name,
        "namespace": function.namespace,
        "size": function.size,
        "parameter_count": function.parameter_count,
        "strings": [
            {"address": f"0x{item.address:x}", "value": item.value} for item in function.strings
        ],
    }


def _fetch_and_register(
    catalog: Catalog, fetcher: CorpusFetcher, spec: ArtifactSpec
) -> tuple[Artifact, FetchResult]:
    fetched = fetcher.fetch(spec)
    artifact = catalog.register(
        fetched.binary_path,
        version=spec.version,
        kind=spec.kind,
        channel=spec.channel,
    )
    return artifact, fetched


def _fetched_json(artifact: Artifact, fetched: FetchResult) -> dict[str, Any]:
    result = _artifact_json(artifact)
    result["acquisition"] = {
        "manifest_id": fetched.spec.id,
        "archive_path": str(fetched.archive_path),
        "cache_hit": fetched.cache_hit,
    }
    return result


def _analysis_backend(arguments: argparse.Namespace, project_dir: Path):
    if arguments.backend == "ida":
        install = arguments.ida_install or find_ida_install()
        if install is None:
            raise IdaUnavailableError(
                "IDA Pro was not found; set IDA_INSTALL_DIR or pass --ida-install"
            )
        return IdaBackend(install, project_dir)
    install = arguments.ghidra_install or find_ghidra_install()
    if install is None:
        raise GhidraUnavailableError(
            "Ghidra was not found; set GHIDRA_INSTALL_DIR or pass --ghidra-install"
        )
    return GhidraBackend(install, project_dir)


def _analysis_project_dir(arguments: argparse.Namespace) -> Path:
    if arguments.project_dir is not None:
        return arguments.project_dir
    # Ghidra 12.1 rejects local project paths containing dot-prefixed path
    # elements (for example, the conventional `.lens` catalog directory).
    return Path.cwd() / f"{arguments.backend}-projects"


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    with Catalog(arguments.database) as catalog:
        if arguments.command == "add":
            result: dict[str, Any] | list[dict[str, Any]] = _artifact_json(
                catalog.register(
                    arguments.path,
                    version=arguments.version,
                    kind=arguments.kind,
                    channel=arguments.channel,
                )
            )
        elif arguments.command == "fetch":
            manifest = load_manifest(arguments.manifest)
            artifact, fetched = _fetch_and_register(
                catalog,
                CorpusFetcher(arguments.cache_dir),
                manifest.artifact(arguments.artifact_id),
            )
            result = _fetched_json(artifact, fetched)
        elif arguments.command == "corpus":
            manifest = load_manifest(arguments.manifest)
            if arguments.corpus_command == "list":
                result = [
                    {
                        "id": spec.id,
                        "version": spec.version,
                        "kind": spec.kind,
                        "channel": spec.channel,
                        "source": spec.source.type,
                        "binary_sha256": spec.binary_sha256,
                    }
                    for spec in manifest.artifacts
                ]
            else:
                fetcher = CorpusFetcher(arguments.cache_dir)
                result = []
                for spec in manifest.artifacts:
                    artifact, fetched = _fetch_and_register(catalog, fetcher, spec)
                    result.append(_fetched_json(artifact, fetched))
        elif arguments.command == "list":
            result = [_artifact_json(artifact) for artifact in catalog.artifacts()]
        elif arguments.command == "search":
            result = [
                _search_hit_json(hit)
                for hit in catalog.search(arguments.query, limit=arguments.limit)
            ]
        elif arguments.command == "analyze":
            artifact = catalog.artifact(arguments.artifact_id)
            project_dir = _analysis_project_dir(arguments)
            if arguments.backend == "ida" and arguments.bsim_database is not None:
                raise ValueError("BSim indexing is only supported by the Ghidra backend")
            backend = _analysis_backend(arguments, project_dir)
            run_id = catalog.start_analysis(
                artifact.id, backend=arguments.backend, backend_version=backend.version
            )
            try:
                analysis = backend.analyze(artifact.path, timeout=arguments.timeout)
                catalog.replace_function_evidence(artifact.id, list(analysis.functions))
                if arguments.backend == "ghidra" and arguments.bsim_database is not None:
                    BSimIndex(backend.install_dir, arguments.bsim_database).index_project(
                        project_dir, analysis.project_name
                    )
            except Exception as exc:
                catalog.fail_analysis(run_id, error=str(exc))
                raise
            catalog.complete_analysis(run_id, function_count=len(analysis.functions))
            result = {
                "artifact_id": artifact.id,
                "backend": arguments.backend,
                "function_count": len(analysis.functions),
                "bsim_database": (
                    str(arguments.bsim_database.resolve())
                    if arguments.bsim_database is not None
                    else None
                ),
            }
            result[f"{arguments.backend}_version"] = analysis.backend_version
        elif arguments.command == "decompile":
            artifact = catalog.artifact(arguments.artifact_id)
            project_dir = _analysis_project_dir(arguments)
            decompilation = _analysis_backend(arguments, project_dir).decompile(
                artifact.path, arguments.rva, timeout=arguments.timeout
            )
            result = {
                "artifact_id": artifact.id,
                "rva": f"0x{decompilation.rva:x}",
                "name": decompilation.name,
                "code": decompilation.code,
            }
        else:
            install = arguments.ghidra_install or find_ghidra_install()
            if install is None:
                raise GhidraUnavailableError(
                    "Ghidra was not found; set GHIDRA_INSTALL_DIR or pass --ghidra-install"
                )
            artifact = catalog.artifact(arguments.artifact_id)
            project_dir = _analysis_project_dir(arguments)
            matches = GhidraBackend(install, project_dir).match(
                artifact.path,
                arguments.rva,
                arguments.bsim_database,
                max_matches=arguments.limit,
                similarity=arguments.min_similarity,
                significance=arguments.min_significance,
            )
            indexed_artifacts = catalog.artifacts()
            md5_cache: dict[Path, str] = {}

            def artifact_md5(candidate: Artifact) -> str:
                if candidate.path not in md5_cache:
                    md5_cache[candidate.path] = _md5(candidate.path)
                return md5_cache[candidate.path]

            result = []
            for match in matches:
                target = next(
                    (
                        candidate
                        for candidate in indexed_artifacts
                        if match.executable.endswith(f"_{candidate.identity.sha256[:12]}")
                        or match.md5.lower() == artifact_md5(candidate)
                    ),
                    None,
                )
                item = {
                    "executable": match.executable,
                    "md5": match.md5,
                    "function": match.function,
                    "address": f"0x{match.address:x}",
                    "similarity": match.similarity,
                    "significance": match.significance,
                }
                if target is not None:
                    item.update(
                        {
                            "artifact_id": target.id,
                            "version": target.version,
                            "kind": target.kind,
                            "rva": f"0x{match.address - target.identity.image_base:x}",
                        }
                    )
                result.append(item)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _md5(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "md5").hexdigest()
