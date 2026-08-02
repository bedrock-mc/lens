"""Bedrock Lens command-line interface."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .bsim import BSimIndex
from .catalog import Artifact, Catalog
from .evidence import SearchHit
from .ghidra import GhidraBackend, GhidraUnavailableError, find_ghidra_install


def _default_database() -> Path:
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return data_home / "bedrock-lens" / "lens.db"


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

    commands.add_parser("list", help="list registered binaries")

    search = commands.add_parser("search", help="search function names and referenced strings")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=50)

    analyze = commands.add_parser("analyze", help="analyze a registered binary with Ghidra")
    analyze.add_argument("artifact_id", type=int)
    analyze.add_argument("--ghidra-install", type=Path)
    analyze.add_argument("--project-dir", type=Path)
    analyze.add_argument("--timeout", type=int)
    analyze.add_argument("--bsim-database", type=Path)

    decompile = commands.add_parser("decompile", help="decompile a function by RVA")
    decompile.add_argument("artifact_id", type=int)
    decompile.add_argument("rva", type=_integer)
    decompile.add_argument("--ghidra-install", type=Path)
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
        elif arguments.command == "list":
            result = [_artifact_json(artifact) for artifact in catalog.artifacts()]
        elif arguments.command == "search":
            result = [
                _search_hit_json(hit)
                for hit in catalog.search(arguments.query, limit=arguments.limit)
            ]
        elif arguments.command == "analyze":
            install = arguments.ghidra_install or find_ghidra_install()
            if install is None:
                raise GhidraUnavailableError(
                    "Ghidra was not found; set GHIDRA_INSTALL_DIR or pass --ghidra-install"
                )
            artifact = catalog.artifact(arguments.artifact_id)
            project_dir = arguments.project_dir or arguments.database.parent / "ghidra-projects"
            backend = GhidraBackend(install, project_dir)
            run_id = catalog.start_analysis(
                artifact.id, backend="ghidra", backend_version=backend.version
            )
            try:
                analysis = backend.analyze(artifact.path, timeout=arguments.timeout)
                catalog.replace_function_evidence(artifact.id, list(analysis.functions))
                if arguments.bsim_database is not None:
                    BSimIndex(install, arguments.bsim_database).index_project(
                        project_dir, analysis.project_name
                    )
            except Exception as exc:
                catalog.fail_analysis(run_id, error=str(exc))
                raise
            catalog.complete_analysis(run_id, function_count=len(analysis.functions))
            result = {
                "artifact_id": artifact.id,
                "ghidra_version": analysis.ghidra_version,
                "function_count": len(analysis.functions),
                "bsim_database": (
                    str(arguments.bsim_database.resolve())
                    if arguments.bsim_database is not None
                    else None
                ),
            }
        elif arguments.command == "decompile":
            install = arguments.ghidra_install or find_ghidra_install()
            if install is None:
                raise GhidraUnavailableError(
                    "Ghidra was not found; set GHIDRA_INSTALL_DIR or pass --ghidra-install"
                )
            artifact = catalog.artifact(arguments.artifact_id)
            project_dir = arguments.project_dir or arguments.database.parent / "ghidra-projects"
            decompilation = GhidraBackend(install, project_dir).decompile(
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
            project_dir = arguments.project_dir or arguments.database.parent / "ghidra-projects"
            matches = GhidraBackend(install, project_dir).match(
                artifact.path,
                arguments.rva,
                arguments.bsim_database,
                max_matches=arguments.limit,
                similarity=arguments.min_similarity,
                significance=arguments.min_significance,
            )
            indexed_artifacts = catalog.artifacts()
            result = []
            for match in matches:
                target = next(
                    (
                        candidate
                        for candidate in indexed_artifacts
                        if match.executable.endswith(f"_{candidate.identity.sha256[:12]}")
                    ),
                    None,
                )
                item = {
                    "executable": match.executable,
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
