"""Reproducible acquisition and verification of Bedrock binary corpora."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tomllib
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request, urlopen

from .pe import inspect_pe
from .sources import resolve_store_download_url, tls_context

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(RuntimeError):
    """Raised when downloaded content does not match its immutable manifest identity."""


@dataclass(frozen=True, slots=True)
class SourceSpec:
    type: str
    url: str | None = None
    update_id: str | None = None
    revision: int = 1


@dataclass(frozen=True, slots=True)
class ArtifactSpec:
    id: str
    version: str
    kind: str
    channel: str
    archive_sha256: str
    binary_sha256: str
    member: str
    source: SourceSpec
    pdb_guid: str | None = None
    pdb_age: int | None = None
    machine: str | None = None


@dataclass(frozen=True, slots=True)
class CorpusManifest:
    artifacts: tuple[ArtifactSpec, ...]

    def artifact(self, artifact_id: str) -> ArtifactSpec:
        try:
            return next(item for item in self.artifacts if item.id == artifact_id)
        except StopIteration as exc:
            raise KeyError(f"artifact is not in the corpus manifest: {artifact_id}") from exc


@dataclass(frozen=True, slots=True)
class FetchResult:
    spec: ArtifactSpec
    archive_path: Path
    binary_path: Path
    cache_hit: bool


def _required(table: dict[str, object], name: str, expected: type) -> object:
    value = table.get(name)
    if not isinstance(value, expected):
        raise ValueError(f"manifest field {name!r} must be {expected.__name__}")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value.lower()) is None:
        raise ValueError(f"manifest field {name!r} must be a 64-digit SHA-256")
    return value.lower()


def _parse_source(table: object) -> SourceSpec:
    if not isinstance(table, dict):
        raise ValueError("manifest artifact source must be a table")
    source_type = _required(table, "type", str)
    if source_type == "url":
        return SourceSpec(type=source_type, url=str(_required(table, "url", str)))
    if source_type == "store":
        update_id = str(_required(table, "update_id", str))
        uuid.UUID(update_id)
        revision = table.get("revision", 1)
        if not isinstance(revision, int) or revision < 1:
            raise ValueError("Store source revision must be a positive integer")
        return SourceSpec(type=source_type, update_id=update_id, revision=revision)
    raise ValueError(f"unsupported corpus source type: {source_type}")


def load_manifest(path: str | Path) -> CorpusManifest:
    manifest_path = Path(path).expanduser().resolve(strict=True)
    with manifest_path.open("rb") as stream:
        data = tomllib.load(stream)
    if data.get("schema") != 1:
        raise ValueError("unsupported corpus manifest schema (expected 1)")
    tables = data.get("artifact")
    if not isinstance(tables, list):
        raise ValueError("manifest must contain one or more [[artifact]] tables")

    artifacts: list[ArtifactSpec] = []
    seen: set[str] = set()
    for table in tables:
        if not isinstance(table, dict):
            raise ValueError("each artifact must be a table")
        artifact_id = str(_required(table, "id", str))
        if not artifact_id or artifact_id in seen:
            raise ValueError(f"artifact IDs must be non-empty and unique: {artifact_id!r}")
        seen.add(artifact_id)
        kind = str(_required(table, "kind", str))
        if kind not in {"client", "server"}:
            raise ValueError("artifact kind must be 'client' or 'server'")
        member = str(_required(table, "member", str))
        member_path = Path(member)
        if (
            not member
            or member_path.is_absolute()
            or member_path.name in {"", ".", ".."}
            or ".." in member_path.parts
        ):
            raise ValueError("artifact member must be a relative file path without '..'")
        pdb_guid = table.get("pdb_guid")
        if pdb_guid is not None:
            if not isinstance(pdb_guid, str):
                raise ValueError("artifact pdb_guid must be a UUID string")
            pdb_guid = str(uuid.UUID(pdb_guid))
        machine = table.get("machine")
        if machine is not None and not isinstance(machine, str):
            raise ValueError("artifact machine must be a string")
        pdb_age = table.get("pdb_age")
        if pdb_age is not None and (not isinstance(pdb_age, int) or pdb_age < 0):
            raise ValueError("artifact pdb_age must be a non-negative integer")
        artifacts.append(
            ArtifactSpec(
                id=artifact_id,
                version=str(_required(table, "version", str)),
                kind=kind,
                channel=str(table.get("channel", "retail")),
                archive_sha256=_digest(table.get("archive_sha256"), "archive_sha256"),
                binary_sha256=_digest(table.get("binary_sha256"), "binary_sha256"),
                member=member,
                source=_parse_source(table.get("source")),
                pdb_guid=pdb_guid,
                pdb_age=pdb_age,
                machine=machine,
            )
        )
    return CorpusManifest(tuple(artifacts))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CorpusFetcher:
    """Fetch packages into a content-addressed cache and verify extracted PE files."""

    def __init__(self, cache_dir: str | Path):
        self.cache_dir = Path(cache_dir).expanduser().resolve()

    def fetch(self, spec: ArtifactSpec) -> FetchResult:
        archive_path = self.cache_dir / "blobs" / "sha256" / spec.archive_sha256
        binary_path = (
            self.cache_dir
            / "artifacts"
            / "sha256"
            / spec.binary_sha256
            / Path(spec.member).name
        )
        archive_cached = archive_path.is_file() and self._matches(
            archive_path, spec.archive_sha256
        )
        binary_cached = binary_path.is_file() and self._matches(binary_path, spec.binary_sha256)

        if not archive_cached:
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            self._download(self._resolve_url(spec.source), archive_path, spec.id)
            self._verify_digest(archive_path, spec.archive_sha256, "archive")
        if not binary_cached:
            binary_path.parent.mkdir(parents=True, exist_ok=True)
            self._extract(archive_path, spec.member, binary_path)
            try:
                self._verify_digest(binary_path, spec.binary_sha256, "binary")
            except Exception:
                binary_path.unlink(missing_ok=True)
                raise

        identity = inspect_pe(binary_path)
        if spec.machine is not None and identity.machine != spec.machine:
            raise VerificationError(
                f"binary machine mismatch: expected {spec.machine}, got {identity.machine}"
            )
        if spec.pdb_guid is not None:
            actual = identity.pdb.guid if identity.pdb else None
            if actual != spec.pdb_guid:
                raise VerificationError(
                    f"binary PDB GUID mismatch: expected {spec.pdb_guid}, got {actual}"
                )
        if spec.pdb_age is not None:
            actual_age = identity.pdb.age if identity.pdb else None
            if actual_age != spec.pdb_age:
                raise VerificationError(
                    f"binary PDB age mismatch: expected {spec.pdb_age}, got {actual_age}"
                )
        return FetchResult(
            spec=spec,
            archive_path=archive_path,
            binary_path=binary_path,
            cache_hit=archive_cached and binary_cached,
        )

    @staticmethod
    def _matches(path: Path, expected: str) -> bool:
        return sha256_file(path) == expected

    @staticmethod
    def _verify_digest(path: Path, expected: str, label: str) -> None:
        actual = sha256_file(path)
        if actual != expected:
            raise VerificationError(
                f"{label} SHA-256 mismatch: expected {expected}, got {actual}"
            )

    @staticmethod
    def _resolve_url(source: SourceSpec) -> str:
        if source.type == "url" and source.url is not None:
            return source.url
        if source.type == "store" and source.update_id is not None:
            return resolve_store_download_url(source.update_id, revision=source.revision)
        raise ValueError(f"incomplete source specification: {source.type}")

    def _download(self, url: str, destination: Path, artifact_id: str) -> None:
        temporary_dir = self.cache_dir / "tmp"
        temporary_dir.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^a-zA-Z0-9_.-]", "_", artifact_id)
        partial = temporary_dir / f"{safe_id}.part"
        offset = partial.stat().st_size if partial.exists() else 0
        headers = {"User-Agent": "Bedrock-Lens/0.1"}
        if offset:
            headers["Range"] = f"bytes={offset}-"
        request = Request(url, headers=headers)
        with urlopen(request, timeout=120, context=tls_context()) as response:
            status = getattr(response, "status", None)
            append = offset > 0 and status == 206
            mode = "ab" if append else "wb"
            with partial.open(mode) as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
        os.replace(partial, destination)

    @staticmethod
    def _extract(archive: Path, member: str, destination: Path) -> None:
        temporary = destination.with_suffix(destination.suffix + ".part")
        temporary.unlink(missing_ok=True)
        try:
            with zipfile.ZipFile(archive) as package:
                try:
                    info = package.getinfo(member)
                except KeyError as exc:
                    raise VerificationError(f"archive member is missing: {member}") from exc
                if info.is_dir():
                    raise VerificationError(f"archive member is not a file: {member}")
                with package.open(info) as source, temporary.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
