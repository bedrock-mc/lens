"""Analysis evidence exchanged between backends and the catalog."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StringEvidence:
    address: int
    value: str


@dataclass(frozen=True, slots=True)
class FunctionEvidence:
    rva: int
    name: str
    namespace: str
    size: int
    parameter_count: int
    strings: tuple[StringEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class SearchHit:
    artifact_id: int
    version: str
    kind: str
    function: FunctionEvidence
    matched_by: str


@dataclass(frozen=True, slots=True)
class AnalysisRun:
    id: int
    artifact_id: int
    backend: str
    backend_version: str
    status: str
    function_count: int | None
    error: str | None
