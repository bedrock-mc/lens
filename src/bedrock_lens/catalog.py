"""Persistent artifact catalog."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from .evidence import AnalysisRun, FunctionEvidence, SearchHit, StringEvidence
from .pe import PdbIdentity, PEIdentity, inspect_pe


@dataclass(frozen=True, slots=True)
class Artifact:
    id: int
    version: str
    kind: str
    channel: str
    path: Path
    identity: PEIdentity


class Catalog:
    """SQLite catalog of immutable binaries and their release metadata."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.path)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS binaries (
                sha256 TEXT PRIMARY KEY,
                file_size INTEGER NOT NULL,
                machine TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                image_base INTEGER NOT NULL,
                image_size INTEGER NOT NULL,
                pdb_name TEXT,
                pdb_guid TEXT,
                pdb_age INTEGER,
                pdb_path TEXT
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY,
                version TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('client', 'server')),
                channel TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL REFERENCES binaries(sha256),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (version, kind, channel, sha256)
            );

            CREATE INDEX IF NOT EXISTS artifacts_version_idx
                ON artifacts(version, kind, channel);

            CREATE TABLE IF NOT EXISTS functions (
                id INTEGER PRIMARY KEY,
                artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
                rva INTEGER NOT NULL,
                name TEXT NOT NULL,
                namespace TEXT NOT NULL,
                size INTEGER NOT NULL,
                parameter_count INTEGER NOT NULL,
                UNIQUE (artifact_id, rva)
            );

            CREATE INDEX IF NOT EXISTS functions_name_idx
                ON functions(name COLLATE NOCASE);

            CREATE TABLE IF NOT EXISTS function_strings (
                function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
                address INTEGER NOT NULL,
                value TEXT NOT NULL,
                UNIQUE (function_id, address, value)
            );

            CREATE INDEX IF NOT EXISTS function_strings_value_idx
                ON function_strings(value COLLATE NOCASE);

            CREATE TABLE IF NOT EXISTS analysis_runs (
                id INTEGER PRIMARY KEY,
                artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
                backend TEXT NOT NULL,
                backend_version TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed')),
                started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                function_count INTEGER,
                error TEXT
            );
            """
        )

    def __enter__(self) -> Catalog:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def register(
        self,
        path: str | Path,
        *,
        version: str,
        kind: str,
        channel: str = "retail",
    ) -> Artifact:
        if kind not in {"client", "server"}:
            raise ValueError("kind must be 'client' or 'server'")
        if not version.strip():
            raise ValueError("version must not be empty")
        if not channel.strip():
            raise ValueError("channel must not be empty")

        binary_path = Path(path).expanduser().resolve(strict=True)
        identity = inspect_pe(binary_path)
        pdb = identity.pdb
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO binaries (
                    sha256, file_size, machine, timestamp, image_base, image_size,
                    pdb_name, pdb_guid, pdb_age, pdb_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (sha256) DO NOTHING
                """,
                (
                    identity.sha256,
                    identity.file_size,
                    identity.machine,
                    identity.timestamp,
                    identity.image_base,
                    identity.image_size,
                    pdb.name if pdb else None,
                    pdb.guid if pdb else None,
                    pdb.age if pdb else None,
                    pdb.path if pdb else None,
                ),
            )
            row = self._connection.execute(
                """
                INSERT INTO artifacts (version, kind, channel, path, sha256)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (version, kind, channel, sha256)
                DO UPDATE SET path = excluded.path
                RETURNING id
                """,
                (version, kind, channel, str(binary_path), identity.sha256),
            ).fetchone()
        if row is None:
            raise RuntimeError("SQLite did not return an artifact ID")
        return self.artifact(row["id"])

    def artifacts(self) -> list[Artifact]:
        rows = self._connection.execute(f"{_ARTIFACT_SELECT} ORDER BY a.id").fetchall()
        return [_artifact_from_row(row) for row in rows]

    def replace_function_evidence(
        self, artifact_id: int, functions: list[FunctionEvidence]
    ) -> None:
        with self._connection:
            self._connection.execute("DELETE FROM functions WHERE artifact_id = ?", (artifact_id,))
            for function in functions:
                row = self._connection.execute(
                    """
                    INSERT INTO functions (
                        artifact_id, rva, name, namespace, size, parameter_count
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    RETURNING id
                    """,
                    (
                        artifact_id,
                        function.rva,
                        function.name,
                        function.namespace,
                        function.size,
                        function.parameter_count,
                    ),
                ).fetchone()
                if row is None:
                    raise RuntimeError("SQLite did not return a function ID")
                self._connection.executemany(
                    """
                    INSERT INTO function_strings (function_id, address, value)
                    VALUES (?, ?, ?)
                    """,
                    ((row["id"], string.address, string.value) for string in function.strings),
                )

    def search(self, query: str, *, limit: int = 50) -> list[SearchHit]:
        if not query.strip():
            raise ValueError("query must not be empty")
        rows = self._connection.execute(
            """
            SELECT
                f.id, f.artifact_id, a.version, a.kind,
                f.rva, f.name, f.namespace, f.size, f.parameter_count,
                CASE
                    WHEN instr(lower(f.name), lower(?)) > 0
                      OR instr(lower(f.namespace), lower(?)) > 0
                    THEN 'symbol'
                    ELSE 'string'
                END AS matched_by
            FROM functions AS f
            JOIN artifacts AS a ON a.id = f.artifact_id
            WHERE instr(lower(f.name), lower(?)) > 0
               OR instr(lower(f.namespace), lower(?)) > 0
               OR EXISTS (
                    SELECT 1
                    FROM function_strings AS fs
                    WHERE fs.function_id = f.id
                      AND instr(lower(fs.value), lower(?)) > 0
               )
            ORDER BY
                CASE WHEN lower(f.name) = lower(?) THEN 0 ELSE 1 END,
                a.version DESC,
                f.rva
            LIMIT ?
            """,
            (query, query, query, query, query, query, limit),
        ).fetchall()

        hits: list[SearchHit] = []
        for row in rows:
            string_rows = self._connection.execute(
                """
                SELECT address, value
                FROM function_strings
                WHERE function_id = ?
                ORDER BY address, value
                """,
                (row["id"],),
            ).fetchall()
            hits.append(
                SearchHit(
                    artifact_id=row["artifact_id"],
                    version=row["version"],
                    kind=row["kind"],
                    function=FunctionEvidence(
                        rva=row["rva"],
                        name=row["name"],
                        namespace=row["namespace"],
                        size=row["size"],
                        parameter_count=row["parameter_count"],
                        strings=tuple(
                            StringEvidence(address=item["address"], value=item["value"])
                            for item in string_rows
                        ),
                    ),
                    matched_by=row["matched_by"],
                )
            )
        return hits

    def start_analysis(self, artifact_id: int, *, backend: str, backend_version: str) -> int:
        with self._connection:
            row = self._connection.execute(
                """
                INSERT INTO analysis_runs (artifact_id, backend, backend_version, status)
                VALUES (?, ?, ?, 'running')
                RETURNING id
                """,
                (artifact_id, backend, backend_version),
            ).fetchone()
        if row is None:
            raise RuntimeError("SQLite did not return an analysis run ID")
        return row["id"]

    def complete_analysis(self, run_id: int, *, function_count: int) -> None:
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE analysis_runs
                SET status = 'complete', completed_at = CURRENT_TIMESTAMP, function_count = ?
                WHERE id = ? AND status = 'running'
                """,
                (function_count, run_id),
            )
        if cursor.rowcount != 1:
            raise KeyError(run_id)

    def fail_analysis(self, run_id: int, *, error: str) -> None:
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE analysis_runs
                SET status = 'failed', completed_at = CURRENT_TIMESTAMP, error = ?
                WHERE id = ? AND status = 'running'
                """,
                (error, run_id),
            )
        if cursor.rowcount != 1:
            raise KeyError(run_id)

    def analysis_runs(self, artifact_id: int) -> list[AnalysisRun]:
        rows = self._connection.execute(
            """
            SELECT id, artifact_id, backend, backend_version, status, function_count, error
            FROM analysis_runs
            WHERE artifact_id = ?
            ORDER BY id
            """,
            (artifact_id,),
        ).fetchall()
        return [
            AnalysisRun(
                id=row["id"],
                artifact_id=row["artifact_id"],
                backend=row["backend"],
                backend_version=row["backend_version"],
                status=row["status"],
                function_count=row["function_count"],
                error=row["error"],
            )
            for row in rows
        ]

    def artifact(self, artifact_id: int) -> Artifact:
        row = self._connection.execute(
            f"{_ARTIFACT_SELECT} WHERE a.id = ?", (artifact_id,)
        ).fetchone()
        if row is None:
            raise KeyError(artifact_id)
        return _artifact_from_row(row)


_ARTIFACT_SELECT = """
    SELECT
        a.id, a.version, a.kind, a.channel, a.path,
        b.sha256, b.file_size, b.machine, b.timestamp, b.image_base, b.image_size,
        b.pdb_name, b.pdb_guid, b.pdb_age, b.pdb_path
    FROM artifacts AS a
    JOIN binaries AS b ON b.sha256 = a.sha256
"""


def _artifact_from_row(row: sqlite3.Row) -> Artifact:
    pdb = None
    if row["pdb_guid"] is not None:
        pdb = PdbIdentity(
            name=row["pdb_name"],
            guid=row["pdb_guid"],
            age=row["pdb_age"],
            path=row["pdb_path"],
        )
    return Artifact(
        id=row["id"],
        version=row["version"],
        kind=row["kind"],
        channel=row["channel"],
        path=Path(row["path"]),
        identity=PEIdentity(
            sha256=row["sha256"],
            file_size=row["file_size"],
            machine=row["machine"],
            timestamp=row["timestamp"],
            image_base=row["image_base"],
            image_size=row["image_size"],
            pdb=pdb,
        ),
    )
