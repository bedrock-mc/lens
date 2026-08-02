"""Portable Executable identity extraction without loading the full image into memory."""

from __future__ import annotations

import hashlib
import mmap
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath


class PEFormatError(ValueError):
    """Raised when a file is not a supported, well-formed PE image."""


@dataclass(frozen=True, slots=True)
class PdbIdentity:
    name: str
    guid: str
    age: int
    path: str


@dataclass(frozen=True, slots=True)
class PEIdentity:
    sha256: str
    file_size: int
    machine: str
    timestamp: int
    image_base: int
    image_size: int
    pdb: PdbIdentity | None


_MACHINES = {
    0x014C: "i386",
    0x8664: "amd64",
    0xAA64: "arm64",
}


def _unpack_from(format_: str, image: mmap.mmap, offset: int) -> tuple[int, ...]:
    try:
        return struct.unpack_from(format_, image, offset)
    except (struct.error, ValueError) as exc:
        raise PEFormatError("truncated PE image") from exc


def _rva_to_offset(rva: int, sections: list[tuple[int, int, int, int]], header_size: int) -> int:
    if rva < header_size:
        return rva
    for virtual_address, virtual_size, raw_offset, raw_size in sections:
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            return raw_offset + (rva - virtual_address)
    raise PEFormatError(f"RVA 0x{rva:x} is not mapped by any section")


def _read_pdb_identity(
    image: mmap.mmap,
    debug_rva: int,
    debug_size: int,
    sections: list[tuple[int, int, int, int]],
    header_size: int,
) -> PdbIdentity | None:
    debug_offset = _rva_to_offset(debug_rva, sections, header_size)
    for offset in range(debug_offset, debug_offset + debug_size, 28):
        if offset + 28 > len(image):
            raise PEFormatError("truncated debug directory")
        _, _, _, _, debug_type, data_size, data_rva, data_offset = _unpack_from(
            "<IIHHIIII", image, offset
        )
        if debug_type != 2 or data_size < 24:
            continue
        if not data_offset:
            data_offset = _rva_to_offset(data_rva, sections, header_size)
        if data_offset + data_size > len(image):
            raise PEFormatError("truncated CodeView record")
        record = image[data_offset : data_offset + data_size]
        if record[:4] != b"RSDS":
            continue
        raw_path = record[24:].split(b"\0", 1)[0].decode("utf-8", errors="replace")
        return PdbIdentity(
            name=PureWindowsPath(raw_path).name,
            guid=str(uuid.UUID(bytes_le=record[4:20])),
            age=struct.unpack_from("<I", record, 20)[0],
            path=raw_path,
        )
    return None


def inspect_pe(path: str | Path) -> PEIdentity:
    """Extract stable binary and CodeView identities from a PE image."""
    binary_path = Path(path)
    with binary_path.open("rb") as binary:
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
        binary.seek(0)
        try:
            with mmap.mmap(binary.fileno(), 0, access=mmap.ACCESS_READ) as image:
                if len(image) < 64 or image[:2] != b"MZ":
                    raise PEFormatError("missing DOS header")
                (pe_offset,) = _unpack_from("<I", image, 0x3C)
                if pe_offset + 24 > len(image) or image[pe_offset : pe_offset + 4] != b"PE\0\0":
                    raise PEFormatError("missing PE signature")

                coff_offset = pe_offset + 4
                machine, section_count, timestamp, _, _, optional_size, _ = _unpack_from(
                    "<HHIIIHH", image, coff_offset
                )
                optional_offset = coff_offset + 20
                (optional_magic,) = _unpack_from("<H", image, optional_offset)
                if optional_magic == 0x20B:
                    directory_count_offset = 108
                    directories_offset = 112
                    (image_base,) = _unpack_from("<Q", image, optional_offset + 24)
                elif optional_magic == 0x10B:
                    directory_count_offset = 92
                    directories_offset = 96
                    (image_base,) = _unpack_from("<I", image, optional_offset + 28)
                else:
                    raise PEFormatError(f"unsupported optional header 0x{optional_magic:x}")

                (image_size,) = _unpack_from("<I", image, optional_offset + 56)
                (header_size,) = _unpack_from("<I", image, optional_offset + 60)
                (directory_count,) = _unpack_from(
                    "<I", image, optional_offset + directory_count_offset
                )

                section_offset = optional_offset + optional_size
                sections: list[tuple[int, int, int, int]] = []
                for index in range(section_count):
                    current = section_offset + (index * 40)
                    virtual_size, virtual_address, raw_size, raw_offset = _unpack_from(
                        "<IIII", image, current + 8
                    )
                    sections.append((virtual_address, virtual_size, raw_offset, raw_size))

                pdb = None
                if directory_count > 6:
                    debug_directory = optional_offset + directories_offset + (6 * 8)
                    debug_rva, debug_size = _unpack_from("<II", image, debug_directory)
                    if debug_rva and debug_size:
                        pdb = _read_pdb_identity(
                            image, debug_rva, debug_size, sections, header_size
                        )
        except ValueError as exc:
            if isinstance(exc, PEFormatError):
                raise
            raise PEFormatError("empty PE image") from exc

    return PEIdentity(
        sha256=digest,
        file_size=binary_path.stat().st_size,
        machine=_MACHINES.get(machine, f"unknown-0x{machine:04x}"),
        timestamp=timestamp,
        image_base=image_base,
        image_size=image_size,
        pdb=pdb,
    )
