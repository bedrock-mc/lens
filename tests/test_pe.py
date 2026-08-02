from __future__ import annotations

import struct
import uuid
from pathlib import Path

from bedrock_lens.pe import inspect_pe


def write_pe_with_rsds(path: Path) -> None:
    pdb_guid = uuid.UUID("603c336c-4fcb-4ec3-b5e2-ecb754278979")
    rsds = b"RSDS" + pdb_guid.bytes_le + struct.pack("<I", 1) + b"Minecraft.Windows.pdb\0"

    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"

    coff = 0x84
    struct.pack_into("<HHIIIHH", image, coff, 0x8664, 1, 0x655F3C98, 0, 0, 0xF0, 0x22)

    optional = coff + 20
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<I", image, optional + 56, 0x5000)
    struct.pack_into("<I", image, optional + 108, 16)
    struct.pack_into("<II", image, optional + 112 + (6 * 8), 0x1000, 28)

    section = optional + 0xF0
    struct.pack_into(
        "<8sIIIIIIHHI",
        image,
        section,
        b".rdata\0\0",
        0x200,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    struct.pack_into(
        "<IIHHIIII",
        image,
        0x200,
        0,
        0x655F3C98,
        0,
        0,
        2,
        len(rsds),
        0x1020,
        0x220,
    )
    image[0x220 : 0x220 + len(rsds)] = rsds
    path.write_bytes(image)


def test_inspect_pe_extracts_binary_and_pdb_identity(tmp_path: Path) -> None:
    binary = tmp_path / "Minecraft.Windows.exe"
    write_pe_with_rsds(binary)

    identity = inspect_pe(binary)

    assert identity.machine == "amd64"
    assert identity.timestamp == 0x655F3C98
    assert identity.image_base == 0x140000000
    assert identity.image_size == 0x5000
    assert identity.file_size == 0x400
    assert len(identity.sha256) == 64
    assert identity.pdb is not None
    assert identity.pdb.name == "Minecraft.Windows.pdb"
    assert identity.pdb.guid == "603c336c-4fcb-4ec3-b5e2-ecb754278979"
    assert identity.pdb.age == 1
