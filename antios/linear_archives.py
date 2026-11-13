"""Bounded member offsets for in-memory ar and newc/CRC CPIO archives."""
from __future__ import annotations

from dataclasses import dataclass
import stat
import struct
from typing import Iterator


AR_MAGIC = b"!<arch>\n"
THIN_AR_MAGIC = b"!<thin>\n"
CPIO_MAGICS = (b"070701", b"070702")
RPM_MAGIC = b"\xed\xab\xee\xdb"
_MAX_NAME = 4096
_HEX_BYTES = frozenset(b"0123456789ABCDEFabcdef")


@dataclass(frozen=True)
class ArchiveEntry:
    name: str
    start: int
    end: int
    kind: str = "file"
    checksum: int | None = None


def _decimal(value: bytes) -> int:
    value = value.strip(b" ")
    if not value.isdigit():
        raise ValueError("Invalid ar numeric field")
    return int(value)


def ar_entries(data: bytes, directory_limit: int) -> Iterator[ArchiveEntry]:
    if not data.startswith(AR_MAGIC):
        raise ValueError("Invalid ar header")
    offset = len(AR_MAGIC)
    names = b""
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:] != b"\x60\n":
            raise ValueError("Invalid ar member header")
        raw_name = header[:16].rstrip(b" ")
        size = _decimal(header[48:58])
        start, end = offset + 60, offset + 60 + size
        offset = end + (size % 2)
        if offset > len(data) or (size % 2 and data[end] != 0x0A):
            raise ValueError("Truncated or invalid ar member")
        if raw_name == b"//":
            if names or size > directory_limit:
                raise ValueError("Invalid or oversized ar name table")
            names = data[start:end]
            yield ArchiveEntry("", start, end, "metadata")
            continue
        if raw_name in (b"/", b"/SYM64/"):
            yield ArchiveEntry("", start, end, "metadata")
            continue
        if raw_name.startswith(b"#1/"):
            name_size = _decimal(raw_name[3:])
            if not 0 < name_size <= min(size, _MAX_NAME):
                raise ValueError("Invalid ar member name length")
            raw_name = data[start:start + name_size].rstrip(b"\x00")
            start += name_size
        elif raw_name.startswith(b"/"):
            index = _decimal(raw_name[1:])
            if index >= len(names) or (index and names[index - 1] not in (0, 0x0A)):
                raise ValueError("Invalid ar name table reference")
            name = names[index:index + _MAX_NAME + 2]
            end_markers = (name.find(b"/\n"), name.find(b"\x00"))
            terminators = [index for index in end_markers if index >= 0]
            if not terminators:
                raise ValueError("Unterminated ar member name")
            raw_name = name[:min(terminators)]
        else:
            raw_name = raw_name.removesuffix(b"/")
        if not raw_name or len(raw_name) > _MAX_NAME or b"\x00" in raw_name:
            raise ValueError("Invalid ar member name")
        name = raw_name.decode("utf-8", "surrogateescape")
        kind = "metadata" if name in {"__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "__.SYMDEF_64 SORTED"} else "file"
        yield ArchiveEntry(name, start, end, kind)


def cpio_entries(data: bytes) -> Iterator[ArchiveEntry]:
    offset = 0
    while offset + 110 <= len(data):
        header = data[offset:offset + 110]
        magic, fields = header[:6], header[6:]
        if magic not in CPIO_MAGICS or any(byte not in _HEX_BYTES for byte in fields):
            break
        mode = int(fields[8:16], 16)
        links = int(fields[32:40], 16)
        size = int(fields[48:56], 16)
        name_size = int(fields[88:96], 16)
        checksum = int(fields[96:104], 16)
        if not 1 < name_size <= _MAX_NAME or (magic == b"070701" and checksum):
            break
        name_start = offset + 110
        name_end = name_start + name_size
        start = (name_end + 3) & ~3
        end = start + size
        offset = (end + 3) & ~3
        if offset > len(data) or data[name_end - 1] != 0:
            break
        raw_name = data[name_start:name_end].rstrip(b"\x00")
        if not raw_name or b"\x00" in raw_name:
            break
        if raw_name == b"TRAILER!!!":
            if size == 0 and data.count(b"\x00", offset) == len(data) - offset:
                return
            break
        name = raw_name.decode("utf-8", "surrogateescape")
        if stat.S_ISREG(mode):
            kind = "link" if links > 1 and not size else "file"
        elif stat.S_ISDIR(mode) and not size:
            kind = "directory"
        elif stat.S_ISLNK(mode):
            kind = "link"
        else:
            kind = "special"
        yield ArchiveEntry(name, start, end, kind, checksum if magic == b"070702" else None)
    raise ValueError("Incomplete or unsupported CPIO data")


def rpm_payload_start(data: bytes, directory_limit: int) -> int:
    """Locate the RPM payload without interpreting untrusted metadata tags."""
    if not data.startswith(RPM_MAGIC) or len(data) < 96 or data[4] not in (3, 4):
        raise ValueError("Invalid or unsupported RPM lead")
    start = 96
    for signature in (True, False):
        if start + 16 > len(data) or data[start:start + 8] != b"\x8e\xad\xe8\x01\x00\x00\x00\x00":
            raise ValueError("Invalid RPM header magic")
        entries, store_size = struct.unpack_from(">II", data, start + 8)
        header_size = 16 + entries * 16 + store_size
        end = start + header_size
        if header_size > directory_limit or end >= len(data):
            raise ValueError("Invalid or oversized RPM header")
        start = ((end + 7) & ~7) if signature else end
        if data[end:start].strip(b"\x00"):
            raise ValueError("Invalid RPM signature padding")
    return start
