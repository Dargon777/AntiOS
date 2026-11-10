"""Independent AntiOS file inspection engine.

No ClamAV service, Windows AMSI provider, driver, network or third-party
antivirus is required. Only a known SHA-256 match is a confirmed detection.
Structural/script observations are advisory and never authorize isolation.
Input is read-only; archive members are decompressed in memory under hard budgets.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import io
import math
from pathlib import PurePosixPath
import re
import struct
import tarfile
from typing import Callable, Iterable
import zipfile
import zlib

from .engine_types import ScanOutcome

MAX_INLINE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 48 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_ARCHIVE_DIRECTORY_BYTES = 256 * 1024
MAX_ARCHIVE_DEPTH = 2
STREAM_PREVIEW_BYTES = 1024 * 1024
_SCRIPT_PREVIEW_BYTES = 2 * 1024 * 1024
_SCRIPT_EXTENSIONS = frozenset({".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".hta"})
_ZIP_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
_ARCHIVE_ERRORS = (zipfile.BadZipFile, RuntimeError, OSError, EOFError, ValueError,
                   NotImplementedError, zlib.error, struct.error)


@dataclass
class _Budget:
    members: int = field(default_factory=lambda: MAX_ARCHIVE_MEMBERS)
    bytes_left: int = field(default_factory=lambda: MAX_ARCHIVE_TOTAL_BYTES)


def _preferred(left: ScanOutcome, right: ScanOutcome) -> ScanOutcome:
    priority = {None: 0, "review": 1, "threat": 2}
    selected = right if priority.get(right.kind, 0) > priority.get(left.kind, 0) else left
    return ScanOutcome(
        selected.kind,
        selected.name,
        selected.engine,
        left.complete and right.complete,
        (left.detail or right.detail)[:500],
    )


def _archive_format(data: bytes, name: str) -> str | None:
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data[257:262] == b"ustar":
        return "tar"
    if (data.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\xfd7zXZ\x00"))
            or (data.startswith(b"BZh") and b"1" <= data[3:4] <= b"9")):
        return "unsupported"
    name = name.lower()
    if name.endswith(".zip"):
        return "zip"
    if name.endswith((".gz", ".tgz")):
        return "gzip"
    if name.endswith(".tar"):
        return "tar"
    if name.endswith((".7z", ".rar", ".bz2", ".xz")):
        return "unsupported"
    return None


def _zip_entry_count(data: bytes) -> int | None:
    """Reject oversized or malformed central directories before ZipFile loads them."""
    tail = data[-65557:]
    marker = tail.rfind(b"PK\x05\x06")
    if marker < 0 or len(tail) - marker < 22:
        return None
    disk, directory_disk, disk_members, total_members, directory_size, directory_offset, comment_size = (
        struct.unpack_from("<4H2IH", tail, marker + 4)
    )
    if marker + 22 + comment_size != len(tail):
        return None
    directory_end = len(data) - len(tail) + marker
    # Use only the ordinary single-disk directory record for bounded enumeration.
    if (disk or directory_disk or disk_members != total_members or total_members == 0xFFFF
            or directory_offset + directory_size > directory_end
            or directory_size > MAX_ARCHIVE_DIRECTORY_BYTES
            or (directory_end >= 20 and data[directory_end - 20:directory_end - 16] == b"PK\x06\x07")):
        return None
    return total_members


def _archive_path_signal(name: str) -> ScanOutcome:
    parts = PurePosixPath(name).parts
    if name.startswith("/") or ".." in parts or not parts or ":" in parts[0]:
        return ScanOutcome("review", "Suspicious archive entry path")
    return ScanOutcome()


def _entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    counts = [0] * 256
    for value in sample:
        counts[value] += 1
    length = len(sample)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def _script_signal(data: bytes, name: str) -> ScanOutcome:
    lower_name = name.replace("\\", "/").lower()
    if not any(lower_name.endswith(ext) for ext in _SCRIPT_EXTENSIONS):
        return ScanOutcome()
    complete = len(data) <= _SCRIPT_PREVIEW_BYTES
    sample = data[:_SCRIPT_PREVIEW_BYTES]
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            encoding = "utf-16-le" if sample[:2] == b"\xff\xfe" else "utf-16-be"
            sample = sample[2:].decode(encoding, errors="ignore").encode("utf-8")
        except UnicodeError:
            return ScanOutcome()
    sample = sample.lower()
    # These are context signals, not malware signatures.
    indicators = (
        b"-encodedcommand" in sample or b"frombase64string(" in sample,
        b"invoke-expression" in sample or re.search(rb"\biex\s*\(", sample) is not None,
        b"downloadstring(" in sample or b"downloadfile(" in sample,
        b"set-mppreference" in sample or b"add-mppreference" in sample,
    )
    detail = "" if complete else "Only a bounded script preview was inspected"
    if sum(indicators) >= 2:
        return ScanOutcome("review", "Script requires manual review", complete=complete, detail=detail)
    return ScanOutcome(complete=complete, detail=detail)


def _pe_signal(data: bytes) -> ScanOutcome:
    if not data.startswith(b"MZ"):
        return ScanOutcome()
    if len(data) < 64:
        return ScanOutcome("review", "Truncated executable header", "AntiOS Engine", complete=False)
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset > len(data) - 24 or data[offset:offset + 4] != b"PE\x00\x00":
        return ScanOutcome("review", "Unrecognized executable header", "AntiOS Engine", complete=False)
    sections = struct.unpack_from("<H", data, offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, offset + 20)[0]
    if sections == 0 or sections > 96 or optional_size < 2:
        return ScanOutcome("review", "Invalid executable section table", "AntiOS Engine", complete=False)
    table = offset + 24 + optional_size
    if table > len(data) or sections > (len(data) - table) // 40:
        return ScanOutcome("review", "Truncated executable section table", "AntiOS Engine", complete=False)
    for index in range(sections):
        entry = table + index * 40
        raw_size, raw_offset, flags = struct.unpack_from("<II12xI", data, entry + 16)
        executable_writable = flags & 0x20000000 and flags & 0x80000000
        if not executable_writable or raw_size < 4096:
            continue
        if raw_offset > len(data) or raw_size > len(data) - raw_offset:
            continue
        if _entropy(data[raw_offset:raw_offset + min(raw_size, 32768)]) > 7.5:
            return ScanOutcome("review", "Unusual executable section", "AntiOS Engine")
    return ScanOutcome()


class AntiOSEngine:
    """Locally owned detection engine with strict, explainable verdict classes."""

    name = "AntiOS Engine"

    def __init__(self, *, signatures: dict[str, str] | None = None) -> None:
        self._signatures = dict(signatures or {})
        if len(self._signatures) > 100_001:
            raise ValueError("Too many local signatures")
        self.metadata = {
            "version": "AntiOS Engine/0.2",
            "database_freshness": "local",
            "signature_scope": "local-sha256",
            "components": {"hashes": True, "scripts": True, "pe": True, "zip": True, "gzip": True, "tar": True},
        }

    def _inspect(self, data: bytes, name: str, *, depth: int, budget: _Budget,
                 digest: str | None = None) -> ScanOutcome:
        digest = digest if digest is not None else hashlib.sha256(data).hexdigest()
        label = self._signatures.get(digest)
        if label is not None:
            return ScanOutcome("threat", label, self.name)
        outcome = _preferred(_script_signal(data, name), _pe_signal(data))
        archive_format = _archive_format(data, name)
        if archive_format is None:
            return outcome
        if archive_format == "unsupported":
            return _preferred(outcome, ScanOutcome(
                "review", "Unsupported archive format", complete=False,
                detail="Archive contents were not inspected"))
        if depth >= MAX_ARCHIVE_DEPTH:
            return _preferred(outcome, ScanOutcome(
                "review", "Nested archive depth limit reached", self.name,
                complete=False, detail="Nested archive was not fully examined"))
        if archive_format == "gzip":
            return _preferred(outcome, self._inspect_gzip(data, name, depth, budget))
        if archive_format == "tar":
            return _preferred(outcome, self._inspect_tar(data, depth, budget))
        return _preferred(outcome, self._inspect_zip(data, depth, budget))

    def _inspect_gzip(self, data: bytes, name: str, depth: int, budget: _Budget) -> ScanOutcome:
        # Ordinary TAR padding can compress to a very small GZIP payload.
        limit = min(MAX_ARCHIVE_MEMBER_BYTES, budget.bytes_left, max(65536, len(data) * 200))
        if budget.members <= 0 or limit <= 0:
            return ScanOutcome("review", "Archive inspection budget exceeded", complete=False)
        budget.members -= 1
        budget.bytes_left -= limit
        decompressor = zlib.decompressobj(wbits=31)
        try:
            payload = decompressor.decompress(data, limit + 1)
        except zlib.error:
            return ScanOutcome("review", "Unreadable gzip archive", complete=False)
        if len(payload) > limit:
            return ScanOutcome("review", "Archive inspection budget exceeded", complete=False)
        if not decompressor.eof:
            return ScanOutcome("review", "Truncated gzip archive", complete=False)
        budget.bytes_left += limit - len(payload)
        lower = name.lower()
        inner_name = name[:-3] if lower.endswith(".gz") else ""
        if lower.endswith(".tgz"):
            inner_name = name[:-4] + ".tar"
        outcome = self._inspect(payload, inner_name, depth=depth + 1, budget=budget)
        if decompressor.unused_data.strip(b"\x00"):
            outcome = _preferred(outcome, ScanOutcome(
                "review", "Additional gzip data was not inspected", complete=False))
        return outcome

    def _inspect_tar(self, data: bytes, depth: int, budget: _Budget) -> ScanOutcome:
        block = tarfile.BLOCKSIZE
        offset = 0
        outcome = ScanOutcome()
        while offset + block <= len(data):
            header = data[offset:offset + block]
            if header == bytes(block):
                remaining = len(data) - offset
                if remaining >= 2 * block and data.count(b"\x00", offset) == remaining:
                    return outcome
                break
            if budget.members <= 0:
                return _preferred(outcome, ScanOutcome(
                    "review", "Archive entry limit reached", complete=False))
            budget.members -= 1
            try:
                member = tarfile.TarInfo.frombuf(header, "utf-8", "surrogateescape")
            except tarfile.HeaderError:
                break
            start = offset + block
            offset = start + (member.size + block - 1) // block * block
            if member.size < 0 or offset > len(data):
                break
            name = member.name.replace("\\", "/")
            if member.type == tarfile.DIRTYPE and not member.size and name == ".":
                continue
            outcome = _preferred(outcome, _archive_path_signal(name))
            if member.type == tarfile.DIRTYPE and not member.size:
                continue
            if member.type in (tarfile.SYMTYPE, tarfile.LNKTYPE) and not member.size:
                outcome = _preferred(outcome, ScanOutcome(
                    "review", "Archive link was not followed", complete=False))
                continue
            # Extension records can alter how later entries are interpreted.
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                return _preferred(outcome, ScanOutcome(
                    "review", "Unsupported TAR entry", complete=False))
            if member.size > min(MAX_ARCHIVE_MEMBER_BYTES, budget.bytes_left):
                outcome = _preferred(outcome, ScanOutcome(
                    "review", "Archive inspection budget exceeded", complete=False))
                continue
            budget.bytes_left -= member.size
            outcome = _preferred(outcome, self._inspect(
                data[start:start + member.size], name, depth=depth + 1, budget=budget))
            if outcome.kind == "threat":
                return outcome
        return _preferred(outcome, ScanOutcome("review", "Unreadable TAR archive", complete=False))

    def _inspect_zip(self, data: bytes, depth: int, budget: _Budget) -> ScanOutcome:
        declared_members = _zip_entry_count(data)
        if declared_members is None or declared_members > budget.members:
            return ScanOutcome(
                "review", "Archive directory requires manual review", self.name,
                complete=False, detail="Archive could not be safely enumerated")
        outcome = ScanOutcome()
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                if len(members) != declared_members:
                    return ScanOutcome("review", "Invalid archive directory", complete=False)
                budget.members -= len(members)
                for item in members:
                    if item.is_dir():
                        if item.file_size:
                            outcome = _preferred(outcome, ScanOutcome(
                                "review", "Archive directory entry contains data", complete=False))
                        continue
                    normalized = item.filename.replace("\\", "/")
                    outcome = _preferred(outcome, _archive_path_signal(normalized))
                    if item.flag_bits & 1:
                        outcome = _preferred(outcome, ScanOutcome(
                            "review", "Encrypted archive entry", self.name,
                            complete=False, detail="Encrypted archive member could not be inspected"))
                        continue
                    if item.compress_type not in _ZIP_METHODS:
                        outcome = _preferred(outcome, ScanOutcome(
                            "review", "Unsupported archive compression", complete=False))
                        continue
                    if (item.file_size > MAX_ARCHIVE_MEMBER_BYTES
                            or item.file_size > budget.bytes_left
                            or (item.compress_size and item.file_size > item.compress_size * 200)):
                        outcome = _preferred(outcome, ScanOutcome(
                            "review", "Archive inspection budget exceeded", self.name,
                            complete=False, detail="Archive member not inspected"))
                        continue
                    # Charge failed reads too. ZipFile verifies CRC without extracting to disk.
                    budget.bytes_left -= item.file_size
                    try:
                        with archive.open(item) as stream:
                            payload = stream.read(item.file_size + 1)
                        if len(payload) != item.file_size:
                            raise ValueError("Archive member size changed")
                    except _ARCHIVE_ERRORS:
                        outcome = _preferred(outcome, ScanOutcome(
                            "review", "Unreadable archive member", complete=False))
                        continue
                    outcome = _preferred(
                        outcome,
                        self._inspect(payload, normalized, depth=depth + 1, budget=budget),
                    )
                    if outcome.kind == "threat":
                        break
        except _ARCHIVE_ERRORS:
            outcome = _preferred(outcome, ScanOutcome(
                "review", "Unreadable archive", self.name,
                complete=False, detail="Archive inspection failed"))
        return outcome

    def scan_with_digest(self, content: bytes, name: str, digest: str) -> ScanOutcome:
        if digest in self._signatures:
            return ScanOutcome("threat", self._signatures[digest], self.name)
        if len(content) > MAX_INLINE_BYTES:
            return ScanOutcome(None, "", self.name, False,
                               "File exceeds full-content inspection budget")
        return self._inspect(content, name, depth=0, budget=_Budget(), digest=digest)

    def scan(self, content: bytes, name: str) -> ScanOutcome:
        return self.scan_with_digest(content, name, hashlib.sha256(content).hexdigest())

    def scan_stream(self, chunks: Iterable[bytes]) -> ScanOutcome:
        return self.scan_stream_named(chunks, "")

    def scan_stream_named(self, chunks: Iterable[bytes], name: str) -> ScanOutcome:
        digest = hashlib.sha256()

        def hashed_chunks():
            for chunk in chunks:
                digest.update(chunk)
                yield chunk

        return self.scan_hashed_stream(hashed_chunks(), name, digest.hexdigest)

    def scan_hashed_stream(self, chunks: Iterable[bytes], name: str,
                           get_digest: Callable[[], str]) -> ScanOutcome:
        """Inspect a stream whose producer hashes the exact bytes it yields."""
        prefix = bytearray()
        size = 0
        for chunk in chunks:
            size += len(chunk)
            if len(prefix) < STREAM_PREVIEW_BYTES:
                prefix.extend(chunk[:STREAM_PREVIEW_BYTES - len(prefix)])
        sha = get_digest()
        if sha in self._signatures:
            return ScanOutcome("threat", self._signatures[sha], self.name)
        content = bytes(prefix)
        if size == len(content):
            return self.scan_with_digest(content, name, sha)
        advisory = _preferred(_script_signal(content, name), _pe_signal(content))
        return ScanOutcome(advisory.kind, advisory.name, self.name, False,
                           "Only local hash and bounded content preview were available")

    def close(self) -> None:
        pass
