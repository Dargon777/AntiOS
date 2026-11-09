"""Independent AntiOS file inspection engine.

No ClamAV service, Windows AMSI provider, driver, network or third-party
antivirus is required. Only a known SHA-256 match is a confirmed detection.
Structural/script observations are advisory and never authorize isolation.
Input is read-only; ZIP members are decompressed in memory under hard budgets.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import math
from pathlib import PurePosixPath
import re
import struct
import zipfile
import zlib

from .engine_types import ScanOutcome

MAX_INLINE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 48 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_ARCHIVE_DEPTH = 2
STREAM_PREVIEW_BYTES = 1024 * 1024
_SCRIPT_EXTENSIONS = frozenset({".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".hta"})


@dataclass
class _Budget:
    members: int = MAX_ARCHIVE_MEMBERS
    bytes_left: int = MAX_ARCHIVE_TOTAL_BYTES


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


def _looks_zip(data: bytes, name: str) -> bool:
    return data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")) or name.lower().endswith(".zip")


def _zip_entry_count(data: bytes) -> int | None:
    """Reject oversized or malformed central directories before ZipFile loads them."""
    tail = data[-65557:]
    marker = tail.rfind(b"PK\x05\x06")
    if marker < 0 or len(tail) - marker < 22:
        return None
    comment_size = struct.unpack_from("<H", tail, marker + 20)[0]
    if marker + 22 + comment_size != len(tail):
        return None
    return struct.unpack_from("<H", tail, marker + 10)[0]


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
    sample = data[:2 * 1024 * 1024]
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
    if sum(indicators) >= 2:
        return ScanOutcome("review", "Script requires manual review", "AntiOS Engine")
    return ScanOutcome()


def _pe_signal(data: bytes) -> ScanOutcome:
    if not data.startswith(b"MZ"):
        return ScanOutcome()
    if len(data) < 64:
        return ScanOutcome("review", "Truncated executable header", "AntiOS native", complete=False)
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset > len(data) - 24 or data[offset:offset + 4] != b"PE\x00\x00":
        return ScanOutcome("review", "Unrecognized executable header", "AntiOS native", complete=False)
    sections = struct.unpack_from("<H", data, offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, offset + 20)[0]
    if sections == 0 or sections > 96 or optional_size < 2:
        return ScanOutcome("review", "Invalid executable section table", "AntiOS native", complete=False)
    table = offset + 24 + optional_size
    if table > len(data) or sections > (len(data) - table) // 40:
        return ScanOutcome("review", "Truncated executable section table", "AntiOS native", complete=False)
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
            "version": "AntiOS Engine/0.1",
            "database_freshness": "local",
            "signature_scope": "local-sha256",
            "components": {"hashes": True, "scripts": True, "pe": True, "zip": True},
        }

    def _inspect(self, data: bytes, name: str, *, depth: int, budget: _Budget,
                 digest: str | None = None) -> ScanOutcome:
        digest = digest if digest is not None else hashlib.sha256(data).hexdigest()
        label = self._signatures.get(digest)
        if label is not None:
            return ScanOutcome("threat", label, self.name)
        outcome = _preferred(_script_signal(data, name), _pe_signal(data))
        if not _looks_zip(data, name):
            return outcome
        if depth >= MAX_ARCHIVE_DEPTH:
            return _preferred(outcome, ScanOutcome(
                "review", "Nested archive depth limit reached", self.name,
                complete=False, detail="Nested archive was not fully examined"))
        declared_members = _zip_entry_count(data)
        if (declared_members is None or declared_members == 0xFFFF
                or declared_members > budget.members):
            return _preferred(outcome, ScanOutcome(
                "review", "Archive directory requires manual review", self.name,
                complete=False, detail="Archive could not be safely enumerated"))
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r", allowZip64=True) as archive:
                for item in archive.infolist():
                    if item.is_dir():
                        continue
                    if budget.members <= 0:
                        return _preferred(outcome, ScanOutcome(
                            "review", "Archive entry limit reached", self.name, complete=False))
                    budget.members -= 1
                    normalized = item.filename.replace("\\", "/")
                    parts = PurePosixPath(normalized).parts
                    if (not normalized or normalized.startswith("/")
                            or ".." in parts or not parts or ":" in parts[0]):
                        outcome = _preferred(outcome, ScanOutcome(
                            "review", "Suspicious archive entry path", self.name))
                    if item.flag_bits & 1:
                        outcome = _preferred(outcome, ScanOutcome(
                            "review", "Encrypted archive entry", self.name,
                            complete=False, detail="Encrypted archive member could not be inspected"))
                        continue
                    if (item.file_size > MAX_ARCHIVE_MEMBER_BYTES
                            or item.file_size > budget.bytes_left
                            or (item.compress_size and item.file_size > item.compress_size * 200)):
                        outcome = _preferred(outcome, ScanOutcome(
                            "review", "Archive inspection budget exceeded", self.name,
                            complete=False, detail="Archive member not inspected"))
                        continue
                    # ZipFile.open enforces CRC; never extract to the filesystem.
                    with archive.open(item, "r") as stream:
                        payload = stream.read(item.file_size + 1)
                        if len(payload) != item.file_size:
                            raise ValueError("Archive member size changed")
                        if stream.read(1):
                            raise ValueError("Archive member exceeded declared size")
                    budget.bytes_left -= len(payload)
                    outcome = _preferred(
                        outcome,
                        self._inspect(payload, normalized, depth=depth + 1, budget=budget),
                    )
                    if outcome.kind == "threat":
                        break
        except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, ValueError,
                NotImplementedError, zlib.error, struct.error):
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

    def scan_stream(self, chunks) -> ScanOutcome:
        return self.scan_stream_named(chunks, "")

    def scan_stream_named(self, chunks, name: str) -> ScanOutcome:
        # File scans hash the entire stream in antivirus._scan_large_file.
        # A bounded prefix is used only for advisory structural signals.
        prefix = bytearray()
        size = 0
        for chunk in chunks:
            size += len(chunk)
            if len(prefix) < STREAM_PREVIEW_BYTES:
                prefix.extend(chunk[:STREAM_PREVIEW_BYTES - len(prefix)])
        if size <= MAX_INLINE_BYTES:
            # Streaming callers cannot assume ZIP data was retained unless it
            # fits the preview; report incomplete rather than false-clean.
            if size == len(prefix):
                return self.scan(bytes(prefix), name)
        advisory = _preferred(_script_signal(bytes(prefix), name), _pe_signal(bytes(prefix)))
        return ScanOutcome(advisory.kind, advisory.name, self.name, False,
                           "Only local hash and bounded content preview were available")

    def close(self) -> None:
        pass
