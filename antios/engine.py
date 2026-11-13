"""Independent AntiOS file inspection engine.

No ClamAV service, Windows AMSI provider, driver, network or third-party
antivirus is required. Only a known SHA-256 match is a confirmed detection.
Structural/script observations are advisory and never authorize isolation.
Input is read-only; archive members are decompressed in memory under hard budgets.
"""
from __future__ import annotations

import bz2
from collections import Counter
from dataclasses import dataclass, replace
import hashlib
import io
import lzma
import math
from pathlib import PurePosixPath
import re
import stat
import struct
import tarfile
from threading import BoundedSemaphore
from typing import Callable, Iterable
import zipfile
import zlib

from .document_inspection import inspect_document
from .engine_types import ScanOutcome
from .linear_archives import (
    AR_MAGIC,
    CPIO_MAGICS,
    RPM_MAGIC,
    THIN_AR_MAGIC,
    ArchiveEntry,
    ar_entries,
    cpio_entries,
    rpm_payload_start,
)
from .rust_static_core import load_static_core

MAX_INLINE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 48 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 160 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_DIRECTORY_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 4
STREAM_PREVIEW_BYTES = 1024 * 1024
_SCRIPT_PREVIEW_BYTES = 16 * 1024 * 1024
_SCRIPT_EXTENSIONS = (".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".mjs", ".cjs", ".hta", ".wsf")
_IEX_CALL = re.compile(rb"\biex\s*\(")
_ZIP_ZSTD_METHODS = {20, 93}
_ZIP_BOUNDED_METHODS = {zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA, *_ZIP_ZSTD_METHODS}
_ZIP_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, *_ZIP_BOUNDED_METHODS}
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_ZSTD_WINDOW_LOG = 26  # Limit decompressor windows to 64 MiB.
_ZIP_EXTENSIONS = (
    ".zip", ".jar", ".war", ".ear", ".apk", ".xapk", ".aab", ".ipa", ".whl", ".epub",
    ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlam",
    ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm", ".odt", ".ods", ".odp",
    ".appx", ".appxbundle", ".msix", ".msixbundle",
)
try:
    from compression import zstd
except ImportError:
    try:
        from backports import zstd
    except ImportError:
        zstd = None
_ZSTD_ERRORS = (zstd.ZstdError,) if zstd is not None else ()
_OFFICE_MACROS = {"word/vbaproject.bin", "xl/vbaproject.bin", "ppt/vbaproject.bin"}
_ARCHIVE_ERRORS = (zipfile.BadZipFile, RuntimeError, OSError, EOFError, ValueError,
                   NotImplementedError, zlib.error, struct.error, lzma.LZMAError, *_ZSTD_ERRORS)


@dataclass(frozen=True)
class InspectionLimits:
    inline_bytes: int
    archive_member_bytes: int
    archive_total_bytes: int
    archive_members: int
    archive_directory_bytes: int
    archive_depth: int


def inspection_limits(profile: str) -> InspectionLimits:
    mib = 1024 * 1024
    if profile == "light":
        return InspectionLimits(16 * mib, 12 * mib, 32 * mib, 1024, mib, 2)
    if profile == "heavy":
        return InspectionLimits(96 * mib, 64 * mib, 192 * mib, 8192, 4 * mib, 6)
    if profile != "balanced":
        raise ValueError("Unsupported scan profile")
    return InspectionLimits(MAX_INLINE_BYTES, MAX_ARCHIVE_MEMBER_BYTES, MAX_ARCHIVE_TOTAL_BYTES,
                            MAX_ARCHIVE_MEMBERS, MAX_ARCHIVE_DIRECTORY_BYTES, MAX_ARCHIVE_DEPTH)


@dataclass(frozen=True)
class _FamilyRule:
    rule_id: str
    label: str
    minimum_matches: int = 1

    def evaluate(self, matches: int = 1) -> ScanOutcome:
        if matches < self.minimum_matches:
            return ScanOutcome()
        return ScanOutcome("review", self.label, rule_id=self.rule_id)


_SCRIPT_COMBINATION = _FamilyRule("script.combined-indicators", "Script requires manual review", minimum_matches=2)
_PE_SECTION = _FamilyRule("executable.unusual-pe-section", "Unusual executable section")
_ARCHIVE_PATH = _FamilyRule("archive.suspicious-entry-path", "Suspicious archive entry path")
_OFFICE_VBA = _FamilyRule("office.vba-macros", "Office document contains VBA macros")


def _inspection_gap(code: str, label: str = "", *, detail: str = "") -> ScanOutcome:
    return ScanOutcome("review" if label else None, label, complete=False, detail=detail or label,
                       coverage_gaps=frozenset({code}))


@dataclass
class _Budget:
    members: int
    bytes_left: int


def _preferred(left: ScanOutcome, right: ScanOutcome) -> ScanOutcome:
    if right.kind is None and right.complete and not right.detail:
        return left
    if left.kind is None and left.complete and not left.detail:
        return right
    priority = {None: 0, "review": 1, "threat": 2}
    left_priority = (priority.get(left.kind, 0), bool(left.rule_id))
    right_priority = (priority.get(right.kind, 0), bool(right.rule_id))
    selected = right if right_priority > left_priority else left
    return replace(
        selected,
        complete=left.complete and right.complete,
        detail=(left.detail or right.detail)[:500],
        coverage_gaps=left.coverage_gaps | right.coverage_gaps,
    )


def _archive_format(data: bytes, name: str) -> str | None:
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data[257:262] == b"ustar":
        return "tar"
    if data.startswith(b"BZh") and b"1" <= data[3:4] <= b"9":
        return "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(_ZSTD_MAGIC) or _zstd_skippable(data):
        return "zstd"
    if data.startswith(AR_MAGIC):
        return "ar"
    if data.startswith(CPIO_MAGICS):
        return "cpio"
    if data.startswith(RPM_MAGIC):
        return "rpm"
    if data.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", THIN_AR_MAGIC, b"MSCF",
                        b"070707", b"07070X", b"\xc7\x71", b"\x71\xc7")):
        return "unsupported"
    name = name.lower()
    if name.endswith(_ZIP_EXTENSIONS):
        return "zip"
    if name.endswith((".gz", ".tgz")):
        return "gzip"
    if name.endswith(".tar"):
        return "tar"
    if name.endswith((".bz2", ".tbz2")):
        return "bzip2"
    if name.endswith((".xz", ".txz")):
        return "xz"
    if name.endswith((".lzma", ".tlz")):
        return "lzma"
    if name.endswith((".zst", ".tzst")):
        return "zstd"
    if name.endswith((".ar", ".deb", ".udeb")):
        return "ar"
    if name.endswith(".cpio"):
        return "cpio"
    if name.endswith(".rpm"):
        return "rpm"
    if name.endswith((".7z", ".rar", ".cab", ".iso", ".dmg", ".wim", ".lz4", ".lz", ".lzo", ".ace")):
        return "unsupported"
    return None


def _zstd_skippable(data: bytes | memoryview) -> bool:
    return data[1:4] == b"\x2a\x4d\x18" and 0x50 <= data[0] <= 0x5F


def _zip_entry_count(data: bytes, max_directory_bytes: int) -> int | None:
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
            or directory_size > max_directory_bytes
            or (directory_end >= 20 and data[directory_end - 20:directory_end - 16] == b"PK\x06\x07")):
        return None
    return total_members


def _archive_path_signal(name: str) -> ScanOutcome:
    parts = PurePosixPath(name).parts
    if name.startswith("/") or ".." in parts or not parts or ":" in parts[0]:
        return _ARCHIVE_PATH.evaluate()
    return ScanOutcome()


def _entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    length = len(sample)
    return -sum((count / length) * math.log2(count / length) for count in Counter(sample).values())


def _has_iex_call(sample: bytes) -> bool:
    position = sample.find(b"iex")
    while position >= 0:
        if _IEX_CALL.match(sample, position):
            return True
        position = sample.find(b"iex", position + 3)
    return False


def _script_signal(data: bytes, name: str) -> ScanOutcome:
    if not name.lower().endswith(_SCRIPT_EXTENSIONS):
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
        b"invoke-expression" in sample or _has_iex_call(sample),
        b"downloadstring(" in sample or b"downloadfile(" in sample,
        b"set-mppreference" in sample or b"add-mppreference" in sample,
    )
    outcome = _SCRIPT_COMBINATION.evaluate(sum(indicators))
    if not complete:
        outcome = _preferred(outcome, _inspection_gap(
            "script-preview-only", detail="Only a bounded script preview was inspected"))
    return outcome


def _pe_signal(data: bytes) -> ScanOutcome:
    if not data.startswith(b"MZ"):
        return ScanOutcome()
    if len(data) < 64:
        return _inspection_gap("invalid-pe-header", "Truncated executable header")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset > len(data) - 24 or data[offset:offset + 4] != b"PE\x00\x00":
        return _inspection_gap("invalid-pe-header", "Unrecognized executable header")
    sections = struct.unpack_from("<H", data, offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, offset + 20)[0]
    if sections == 0 or sections > 96 or optional_size < 2:
        return _inspection_gap("invalid-pe-header", "Invalid executable section table")
    table = offset + 24 + optional_size
    if table > len(data) or sections > (len(data) - table) // 40:
        return _inspection_gap("invalid-pe-header", "Truncated executable section table")
    for index in range(sections):
        entry = table + index * 40
        raw_size, raw_offset, flags = struct.unpack_from("<II12xI", data, entry + 16)
        if raw_size and (raw_offset > len(data) or raw_size > len(data) - raw_offset):
            return _inspection_gap(
                "invalid-pe-section-bounds", "Executable section exceeds file bounds",
                detail="PE section raw data points outside the inspected file",
            )
        executable_writable = flags & 0x20000000 and flags & 0x80000000
        if not executable_writable or raw_size < 4096:
            continue
        if _entropy(data[raw_offset:raw_offset + min(raw_size, 32768)]) > 7.5:
            return _PE_SECTION.evaluate()
    return ScanOutcome()


def _executable_signal(data: bytes) -> ScanOutcome:
    if data.startswith(b"\x7fELF"):
        if len(data) < 16 or data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
            return _inspection_gap("invalid-elf-header", "Invalid ELF identification header")
        byte_order = "<" if data[5] == 1 else ">"
        header_size, size_field = (52, 40) if data[4] == 1 else (64, 52)
        if len(data) < header_size:
            return _inspection_gap("invalid-elf-header", "Truncated ELF header")
        declared_size = struct.unpack_from(byte_order + "H", data, size_field)[0]
        if not header_size <= declared_size <= len(data):
            return _inspection_gap("invalid-elf-header", "Invalid ELF header size")
        return ScanOutcome()
    return _pe_signal(data)


_NATIVE_EXECUTABLE_GAPS = {
    1: ("invalid-pe-header", "Truncated executable header", ""),
    2: ("invalid-pe-header", "Unrecognized executable header", ""),
    3: ("invalid-pe-header", "Invalid executable section table", ""),
    4: ("invalid-pe-header", "Truncated executable section table", ""),
    5: ("invalid-pe-section-bounds", "Executable section exceeds file bounds",
        "PE section raw data points outside the inspected file"),
    7: ("invalid-elf-header", "Invalid ELF identification header", ""),
    8: ("invalid-elf-header", "Truncated ELF header", ""),
    9: ("invalid-elf-header", "Invalid ELF header size", ""),
}


def _zstd_decoder():
    if zstd is None:
        raise NotImplementedError("Zstandard decoder is unavailable")
    return zstd.ZstdDecompressor(options={zstd.DecompressionParameter.window_log_max: _ZSTD_WINDOW_LOG})


def _zip_encoded_member(item: zipfile.ZipInfo, data: bytes) -> memoryview:
    offset = item.header_offset
    if offset < 0:
        raise ValueError("Invalid ZIP header offset")
    (magic, _version, flags, method, _time, _date, _crc, _compressed, _expanded,
     name_size, extra_size) = struct.unpack_from("<4s5H3I2H", data, offset)
    name_start = offset + 30
    start = name_start + name_size + extra_size
    end = start + item.compress_size
    raw_name = data[name_start:name_start + name_size]
    encoding = "utf-8" if flags & 0x800 else "cp437"
    if (magic != b"PK\x03\x04" or flags != item.flag_bits or flags & 0x61
            or method != item.compress_type or raw_name.decode(encoding) != item.orig_filename
            or end > min(len(data), item._end_offset)):
        raise ValueError("Inconsistent or overlapping ZIP member")
    return memoryview(data)[start:end]


def _zip_lzma_decoder(content: memoryview):
    if len(content) < 9 or content[2:4] != b"\x05\x00":
        raise ValueError("Invalid ZIP LZMA properties")
    properties = content[4]
    dictionary_size, = struct.unpack_from("<I", content, 5)
    if properties >= 225 or dictionary_size > 64 * 1024 * 1024:
        raise ValueError("ZIP LZMA properties exceed the decoder limit")
    lc = properties % 9
    lp = (properties // 9) % 5
    pb = properties // 45
    return lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{
        "id": lzma.FILTER_LZMA1, "dict_size": max(4096, dictionary_size), "lc": lc, "lp": lp, "pb": pb,
    }])


def _read_zip_member(archive: zipfile.ZipFile, item: zipfile.ZipInfo, data: bytes) -> bytes:
    if item.compress_type not in _ZIP_BOUNDED_METHODS:
        with archive.open(item) as stream:
            return stream.read(item.file_size + 1)
    # ZipExtFile does not limit the output of every decoder call.
    encoded = _zip_encoded_member(item, data)
    if item.compress_type == zipfile.ZIP_LZMA:
        decoder = _zip_lzma_decoder(encoded)
        encoded = encoded[9:]
    elif item.compress_type == zipfile.ZIP_BZIP2:
        decoder = bz2.BZ2Decompressor()
    else:
        if _zstd_skippable(encoded):
            raise ValueError("Skipped Zstandard data cannot be inspected")
        decoder = _zstd_decoder()
    payload = decoder.decompress(encoded, item.file_size + 1)
    if not decoder.eof or decoder.unused_data or zlib.crc32(payload) != item.CRC:
        raise ValueError("Incomplete or corrupt ZIP member")
    return payload


class AntiOSEngine:
    """Locally owned detection engine with strict, explainable verdict classes."""

    name = "AntiOS Engine"

    def __init__(self, *, signatures: dict[str, str] | None = None, profile: str = "balanced") -> None:
        self._signatures = dict(signatures or {})
        if len(self._signatures) > 100_001:
            raise ValueError("Too many local signatures")
        self._limits = inspection_limits(profile)
        self._archive_slots = BoundedSemaphore(1 if profile == "light" else 2)
        self._native = load_static_core()
        self.metadata = {
            "version": "AntiOS Engine/0.4",
            "database_freshness": "local",
            "signature_scope": "local-sha256",
            "static_core": "rust" if self._native is not None else "python",
            "components": {"hashes": True, "scripts": True, "pe": True, "elf": True, "zip": True,
                           "gzip": True, "tar": True, "bzip2": True, "xz": True, "lzma": True,
                           "ar": True, "cpio": True, "rpm_payload": True,
                           "zstd": zstd is not None, "office_macros": True},
        }

    def hash_content(self, data: bytes) -> str:
        native = self._native
        if native is not None:
            try:
                return native.digest(data)
            except (OSError, ValueError):
                self._disable_native()
        return hashlib.sha256(data).hexdigest()

    def _disable_native(self) -> None:
        self._native = None
        self.metadata["static_core"] = "python"
        self.metadata["static_core_fallback"] = True

    def _static_signal(self, data: bytes, name: str) -> ScanOutcome:
        native = self._native
        if native is not None and _SCRIPT_PREVIEW_BYTES == 16 * 1024 * 1024:
            try:
                script, executable = native.inspect(data, name.lower().endswith(_SCRIPT_EXTENSIONS))
            except (OSError, ValueError):
                self._disable_native()
            else:
                signal = _SCRIPT_COMBINATION.evaluate(2 if script & 1 else 0)
                if script & 2:
                    signal = _preferred(signal, _inspection_gap(
                        "script-preview-only", detail="Only a bounded script preview was inspected",
                    ))
                if executable in _NATIVE_EXECUTABLE_GAPS:
                    code, label, detail = _NATIVE_EXECUTABLE_GAPS[executable]
                    return _preferred(signal, _inspection_gap(code, label, detail=detail))
                if executable == 6:
                    return _preferred(signal, _PE_SECTION.evaluate())
                if executable == 10:
                    return _preferred(signal, _executable_signal(data))
                return signal
        return _preferred(_script_signal(data, name), _executable_signal(data))

    def _inspect(self, data: bytes, name: str, *, depth: int, budget: _Budget,
                 digest: str | None = None) -> ScanOutcome:
        digest = digest if digest is not None else self.hash_content(data)
        label = self._signatures.get(digest)
        if label is not None:
            return ScanOutcome("threat", label, self.name)
        outcome = self._static_signal(data, name)
        outcome = _preferred(outcome, inspect_document(data, name))
        archive_format = _archive_format(data, name)
        if archive_format is None:
            return outcome
        if archive_format == "unsupported":
            return _preferred(outcome, _inspection_gap(
                "unsupported-archive-format", "Unsupported archive format",
                detail="Archive contents were not inspected"))
        if depth >= self._limits.archive_depth:
            return _preferred(outcome, _inspection_gap(
                "archive-depth-limit", "Nested archive depth limit reached",
                detail="Nested archive was not fully examined"))
        if depth == 0:
            with self._archive_slots:
                archive = self._inspect_archive(data, name, archive_format, depth, budget)
        else:
            archive = self._inspect_archive(data, name, archive_format, depth, budget)
        return _preferred(outcome, archive)

    def _inspect_archive(self, data: bytes, name: str, archive_format: str,
                         depth: int, budget: _Budget) -> ScanOutcome:
        if archive_format == "zip":
            return self._inspect_zip(data, depth, budget)
        if archive_format == "tar":
            return self._inspect_tar(data, depth, budget)
        if archive_format in {"ar", "cpio"}:
            entries = ar_entries(data, self._limits.archive_directory_bytes) if archive_format == "ar" else cpio_entries(data)
            return self._inspect_linear_archive(data, entries, depth, budget)
        if archive_format == "rpm":
            return self._inspect_rpm_payload(data, depth, budget)
        return self._inspect_compressed(data, name, archive_format, depth, budget)

    def _inspect_compressed(self, data: bytes, name: str, archive_format: str,
                            depth: int, budget: _Budget) -> ScanOutcome:
        # Ordinary TAR padding can compress to a very small GZIP payload.
        limit = min(self._limits.archive_member_bytes, budget.bytes_left, max(65536, len(data) * 200))
        if budget.members <= 0 or limit <= 0:
            return _inspection_gap("archive-budget-exceeded", "Archive inspection budget exceeded")
        budget.members -= 1
        budget.bytes_left -= limit
        if archive_format == "gzip":
            decompressor = zlib.decompressobj(wbits=31)
        elif archive_format == "bzip2":
            decompressor = bz2.BZ2Decompressor()
        elif archive_format == "zstd":
            if zstd is None:
                return _inspection_gap("unsupported-archive-compression", "Zstandard decoder is unavailable")
            if _zstd_skippable(data):
                return _inspection_gap("uninspected-compressed-data", "Zstandard skippable frame was not inspected")
            decompressor = _zstd_decoder()
        else:
            encoding = lzma.FORMAT_ALONE if archive_format == "lzma" else lzma.FORMAT_XZ
            decompressor = lzma.LZMADecompressor(format=encoding, memlimit=64 * 1024 * 1024)
        try:
            payload = decompressor.decompress(data, limit + 1)
        except (OSError, EOFError, zlib.error, lzma.LZMAError, *_ZSTD_ERRORS):
            return _inspection_gap("unreadable-archive", "Unreadable compressed archive")
        if len(payload) > limit:
            return _inspection_gap("archive-budget-exceeded", "Archive inspection budget exceeded")
        if not decompressor.eof:
            return _inspection_gap("unreadable-archive", "Truncated compressed archive")
        trailing = decompressor.unused_data
        unread = bool(trailing and (archive_format in {"bzip2", "zstd", "lzma"} or trailing.strip(b"\x00")
                                    or (archive_format == "xz" and len(trailing) % 4)))
        del decompressor, trailing
        budget.bytes_left += limit - len(payload)
        lower = name.lower()
        extension = lower.rpartition(".")[2]
        inner_name = ""
        if extension in {"gz", "bz2", "xz", "zst", "lzma"}:
            inner_name = name[:-(len(extension) + 1)]
        elif extension in {"tgz", "tbz2", "txz", "tzst", "tlz"}:
            inner_name = name[:-(len(extension) + 1)] + ".tar"
        outcome = self._inspect(payload, inner_name, depth=depth + 1, budget=budget)
        if unread:
            outcome = _preferred(outcome, _inspection_gap(
                "uninspected-compressed-data", "Additional compressed data was not inspected"))
        return outcome

    def _inspect_rpm_payload(self, data: bytes, depth: int, budget: _Budget) -> ScanOutcome:
        try:
            start = rpm_payload_start(data, self._limits.archive_directory_bytes)
        except (ValueError, struct.error):
            return _inspection_gap("unreadable-archive", "Unreadable RPM package")
        size = len(data) - start
        if budget.members <= 0 or size > min(self._limits.archive_member_bytes, budget.bytes_left):
            return _inspection_gap("archive-budget-exceeded", "Archive inspection budget exceeded")
        budget.members -= 1
        budget.bytes_left -= size
        payload = data[start:]
        encoding = _archive_format(payload, "")
        suffixes = {"cpio": "", "gzip": ".gz", "bzip2": ".bz2", "xz": ".xz", "zstd": ".zst"}
        if encoding not in suffixes:
            return _inspection_gap("unsupported-archive-entry", "RPM payload format was not inspected")
        # Header tags may carry scriptlets. Payload inspection cannot establish
        # package authenticity or cover code in those tags.
        metadata = _inspection_gap(
            "rpm-metadata-not-inspected", detail="RPM header metadata and scriptlets were not inspected",
        )
        name = "payload.cpio" + suffixes[encoding]
        return _preferred(self._inspect(payload, name, depth=depth + 1, budget=budget), metadata)

    def _inspect_linear_archive(self, data: bytes, entries: Iterable[ArchiveEntry],
                                depth: int, budget: _Budget) -> ScanOutcome:
        outcome = ScanOutcome()
        try:
            for entry in entries:
                if budget.members <= 0:
                    return _preferred(outcome, _inspection_gap(
                        "archive-budget-exceeded", "Archive entry limit reached"))
                budget.members -= 1
                if entry.kind == "metadata":
                    continue
                name = entry.name.replace("\\", "/")
                if entry.kind == "directory" and name == ".":
                    continue
                outcome = _preferred(outcome, _archive_path_signal(name))
                if entry.kind == "directory":
                    continue
                if entry.kind != "file":
                    gap = "archive-link-skipped" if entry.kind == "link" else "unsupported-archive-entry"
                    outcome = _preferred(outcome, _inspection_gap(gap, "Archive member was not inspected"))
                    continue
                size = entry.end - entry.start
                if size > min(self._limits.archive_member_bytes, budget.bytes_left):
                    outcome = _preferred(outcome, _inspection_gap(
                        "archive-budget-exceeded", "Archive inspection budget exceeded"))
                    continue
                budget.bytes_left -= size
                payload = data[entry.start:entry.end]
                if entry.checksum is not None and (sum(payload) & 0xffffffff) != entry.checksum:
                    outcome = _preferred(outcome, _inspection_gap(
                        "unreadable-archive-entry", "CPIO member checksum mismatch"))
                    continue
                outcome = _preferred(outcome, self._inspect(payload, name, depth=depth + 1, budget=budget))
                if outcome.kind == "threat":
                    break
        except ValueError:
            return _preferred(outcome, _inspection_gap("unreadable-archive", "Unreadable archive"))
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
                return _preferred(outcome, _inspection_gap(
                    "archive-budget-exceeded", "Archive entry limit reached"))
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
                outcome = _preferred(outcome, _inspection_gap(
                    "archive-link-skipped", "Archive link was not followed"))
                continue
            # Extension records can alter how later entries are interpreted.
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                return _preferred(outcome, _inspection_gap(
                    "unsupported-archive-entry", "Unsupported TAR entry"))
            if member.size > min(self._limits.archive_member_bytes, budget.bytes_left):
                outcome = _preferred(outcome, _inspection_gap(
                    "archive-budget-exceeded", "Archive inspection budget exceeded"))
                continue
            budget.bytes_left -= member.size
            outcome = _preferred(outcome, self._inspect(
                data[start:start + member.size], name, depth=depth + 1, budget=budget))
            if outcome.kind == "threat":
                return outcome
        return _preferred(outcome, _inspection_gap("unreadable-archive", "Unreadable TAR archive"))

    def _inspect_zip(self, data: bytes, depth: int, budget: _Budget) -> ScanOutcome:
        declared_members = _zip_entry_count(data, self._limits.archive_directory_bytes)
        if declared_members is None or declared_members > budget.members:
            gap = "archive-directory-unavailable" if declared_members is None else "archive-budget-exceeded"
            return _inspection_gap(gap, "Archive directory requires manual review",
                                   detail="Archive could not be safely enumerated")
        outcome = ScanOutcome()
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                if len(members) != declared_members:
                    return _inspection_gap("archive-directory-unavailable", "Invalid archive directory")
                budget.members -= len(members)
                for item in members:
                    if item.create_system == 3 and stat.S_ISLNK(item.external_attr >> 16):
                        outcome = _preferred(outcome, _inspection_gap("archive-link-skipped", "Archive link was not followed"))
                        continue
                    if item.is_dir():
                        if item.file_size:
                            outcome = _preferred(outcome, _inspection_gap(
                                "unsupported-archive-entry", "Archive directory entry contains data"))
                        continue
                    normalized = item.filename.replace("\\", "/")
                    outcome = _preferred(outcome, _archive_path_signal(normalized))
                    if item.flag_bits & 1:
                        outcome = _preferred(outcome, _inspection_gap(
                            "encrypted-archive-entry", "Encrypted archive entry",
                            detail="Encrypted archive member could not be inspected"))
                        continue
                    if item.compress_type not in _ZIP_METHODS or (item.compress_type in _ZIP_ZSTD_METHODS and zstd is None):
                        outcome = _preferred(outcome, _inspection_gap(
                            "unsupported-archive-compression", "Unsupported archive compression"))
                        continue
                    if (item.file_size > self._limits.archive_member_bytes
                            or item.file_size > budget.bytes_left
                            or (item.compress_size and item.file_size > item.compress_size * 200)):
                        outcome = _preferred(outcome, _inspection_gap(
                            "archive-budget-exceeded", "Archive inspection budget exceeded",
                            detail="Archive member not inspected"))
                        continue
                    # Charge failed reads too. ZipFile verifies CRC without extracting to disk.
                    budget.bytes_left -= item.file_size
                    try:
                        payload = _read_zip_member(archive, item, data)
                        if len(payload) != item.file_size:
                            raise ValueError("Archive member size changed")
                    except _ARCHIVE_ERRORS:
                        outcome = _preferred(outcome, _inspection_gap(
                            "unreadable-archive-entry", "Unreadable archive member"))
                        continue
                    if (normalized.lower() in _OFFICE_MACROS
                            and payload.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")):
                        outcome = _preferred(outcome, _OFFICE_VBA.evaluate())
                    outcome = _preferred(
                        outcome,
                        self._inspect(payload, normalized, depth=depth + 1, budget=budget),
                    )
                    if outcome.kind == "threat":
                        break
        except _ARCHIVE_ERRORS:
            outcome = _preferred(outcome, _inspection_gap(
                "unreadable-archive", "Unreadable archive", detail="Archive inspection failed"))
        return outcome

    def scan_with_digest(self, content: bytes, name: str, digest: str) -> ScanOutcome:
        if digest in self._signatures:
            return ScanOutcome("threat", self._signatures[digest], self.name)
        if len(content) > self._limits.inline_bytes:
            return _inspection_gap("file-inspection-budget-exceeded",
                                   detail="File exceeds full-content inspection budget")
        budget = _Budget(self._limits.archive_members, self._limits.archive_total_bytes)
        return self._inspect(content, name, depth=0, budget=budget, digest=digest)

    def scan(self, content: bytes, name: str) -> ScanOutcome:
        return self.scan_with_digest(content, name, self.hash_content(content))

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
        preview_limit = _SCRIPT_PREVIEW_BYTES if name.lower().endswith(_SCRIPT_EXTENSIONS) else STREAM_PREVIEW_BYTES
        for chunk in chunks:
            size += len(chunk)
            if len(prefix) < preview_limit:
                prefix.extend(chunk[:preview_limit - len(prefix)])
        sha = get_digest()
        if sha in self._signatures:
            return ScanOutcome("threat", self._signatures[sha], self.name)
        content = bytes(prefix)
        if size == len(content):
            return self.scan_with_digest(content, name, sha)
        advisory = self._static_signal(content, name)
        advisory = _preferred(advisory, inspect_document(content, name))
        outcome = _preferred(advisory, _inspection_gap("stream-preview-only"))
        return replace(outcome, detail="Only local hash and bounded content preview were available")

    def close(self) -> None:
        pass
