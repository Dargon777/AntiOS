from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

ProgressCallback = Callable[[dict[str, Any]], None]
CancelCallback = Callable[[], bool]

ARCHIVE_INSTALLER_EXTENSIONS = {
    ".7z",
    ".appx",
    ".appxbundle",
    ".cab",
    ".iso",
    ".msi",
    ".msix",
    ".msixbundle",
    ".rar",
    ".tar",
    ".tgz",
    ".zip",
}

DEFAULT_OLD_DAYS = 180
DEFAULT_LARGE_BYTES = 500 * 1024 * 1024
DEFAULT_DUPLICATE_MIN_BYTES = 1 * 1024 * 1024
QUICK_HASH_BYTES = 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class FileRecord:
    path: Path
    size: int
    modified: float

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()

    def to_dict(self, *, now: float | None = None) -> dict[str, Any]:
        timestamp = time.time() if now is None else now
        age_days = max(0.0, (timestamp - self.modified) / 86400)
        return {
            "path": str(self.path),
            "size_bytes": self.size,
            "modified": self.modified,
            "age_days": round(age_days, 1),
        }


def default_scan_path() -> Path:
    downloads = Path.home() / "Downloads"
    return downloads if downloads.is_dir() else Path.home()


def _iter_files(
    root: Path,
    *,
    progress: ProgressCallback | None = None,
    cancelled: CancelCallback | None = None,
) -> tuple[list[FileRecord], list[str]]:
    records: list[FileRecord] = []
    errors: list[str] = []
    stack = [root]
    scanned_dirs = 0

    while stack:
        if cancelled and cancelled():
            break

        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    if cancelled and cancelled():
                        break
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        stat = entry.stat(follow_symlinks=False)
                        records.append(
                            FileRecord(
                                path=Path(entry.path),
                                size=int(stat.st_size),
                                modified=float(stat.st_mtime),
                            )
                        )
                        if progress and len(records) % 250 == 0:
                            progress({
                                "phase": "enumerating",
                                "files_scanned": len(records),
                                "directories_scanned": scanned_dirs,
                            })
                    except (OSError, PermissionError) as exc:
                        errors.append(f"{entry.path}: {exc}")
        except (OSError, PermissionError) as exc:
            errors.append(f"{current}: {exc}")
        scanned_dirs += 1

    return records, errors


def _quick_fingerprint(path: Path, size: int) -> str:
    digest = hashlib.sha256()
    digest.update(str(size).encode("ascii"))

    with path.open("rb") as handle:
        first = handle.read(QUICK_HASH_BYTES)
        digest.update(first)
        if size > QUICK_HASH_BYTES:
            seek_to = max(0, size - QUICK_HASH_BYTES)
            handle.seek(seek_to)
            digest.update(handle.read(QUICK_HASH_BYTES))

    return digest.hexdigest()


def _full_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _duplicate_groups(
    records: Iterable[FileRecord],
    *,
    min_size: int,
    progress: ProgressCallback | None = None,
    cancelled: CancelCallback | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    by_size: dict[int, list[FileRecord]] = {}

    for record in records:
        if record.size >= min_size:
            by_size.setdefault(record.size, []).append(record)

    same_size = [
        group
        for group in by_size.values()
        if len(group) > 1
    ]

    quick_groups: dict[tuple[int, str], list[FileRecord]] = {}
    hashed = 0
    for group in same_size:
        for record in group:
            if cancelled and cancelled():
                return [], errors
            try:
                quick = _quick_fingerprint(record.path, record.size)
                quick_groups.setdefault((record.size, quick), []).append(record)
            except (OSError, PermissionError) as exc:
                errors.append(f"{record.path}: {exc}")
            hashed += 1
            if progress and hashed % 25 == 0:
                progress({
                    "phase": "hashing",
                    "files_hashed": hashed,
                })

    full_groups: dict[tuple[int, str], list[FileRecord]] = {}
    for group in quick_groups.values():
        if len(group) < 2:
            continue
        for record in group:
            if cancelled and cancelled():
                return [], errors
            try:
                digest = _full_hash(record.path)
                full_groups.setdefault((record.size, digest), []).append(record)
            except (OSError, PermissionError) as exc:
                errors.append(f"{record.path}: {exc}")
            hashed += 1
            if progress and hashed % 25 == 0:
                progress({
                    "phase": "hashing",
                    "files_hashed": hashed,
                })

    result: list[dict[str, Any]] = []
    for (size, digest), group in full_groups.items():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda item: str(item.path).casefold())
        result.append({
            "size_bytes": size,
            "hash": digest,
            "count": len(ordered),
            "reclaimable_bytes": size * (len(ordered) - 1),
            "paths": [str(item.path) for item in ordered],
        })

    result.sort(
        key=lambda item: (
            -int(item["reclaimable_bytes"]),
            str(item["paths"][0]).casefold(),
        )
    )
    return result, errors


def scan_storage(
    root: str | os.PathLike[str],
    *,
    old_days: int = DEFAULT_OLD_DAYS,
    large_bytes: int = DEFAULT_LARGE_BYTES,
    duplicate_min_bytes: int = DEFAULT_DUPLICATE_MIN_BYTES,
    progress: ProgressCallback | None = None,
    cancelled: CancelCallback | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.exists():
        raise ValueError(f"Scan path does not exist: {base}")
    if not base.is_dir():
        raise ValueError(f"Scan path is not a directory: {base}")
    if old_days < 1:
        raise ValueError("old_days must be at least 1")
    if large_bytes < 1:
        raise ValueError("large_bytes must be positive")
    if duplicate_min_bytes < 1:
        raise ValueError("duplicate_min_bytes must be positive")

    timestamp = time.time() if now is None else now

    if progress:
        progress({"phase": "enumerating", "files_scanned": 0})

    records, errors = _iter_files(
        base,
        progress=progress,
        cancelled=cancelled,
    )

    if cancelled and cancelled():
        return {
            "root": str(base),
            "cancelled": True,
            "summary": {
                "files_scanned": len(records),
                "bytes_scanned": sum(item.size for item in records),
            },
            "duplicates": [],
            "old_large_files": [],
            "installer_archives": [],
            "empty_files": [],
            "errors": errors,
        }

    old_cutoff = timestamp - (old_days * 86400)
    old_large = [
        record
        for record in records
        if record.size >= large_bytes and record.modified <= old_cutoff
    ]
    old_large.sort(key=lambda item: (-item.size, item.modified, str(item.path).casefold()))

    installer_archives = [
        record
        for record in records
        if record.suffix in ARCHIVE_INSTALLER_EXTENSIONS
    ]
    installer_archives.sort(key=lambda item: (-item.size, str(item.path).casefold()))

    empty = [record for record in records if record.size == 0]
    empty.sort(key=lambda item: str(item.path).casefold())

    duplicates, hash_errors = _duplicate_groups(
        records,
        min_size=duplicate_min_bytes,
        progress=progress,
        cancelled=cancelled,
    )
    errors.extend(hash_errors)

    result = {
        "root": str(base),
        "cancelled": bool(cancelled and cancelled()),
        "rules": {
            "old_days": old_days,
            "large_bytes": large_bytes,
            "duplicate_min_bytes": duplicate_min_bytes,
            "unused_claim": False,
            "note": (
                "Old-file results use last-modified time. AntiOS does not claim "
                "a file is unused because Windows last-access timestamps can be "
                "disabled, delayed, or unreliable."
            ),
        },
        "summary": {
            "files_scanned": len(records),
            "bytes_scanned": sum(item.size for item in records),
            "duplicate_groups": len(duplicates),
            "duplicate_files": sum(int(item["count"]) for item in duplicates),
            "duplicate_reclaimable_bytes": sum(
                int(item["reclaimable_bytes"]) for item in duplicates
            ),
            "old_large_files": len(old_large),
            "installer_archives": len(installer_archives),
            "empty_files": len(empty),
            "errors": len(errors),
        },
        "duplicates": duplicates,
        "old_large_files": [item.to_dict(now=timestamp) for item in old_large],
        "installer_archives": [
            item.to_dict(now=timestamp) for item in installer_archives
        ],
        "empty_files": [item.to_dict(now=timestamp) for item in empty],
        "errors": errors[:200],
    }

    if progress:
        progress({
            "phase": "done",
            "files_scanned": len(records),
            "duplicate_groups": len(duplicates),
        })

    return result


def format_bytes(value: int | float) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TB"


def render_storage_scan(result: dict[str, Any]) -> str:
    summary = result.get("summary", {})
    lines = [
        "AntiOS storage scan",
        "===================",
        f"Path: {result.get('root', '')}",
        f"Files scanned: {summary.get('files_scanned', 0)}",
        f"Data scanned: {format_bytes(summary.get('bytes_scanned', 0))}",
        "",
        (
            f"Duplicate groups: {summary.get('duplicate_groups', 0)} "
            f"({format_bytes(summary.get('duplicate_reclaimable_bytes', 0))} "
            "potentially reclaimable)"
        ),
        f"Old large files: {summary.get('old_large_files', 0)}",
        f"Installer/archive candidates: {summary.get('installer_archives', 0)}",
        f"Empty files: {summary.get('empty_files', 0)}",
        "",
        "Note: old files are classified by last-modified time, not by a claim that they are unused.",
    ]

    duplicates = result.get("duplicates", [])
    if duplicates:
        lines.extend(["", "Duplicates:"])
        for group in duplicates[:20]:
            lines.append(
                f"- {format_bytes(group.get('size_bytes', 0))} × "
                f"{group.get('count', 0)}"
            )
            for path in group.get("paths", []):
                lines.append(f"    {path}")

    return "\n".join(lines)
