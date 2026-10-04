"""Bounded on-demand file scanner. Findings never mutate scanned files."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .windows_antivirus import AmsiScanner
from .clamav import ClamAVScanner, ScanOutcome

DEFAULT_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_FILES = 100_000
MAX_DETAILS = 1000
# Hash only: do not embed the EICAR test payload in packaged executables.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fingerprint(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


def checked_path(path: str | Path) -> Path:
    """Reject symlinks/junctions and Windows alternate streams, including parents."""
    target = Path(os.path.abspath(Path(path).expanduser()))
    if os.name == "nt" and any(":" in part for part in target.parts[1:]):
        raise ValueError("Alternate data streams are not supported")
    for component in (*reversed(target.parents), target):
        info = component.lstat()
        if is_link(info):
            raise ValueError("Symbolic links and reparse points are not supported")
    return target


def read_regular(path: Path, max_bytes: int) -> tuple[bytes, os.stat_result]:
    target = checked_path(path)
    before = target.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("Not a regular file")
    if before.st_size > max_bytes:
        raise ValueError("File exceeds the scan size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(target, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or fingerprint(before) != fingerprint(opened):
            raise ValueError("File changed while opening")
        content = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
    if len(content) > max_bytes:
        raise ValueError("File exceeds the scan size limit")
    if fingerprint(opened) != fingerprint(after) or fingerprint(after) != fingerprint(target.lstat()):
        raise ValueError("File changed while reading")
    return content, after


def load_signatures(path: str | Path | None = None) -> dict[str, str]:
    signatures = {EICAR_SHA256: "EICAR test file (not live malware)"}
    if path is None:
        return signatures
    content, _info = read_regular(Path(path), 8 * 1024 * 1024)
    data = json.loads(content)
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise ValueError("Signature database requires schema 1")
    entries = data.get("sha256")
    if not isinstance(entries, dict) or len(entries) > 100_000:
        raise ValueError("Signature database must contain at most 100000 SHA-256 entries")
    for digest, label in entries.items():
        if not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise ValueError("Invalid SHA-256 signature")
        if not isinstance(label, str) or not label.strip() or len(label) > 200:
            raise ValueError("Invalid signature label")
        signatures[digest.lower()] = label
    return signatures


def scan_files(
    path: str | Path,
    *,
    signature_path: str | Path | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    progress: Callable[[dict], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    provider_factory: Callable | None = None,
    engine: str = "amsi",
    engine_service: str | None = None,
    require_verified_peer: bool = False,
    excluded_paths: tuple[Path, ...] = (),
    checkpoint: Callable[[dict], None] | None = None,
) -> dict[str, Any]:
    if engine not in {"amsi", "clamav"}:
        raise ValueError("Unknown scan engine")
    if provider_factory is None:
        if engine == "amsi":
            provider_factory = AmsiScanner
        elif engine_service is None and not require_verified_peer:
            # Preserve the ordinary on-demand provider contract. Strict Windows
            # peer binding is opt-in here and mandatory in Resident Guard.
            provider_factory = ClamAVScanner
        else:
            provider_factory = lambda: ClamAVScanner(
                service_name=engine_service,
                require_verified_peer=require_verified_peer,
            )
    if not 1 <= max_bytes <= 256 * 1024 * 1024 or not 1 <= max_files <= 1_000_000:
        raise ValueError("Scan limits must be 1..256 MiB and 1..1000000 files")
    target = checked_path(path)
    if not target.is_file() and not target.is_dir():
        raise ValueError("Select a regular file or directory")
    signatures = load_signatures(signature_path)
    result: dict[str, Any] = {
        "schema": 1, "kind": "antivirus-scan", "path": str(target),
        "started_at": utc_now(), "finished_at": None,
        "limits": {"max_file_bytes": max_bytes, "max_files": max_files,
                   "max_entries": max_files * 2},
        "engine": {"provider": "Windows AMSI" if engine == "amsi" else "ClamAV", "available": False,
                   "signatures": len(signatures), "signature_path": str(signature_path or "")},
        "summary": {"files_seen": 0, "entries_seen": 0, "files_scanned": 0, "provider_scanned": 0,
                    "bytes_scanned": 0, "threats": 0, "reviews": 0, "skipped": 0,
                    "errors": 0, "cancelled": False, "limit_reached": False},
        "findings": [], "issues": [],
        "coverage": "limited", "verdict": "incomplete",
    }
    if checkpoint:
        checkpoint(result)
    summary = result["summary"]
    provider = None
    try:
        provider = provider_factory()
        result["engine"]["available"] = True
        result["engine"].update(getattr(provider, "metadata", {}))
    except (OSError, RuntimeError) as exc:
        result["engine"]["detail"] = str(exc)

    exclusions = tuple(Path(os.path.abspath(p)) for p in excluded_paths)
    stopped = cancelled or (lambda: False)

    def issue(item: Path, reason: str, *, error: bool = False) -> None:
        summary["errors" if error else "skipped"] += 1
        if len(result["issues"]) < MAX_DETAILS:
            result["issues"].append({"path": str(item), "reason": reason, "error": error})

    def exclude(item: Path) -> bool:
        return any(item == root or root in item.parents for root in exclusions)

    def candidates():
        if target.is_file():
            yield target
            return
        stack = [target]
        while stack:
            if stopped():
                return
            folder = stack.pop()
            try:
                checked_path(folder)
                with os.scandir(folder) as entries:
                    for entry in entries:
                        if stopped():
                            return
                        if summary["entries_seen"] >= max_files * 2:
                            summary["limit_reached"] = True
                            return
                        summary["entries_seen"] += 1
                        item = Path(entry.path)
                        if exclude(item):
                            issue(item, "quarantine-excluded")
                            continue
                        try:
                            info = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            issue(item, str(exc), error=True)
                            continue
                        if is_link(info):
                            issue(item, "link-or-reparse-point")
                        elif stat.S_ISDIR(info.st_mode):
                            # Bound traversal memory, even for directory-only trees.
                            if len(stack) >= max_files:
                                summary["limit_reached"] = True
                                return
                            stack.append(item)
                        else:
                            yield item
            except (OSError, ValueError) as exc:
                issue(folder, str(exc), error=True)

    provider_failed = False
    try:
        for item in candidates():
            if stopped():
                break
            if summary["files_seen"] >= max_files:
                summary["limit_reached"] = True
                break
            summary["files_seen"] += 1
            if exclude(item):
                issue(item, "quarantine-excluded")
                continue
            try:
                info = item.lstat()
                if not stat.S_ISREG(info.st_mode) or is_link(info):
                    issue(item, "not-a-regular-file")
                    continue
                if info.st_size > max_bytes:
                    issue(item, "file-size-limit")
                    continue
                content, info = read_regular(item, max_bytes)
                digest = hashlib.sha256(content).hexdigest()
                label = signatures.get(digest)
                # EICAR allows trailing whitespace up to 128 bytes.
                if label is None and 68 <= len(content) <= 128:
                    if hashlib.sha256(content.rstrip(b" \t\r\n\x1a")).hexdigest() == EICAR_SHA256:
                        label = signatures[EICAR_SHA256]
                finding = None
                if label:
                    finding = {"kind": "threat", "engine": "SHA-256", "name": label}
                if provider is not None and not provider_failed:
                    try:
                        value = provider.scan(content, str(item))
                        summary["provider_scanned"] += 1
                        if isinstance(value, ScanOutcome):
                            if value.kind == "review":
                                result["engine"]["limited_results"] = result["engine"].get("limited_results", 0) + 1
                            if value.kind and finding is None:
                                finding = {"kind": value.kind, "engine": "ClamAV", "name": value.name}
                        elif value >= 32768:
                            finding = finding or {"kind": "threat", "engine": "Windows AMSI",
                                                  "name": "AMSI malware detection"}
                            finding["amsi_result"] = value
                        elif 0x4000 <= value <= 0x4FFF and finding is None:
                            finding = {"kind": "review", "engine": "Windows AMSI",
                                       "name": "Blocked by administrator policy", "amsi_result": value}
                    except (OSError, RuntimeError) as exc:
                        issue(item, str(exc), error=True)
                        # Avoid a timeout per remaining file after an engine failure.
                        # Hash scans continue, but provider coverage remains incomplete.
                        provider_failed = True
                        result["engine"]["detail"] = str(exc)
                        result["engine"]["failed_during_scan"] = True
                summary["files_scanned"] += 1
                summary["bytes_scanned"] += len(content)
                if finding:
                    finding.update(path=str(item), sha256=digest, size=len(content),
                                   fingerprint=list(fingerprint(info)))
                    summary["threats" if finding["kind"] == "threat" else "reviews"] += 1
                    # Finding count is bounded by max_files; no actionable threat is dropped.
                    result["findings"].append(finding)
            except (OSError, ValueError) as exc:
                issue(item, str(exc), error=True)
            finally:
                if checkpoint:
                    checkpoint(result)
                if progress and (summary["files_seen"] == 1 or summary["files_seen"] % 25 == 0):
                    progress(dict(summary))
        summary["cancelled"] = stopped()
    finally:
        if provider is not None:
            provider.close()
    result["finished_at"] = utc_now()
    complete = (summary["files_scanned"] > 0 and not any(
        summary[key] for key in ("cancelled", "limit_reached", "errors", "skipped")
    ))
    if engine == "clamav" and (result["engine"].get("limited_results") or
            result["engine"].get("database_freshness") != "current" or
            (result["engine"].get("peer_verification_required") and
             result["engine"].get("peer_verified") is not True)):
        complete = False
    if complete and summary["provider_scanned"] == summary["files_scanned"]:
        result["coverage"] = "provider-and-signatures" if engine == "amsi" else "clamav-and-signatures"
    if summary["threats"]:
        result["verdict"] = "threats-found"
    elif summary["reviews"]:
        result["verdict"] = "review"
    elif complete and result["coverage"] != "limited":
        result["verdict"] = "no-threats-found"
    if progress:
        progress(dict(summary))
    if checkpoint:
        checkpoint(result)
    return result


def render_antivirus_scan(result: dict) -> str:
    summary = result["summary"]
    lines = ["AntiOS on-demand antivirus scan", f"Path: {result['path']}",
             f"Engine: {result['engine'].get('provider', 'unknown')}",
             f"Verdict: {result['verdict']}; coverage: {result['coverage']}",
             f"Scanned: {summary['files_scanned']}; threats: {summary['threats']}; "
             f"review: {summary['reviews']}; skipped: {summary['skipped']}; errors: {summary['errors']}"]
    for key in ("version", "database_freshness", "detail"):
        if key in result["engine"]:
            lines.append(f"{key}: {result['engine'][key]}")
    lines.extend(f"{f['kind']}: {f['name']} | {f['path']}" for f in result["findings"])
    return "\n".join(lines)
