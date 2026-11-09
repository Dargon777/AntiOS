"""Bounded on-demand file scanner. Findings never mutate scanned files."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .engine import AntiOSEngine
from .engine_types import ScanOutcome
from .scan_cache import ScanCache, engine_key as make_engine_key, signature_key as make_signature_key

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
        # The size was checked against max_bytes before opening. Reading only
        # that size avoids a max_bytes-sized allocation for a tiny file.
        content = stream.read(opened.st_size + 1)
        after = os.fstat(stream.fileno())
    if len(content) != opened.st_size:
        raise ValueError("File changed while reading")
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


def _scan_large_file(item, provider, signatures, stopped, max_bytes):
    """Hash one stable snapshot while sending identical bytes to AntiOS Engine."""
    target = checked_path(item)
    before = target.lstat()
    if is_link(before) or not stat.S_ISREG(before.st_mode):
        raise ValueError("Not a regular file")
    if max_bytes is not None and before.st_size > max_bytes:
        raise ValueError("File exceeds the scan size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(target, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if fingerprint(opened) != fingerprint(before) or not stat.S_ISREG(opened.st_mode):
            raise ValueError("File changed while opening")
        digest = hashlib.sha256()
        complete = False

        def blocks():
            nonlocal complete
            remaining = opened.st_size
            while remaining:
                if stopped():
                    raise InterruptedError("Scan cancelled")
                block = stream.read(min(65536, remaining))
                if not block:
                    raise ValueError("File changed while reading")
                digest.update(block)
                remaining -= len(block)
                yield block
            complete = True

        chunks = blocks()
        outcome, error = None, None
        if provider is not None:
            try:
                if not hasattr(provider, "scan_stream"):
                    raise OSError("Engine does not support large-file streaming")
                outcome = (provider.scan_stream_named(chunks, str(item))
                           if hasattr(provider, "scan_stream_named")
                           else provider.scan_stream(chunks))
                if not complete or not isinstance(outcome, ScanOutcome):
                    raise OSError("Engine did not confirm the complete stream")
            except (OSError, RuntimeError) as exc:
                # Engine stream limits are per file. Continue hashing and
                # allow the next file to receive its own engine inspection.
                outcome, error = None, str(exc)
        for _block in chunks:
            pass
        after = os.fstat(stream.fileno())
        if (not complete or fingerprint(opened) != fingerprint(after)
                or fingerprint(after) != fingerprint(checked_path(item).lstat())):
            raise ValueError("File changed or could not be read completely")
    sha = digest.hexdigest()
    finding = None
    if sha in signatures:
        finding = {"kind": "threat", "engine": "SHA-256", "name": signatures[sha]}
    elif outcome and outcome.kind:
        finding = {"kind": outcome.kind, "engine": outcome.engine, "name": outcome.name}
    return {"item": item, "info": after, "size": after.st_size, "sha256": sha,
            "finding": finding, "provider_scanned": outcome is not None,
            "file_engine_error": error,
            "limited_result": bool(error or (outcome and (outcome.kind == "review" or not outcome.complete)))}


def scan_files(
    path: str | Path,
    *,
    signature_path: str | Path | None = None,
    max_bytes: int | None = None,
    max_files: int | None = None,
    progress: Callable[[dict], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    provider_factory: Callable | None = None,
    engine: str = "antios",
    engine_service: str | None = None,
    require_verified_peer: bool = False,
    excluded_paths: tuple[Path, ...] = (),
    checkpoint: Callable[[dict], None] | None = None,
    workers: int = 4,
    cache_path: str | Path | None = None,
    use_cache: bool = True,
) -> dict[str, Any]:
    if engine != "antios":
        raise ValueError("Only the independent AntiOS Engine is supported")
    if provider_factory is None:
        provider_factory = lambda: AntiOSEngine(signatures=signatures)
    if any(v is not None and (type(v) is not int or v <= 0) for v in (max_files, max_bytes)):
        raise ValueError("Explicit scan limits must be positive integers")
    if max_bytes is not None and max_bytes > 256 * 1024 * 1024:
        raise ValueError("Explicit scan size limit cannot exceed 256 MiB")
    buffer_limit = min(max_bytes or DEFAULT_MAX_BYTES, DEFAULT_MAX_BYTES)
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 8:
        raise ValueError("Scan workers must be between 1 and 8")
    target = checked_path(path)
    if not target.is_file() and not target.is_dir():
        raise ValueError("Select a regular file or directory")
    signatures = load_signatures(signature_path)
    result: dict[str, Any] = {
        "schema": 1, "kind": "antivirus-scan", "path": str(target),
        "started_at": utc_now(), "finished_at": None,
        "limits": {"max_file_bytes": max_bytes, "max_files": max_files,
                   "max_entries": max_files * 2 if max_files is not None else None, "workers": workers},
        "engine": {"provider": "AntiOS Engine", "available": False,
                   "signatures": len(signatures), "signature_path": str(signature_path or "")},
        "summary": {"files_seen": 0, "entries_seen": 0, "files_scanned": 0, "provider_scanned": 0,
                    "bytes_scanned": 0, "cache_hits": 0, "threats": 0, "reviews": 0, "skipped": 0,
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
        # Keep one iterator per active ancestor. A drive with many sibling
        # directories never needs a drive-sized list of pending paths.
        stack = []
        def children(folder):
            with os.scandir(checked_path(folder)) as entries:
                yield from entries

        def descend(folder):
            stack.append((folder, children(folder)))
        descend(target)
        try:
            while stack and not stopped():
                folder, entries = stack[-1]
                try:
                    entry = next(entries)
                except (StopIteration, OSError, ValueError) as exc:
                    if not isinstance(exc, StopIteration):
                        issue(folder, str(exc), error=True)
                    stack.pop()[1].close()
                    continue
                if max_files is not None and summary["entries_seen"] >= max_files * 2:
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
                    descend(item)
                else:
                    yield item
        finally:
            for _folder, entries in stack:
                entries.close()

    provider_failed = threading.Event()
    cache = None
    cache_engine = ""
    cache_signatures = make_signature_key(signatures)
    cache_allowed = bool(
        use_cache and cache_path and provider is not None
        and result["engine"].get("database_freshness") == "local"
    )
    if cache_allowed:
        try:
            cache = ScanCache(cache_path)
            cache_engine = make_engine_key(result["engine"])
            result["engine"]["cache"] = "enabled"
        except (OSError, sqlite3.Error) as exc:
            result["engine"]["cache"] = "unavailable"
            result["engine"]["cache_detail"] = str(exc)[:300]
    else:
        result["engine"]["cache"] = "disabled"

    effective_workers = min(workers, 2) if provider is not None else 1
    result["limits"]["effective_workers"] = effective_workers
    result["engine"]["limited_results"] = 0

    def apply_outcome(outcome: dict) -> None:
        item = outcome["item"]
        if outcome.get("issue"):
            issue(item, outcome["issue"], error=bool(outcome.get("error")))
            return
        summary["files_scanned"] += 1
        summary["bytes_scanned"] += outcome["size"]
        if outcome.get("provider_scanned"):
            summary["provider_scanned"] += 1
        if outcome.get("provider_error"):
            issue(item, outcome["provider_error"], error=True)
            result["engine"]["detail"] = outcome["provider_error"]
            result["engine"]["failed_during_scan"] = True
        if outcome.get("limited_result"):
            result["engine"]["limited_results"] += 1
        if outcome.get("file_engine_error"):
            issue(item, "Scan engine could not finish this file: " + outcome["file_engine_error"], error=True)
        finding = outcome.get("finding")
        if finding:
            finding.update(
                path=str(item),
                sha256=outcome["sha256"],
                size=outcome["size"],
                fingerprint=list(fingerprint(outcome["info"])),
            )
            summary["threats" if finding["kind"] == "threat" else "reviews"] += 1
            result["findings"].append(finding)
        elif (cache is not None and outcome.get("provider_scanned")
              and not outcome.get("limited_result") and not outcome.get("provider_error")
              and outcome["size"] <= DEFAULT_MAX_BYTES):
            try:
                cache.put(
                    item, outcome["info"], cache_engine, cache_signatures, outcome["sha256"]
                )
            except (OSError, sqlite3.Error):
                pass

    def scan_one(item: Path) -> dict:
        try:
            if stopped():
                return {"item": item, "issue": "cancelled"}
            info = item.lstat()
            if not stat.S_ISREG(info.st_mode) or is_link(info):
                return {"item": item, "issue": "not-a-regular-file"}
            if max_bytes is not None and info.st_size > max_bytes:
                return {"item": item, "issue": "file-size-limit"}
            if info.st_size > DEFAULT_MAX_BYTES:
                return _scan_large_file(item, provider, signatures, stopped, max_bytes)
            content, info = read_regular(item, buffer_limit)
            digest = hashlib.sha256(content).hexdigest()
            label = signatures.get(digest)
            if label is None and 68 <= len(content) <= 128:
                if hashlib.sha256(content.rstrip(b" \t\r\n\x1a")).hexdigest() == EICAR_SHA256:
                    label = signatures[EICAR_SHA256]
            finding = {"kind": "threat", "engine": "SHA-256", "name": label} if label else None
            provider_scanned = False
            provider_error = None
            limited_result = False
            if provider is not None and not provider_failed.is_set():
                try:
                    value = (provider.scan_with_digest(content, str(item), digest)
                             if hasattr(provider, "scan_with_digest")
                             else provider.scan(content, str(item)))
                    provider_scanned = True
                    if isinstance(value, ScanOutcome):
                        limited_result = value.kind == "review" or not value.complete
                        # Incomplete inspection of a particular file is not a
                        # global provider crash. Preserve its limited verdict.
                        if value.kind and finding is None:
                            finding = {"kind": value.kind, "engine": value.engine, "name": value.name}
                    else:
                        raise OSError("AntiOS Engine returned an invalid result")
                except (OSError, RuntimeError) as exc:
                    provider_failed.set()
                    provider_error = str(exc)
            return {
                "item": item,
                "info": info,
                "size": len(content),
                "sha256": digest,
                "finding": finding,
                "provider_scanned": provider_scanned,
                "provider_error": provider_error,
                "limited_result": limited_result,
            }
        except (OSError, ValueError) as exc:
            return {"item": item, "issue": str(exc), "error": True}

    def account_cached(item: Path, info: os.stat_result, digest: str) -> None:
        summary["files_scanned"] += 1
        summary["provider_scanned"] += 1
        summary["bytes_scanned"] += int(info.st_size)
        summary["cache_hits"] += 1

    def prepare(item: Path) -> tuple[bool, os.stat_result | None]:
        try:
            info = item.lstat()
            if not stat.S_ISREG(info.st_mode) or is_link(info):
                issue(item, "not-a-regular-file")
                return False, None
            if max_bytes is not None and info.st_size > max_bytes:
                issue(item, "file-size-limit")
                return False, None
            if cache is not None and info.st_size <= DEFAULT_MAX_BYTES:
                try:
                    digest = cache.get(item, info, cache_engine, cache_signatures)
                except (OSError, sqlite3.Error):
                    digest = None
                if digest:
                    # Metadata is only a lookup hint. Re-read and hash the file
                    # through the same stable-snapshot path before trusting a hit.
                    content, verified_info = read_regular(item, buffer_limit)
                    if hashlib.sha256(content).hexdigest() == digest:
                        account_cached(item, verified_info, digest)
                        return False, verified_info
            return True, info
        except (OSError, ValueError) as exc:
            issue(item, str(exc), error=True)
            return False, None

    def after_item() -> None:
        if checkpoint:
            checkpoint(result)
        if progress and (summary["files_seen"] == 1 or summary["files_seen"] % 25 == 0):
            progress(dict(summary))

    pending: list[Path] = []
    executor = ThreadPoolExecutor(max_workers=effective_workers) if effective_workers > 1 else None
    provider_probe_done = effective_workers <= 1
    try:
        def flush_pending() -> None:
            nonlocal pending, provider_probe_done
            if not pending:
                return

            # Preserve the failure circuit breaker: prove that the provider is
            # responsive with one request before fanning work out concurrently.
            # An unhealthy scanner cannot fan out unbounded failures.
            if executor is not None and not provider_probe_done and pending:
                first = pending.pop(0)
                apply_outcome(scan_one(first))
                after_item()
                provider_probe_done = True

            if not pending:
                return
            if executor is None or provider_failed.is_set():
                outcomes = map(scan_one, pending)
            else:
                outcomes = executor.map(scan_one, pending)
            for outcome in outcomes:
                apply_outcome(outcome)
                after_item()
            pending = []

        for item in candidates():
            if stopped():
                break
            if max_files is not None and summary["files_seen"] >= max_files:
                summary["limit_reached"] = True
                break
            summary["files_seen"] += 1
            if exclude(item):
                issue(item, "quarantine-excluded")
                after_item()
                continue
            should_scan, _info = prepare(item)
            if not should_scan:
                after_item()
                continue
            pending.append(item)
            if len(pending) >= effective_workers * 4:
                flush_pending()
        flush_pending()
        summary["cancelled"] = stopped()
    finally:
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
        if provider is not None:
            provider.close()
        if cache is not None:
            try:
                cache.close()
            except (OSError, sqlite3.Error):
                pass
    result["finished_at"] = utc_now()
    complete = (summary["files_scanned"] > 0 and not any(
        summary[key] for key in ("cancelled", "limit_reached", "errors", "skipped")
    ))
    if (result["engine"].get("limited_results") or
            result["engine"].get("database_freshness") != "local"):
        complete = False
    if complete and summary["provider_scanned"] == summary["files_scanned"]:
        result["coverage"] = "antios-local-inspection"
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
