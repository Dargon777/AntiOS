"""Authenticated local catalog updates shared by all AntiOS scan entry points."""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import date
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .signature_bootstrap import BUNDLED_PACKAGE, PUBLIC_KEY

MAX_PACKAGE_BYTES = 8 * 1024 * 1024
MAX_TRUSTED_FILES = 4096
_MAX_TRUSTED_FILE_BYTES = 64 * 1024 * 1024
_SIGNING_CONTEXT = b"AntiOS.SignatureCatalog.v1\0"


def default_catalog_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local")
        return (root / "AntiOS" / "signatures.sqlite3").absolute()
    root = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    return (root / "antios" / "signatures.sqlite3").absolute()


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate signature package field")
        value[key] = item
    return value


def _json(data: bytes) -> dict:
    try:
        result = json.loads(data, object_pairs_hook=_object)
    except (ValueError, RecursionError) as exc:
        raise ValueError("Invalid signature package JSON") from exc
    if not isinstance(result, dict):
        raise ValueError("Invalid signature package object")
    return result


def signed_bytes(catalog: dict) -> bytes:
    """Canonical byte representation used by the verifier and offline signer."""
    return _SIGNING_CONTEXT + json.dumps(
        catalog, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ).encode("ascii")


def _date(value) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Invalid signature catalog date")
    date.fromisoformat(value)
    return value


@dataclass(frozen=True)
class Catalog:
    version: int
    published: str
    rules: Mapping[str, str]
    source: str = "bundled"
    warning: str = ""

    def metadata(self) -> dict:
        result = {
            "signature_catalog_version": self.version,
            "signature_catalog_published": self.published,
            "signature_catalog_status": "fallback" if self.warning else self.source,
            "signature_catalog_entries": len(self.rules),
        }
        if self.warning:
            result["signature_catalog_warning"] = self.warning
        return result


def verify_catalog(package: bytes, public_key: bytes | None = None) -> Catalog:
    if not isinstance(package, bytes) or len(package) > MAX_PACKAGE_BYTES:
        raise ValueError("Invalid signature package size")
    envelope = _json(package)
    if set(envelope) != {"catalog", "signature"} or not isinstance(envelope["catalog"], dict):
        raise ValueError("Invalid signature package envelope")
    catalog, signature = envelope["catalog"], envelope["signature"]
    if not isinstance(signature, str) or not re.fullmatch(r"[a-f0-9]{128}", signature):
        raise ValueError("Invalid catalog signature format")
    try:
        Ed25519PublicKey.from_public_bytes(PUBLIC_KEY if public_key is None else public_key).verify(
            bytes.fromhex(signature), signed_bytes(catalog),
        )
    except (InvalidSignature, RecursionError) as exc:
        raise ValueError("Signature catalog authentication failed") from exc
    if set(catalog) != {"schema", "version", "published", "sha256"} or (
            type(catalog["schema"]) is not int or catalog["schema"] != 1):
        raise ValueError("Unsupported signature catalog schema")
    version = catalog["version"]
    if type(version) is not int or not 1 <= version <= 2_147_483_647:
        raise ValueError("Invalid signature catalog version")
    published = _date(catalog["published"])
    entries = catalog["sha256"]
    if not isinstance(entries, dict) or len(entries) > 50_000:
        raise ValueError("Invalid signature catalog entry count")
    rules = {}
    for digest, entry in entries.items():
        if not re.fullmatch(r"[a-f0-9]{64}", digest) or not isinstance(entry, dict) or (
                set(entry) != {"label", "source", "source_date"}):
            raise ValueError("Invalid catalog entry")
        label, source = entry["label"], entry["source"]
        if (not isinstance(label, str) or not label.strip() or not label.isprintable()
                or len(label) > 200 or not isinstance(source, str)
                or not source.isascii() or not source.isprintable() or len(source) > 500):
            raise ValueError("Invalid catalog label or source")
        url = urlsplit(source)
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise ValueError("Invalid catalog source URL")
        if _date(entry["source_date"]) > published:
            raise ValueError("Catalog source postdates publication")
        rules[digest] = label
    return Catalog(version, published, MappingProxyType(rules))


@lru_cache(maxsize=1)
def bundled_catalog() -> Catalog:
    return verify_catalog(BUNDLED_PACKAGE)


def _versions(db):
    return db.execute(
        """SELECT version, CASE WHEN length(package) <= ? THEN package END
           FROM catalogs ORDER BY version DESC LIMIT 2""",
        (MAX_PACKAGE_BYTES,),
    ).fetchall()


def _has_table(db, name: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?", (name,),
    ).fetchone() is not None


def load_active_catalog() -> Catalog:
    from .antivirus import checked_path

    baseline = bundled_catalog()
    try:
        path = checked_path(default_catalog_path())
    except FileNotFoundError:
        return baseline
    except (OSError, ValueError):
        return replace(baseline, warning="Installed signature catalog cannot be read")
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("BEGIN")
            if not _has_table(db, "catalogs") and _has_table(db, "trusted_files"):
                return baseline
            versions = _versions(db)
    except sqlite3.Error:
        return replace(baseline, warning="Installed signature catalog cannot be read")

    warning = "" if versions else "Installed signature catalog is empty"
    for version, package in versions:
        if type(version) is not int:
            warning = "Installed signature catalog failed validation"
            continue
        if version <= baseline.version:
            break
        try:
            catalog = verify_catalog(package)
            if catalog.version != version:
                raise ValueError("Catalog version mismatch")
        except ValueError:
            warning = "Installed signature catalog failed validation"
            continue
        return replace(catalog, source="installed", warning=warning)
    return replace(baseline, warning=warning)


def _read_candidate(path: str | Path) -> tuple[bytes, Catalog]:
    from .antivirus import read_regular

    package, _ = read_regular(Path(path), MAX_PACKAGE_BYTES)
    return package, verify_catalog(package)


def _checked_catalog_store():
    from .antivirus import checked_path

    target = default_catalog_path()
    try:
        return checked_path(target)
    except FileNotFoundError:
        return None


def _prepare_catalog_store():
    from .antivirus import checked_path

    target = default_catalog_path()
    ancestor = target.parent
    while not ancestor.exists() and not ancestor.is_symlink():
        ancestor = ancestor.parent
    checked_path(ancestor)
    target.parent.mkdir(parents=True, exist_ok=True)
    checked_path(target.parent)
    _checked_catalog_store()
    return target


def _trusted_hashes(db) -> tuple[str, ...]:
    if not _has_table(db, "trusted_files"):
        return ()
    rows = db.execute("SELECT sha256 FROM trusted_files ORDER BY sha256 LIMIT ?", (
        MAX_TRUSTED_FILES + 1,
    )).fetchall()
    if len(rows) > MAX_TRUSTED_FILES or any(
        not isinstance(row[0], str) or re.fullmatch(r"[a-f0-9]{64}", row[0]) is None
        for row in rows
    ):
        raise ValueError("Invalid trusted-file baseline")
    return tuple(row[0] for row in rows)


def _read_trusted_hashes() -> tuple[str, ...]:
    target = _checked_catalog_store()
    if target is None:
        return ()
    try:
        with closing(sqlite3.connect(target.as_uri() + "?mode=ro", uri=True, timeout=5)) as db, db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("BEGIN")
            return _trusted_hashes(db)
    except sqlite3.Error as exc:
        raise OSError("Trusted-file baseline could not be checked") from exc


def lookup_trusted_hashes(digests: Iterable[str]) -> set[str]:
    """Find exact local trust conflicts without writing to the catalog store."""
    wanted = set(digests)
    return wanted.intersection(_read_trusted_hashes()) if wanted else set()


def _preflight(catalog: Catalog, trusted: tuple[str, ...]) -> dict:
    trusted_hashes = set(trusted)
    conflicts = [{"sha256": digest, "label": catalog.rules[digest]}
                 for digest in sorted(catalog.rules) if digest in trusted_hashes]
    return {
        "schema": 1, "kind": "signature-catalog-preflight", "version": catalog.version,
        "trusted_hashes_checked": len(trusted), "conflicts": conflicts,
        "status": "blocked" if conflicts else "passed" if trusted else "no-baseline",
    }


def catalog_preflight(path: str | Path) -> dict:
    """Verify a candidate and compare it with the explicitly curated local baseline."""
    _, candidate = _read_candidate(path)
    return _preflight(candidate, _read_trusted_hashes())


def replay_catalog(path: str | Path, report_path: str | Path) -> dict:
    """Match a verified catalog against historical whole-file hashes, for review."""
    from .antivirus import read_regular
    from .scan_verdict import MAX_REPLAY_BYTES, read_scan_report_json, replay_scan_report

    package, candidate = _read_candidate(path)
    content, _ = read_regular(Path(report_path), MAX_REPLAY_BYTES)
    report = read_scan_report_json(content)
    replayed = replay_scan_report(report)
    historical = report["proof_receipt"]["evidence"]
    files_scanned = historical["counts"]["files_scanned"]
    if type(files_scanned) is not int or files_scanned < 0:
        raise ValueError("Invalid historical scan file count")

    if replayed["policy"] == "antios-scan-verdict-v2":
        hashes = Counter(report["file_hash_history"]["entries"])
        source = "scan-hash-history"
    else:
        # v1 does not bind a history ledger. Its optional digest on each
        # finding identifies the enclosing file, even for an archive hit.
        by_path: dict[str, str] = {}
        for finding in report["findings"]:
            digest = finding.get("sha256")
            reported_path = finding.get("path")
            if (not isinstance(reported_path, str) or not reported_path or
                    not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None):
                continue
            if by_path.setdefault(reported_path, digest) != digest:
                raise ValueError("Conflicting historical hashes for the same reported file")
        hashes = Counter(by_path.values())
        source = "findings-only"

    files_with_hash = sum(hashes.values())
    if files_with_hash > files_scanned:
        raise ValueError("Historical hash count exceeds the scan file count")
    matches = [
        {"sha256": digest, "label": candidate.rules[digest], "files": hashes[digest]}
        for digest in sorted(candidate.rules.keys() & hashes.keys())
    ]
    return {
        "schema": 1,
        "kind": "signature-catalog-replay",
        "version": candidate.version,
        "package_sha256": hashlib.sha256(package).hexdigest(),
        "receipt_sha256": replayed["receipt_sha256"],
        "scope": "whole-file-sha256",
        "hash_source": source,
        "status": "matches" if matches else "no-matches" if files_with_hash else "no-hashes",
        "historical_coverage": historical["coverage"],
        "files_scanned": files_scanned,
        "files_with_hash": files_with_hash,
        "files_without_hash": files_scanned - files_with_hash,
        "archive_members": "not-replayed",
        "matches": matches,
    }


def trust_file(path: str | Path) -> str:
    """Remember an explicitly selected trusted file by content, without storing its path."""
    from .antivirus import read_regular

    content, _ = read_regular(Path(path), _MAX_TRUSTED_FILE_BYTES)
    digest = hashlib.sha256(content).hexdigest()
    target = _prepare_catalog_store()
    try:
        with closing(sqlite3.connect(target, timeout=5)) as db, db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS trusted_files (sha256 TEXT PRIMARY KEY)")
            trusted = _trusted_hashes(db)
            if digest not in trusted and len(trusted) == MAX_TRUSTED_FILES:
                raise ValueError("Trusted-file baseline is full")
            db.execute("INSERT OR IGNORE INTO trusted_files VALUES (?)", (digest,))
    except sqlite3.Error as exc:
        raise OSError("Trusted-file baseline could not be saved") from exc
    return digest


def untrust_hash(digest: str) -> bool:
    if re.fullmatch(r"[a-f0-9]{64}", digest) is None:
        raise ValueError("Expected a lowercase SHA-256 hash")
    target = _checked_catalog_store()
    if target is None:
        return False
    try:
        with closing(sqlite3.connect(target, timeout=5)) as db, db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("BEGIN IMMEDIATE")
            if digest not in _trusted_hashes(db):
                return False
            db.execute("DELETE FROM trusted_files WHERE sha256=?", (digest,))
            return True
    except sqlite3.Error as exc:
        raise OSError("Trusted-file baseline could not be saved") from exc


def install_catalog(path: str | Path) -> Catalog:
    package, catalog = _read_candidate(path)
    baseline = bundled_catalog()
    if catalog.version <= baseline.version:
        raise ValueError("Update must be newer than the bundled signature catalog")

    target = _prepare_catalog_store()
    try:
        with closing(sqlite3.connect(target, timeout=5)) as db, db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS catalogs (version INTEGER PRIMARY KEY, package BLOB NOT NULL)")
            versions = _versions(db)
            if any(type(version) is not int for version, _ in versions):
                raise ValueError("Installed signature catalog versions are invalid")
            if versions and catalog.version <= versions[0][0]:
                if (catalog.version, package) == versions[0]:
                    return replace(catalog, source="installed")
                raise ValueError("Update must be newer than the installed signature catalog")
            preflight = _preflight(catalog, _trusted_hashes(db))
            if preflight["conflicts"]:
                raise ValueError(
                    f"Signature update blocked by {len(preflight['conflicts'])} trusted-file "
                    "conflict(s). Run signatures preflight for details"
                )
            db.execute("INSERT INTO catalogs VALUES (?, ?)", (catalog.version, package))
            # Keep the latest older *verified* package as a fallback.
            keep = baseline.version
            for version, previous in versions:
                if version <= baseline.version:
                    break
                try:
                    if verify_catalog(previous).version == version:
                        keep = version
                        break
                except ValueError:
                    continue
            db.execute("DELETE FROM catalogs WHERE version NOT IN (?, ?)", (catalog.version, keep))
    except sqlite3.Error as exc:
        raise OSError("Signature catalog update could not be committed") from exc
    return replace(catalog, source="installed")
