"""Standalone ClamAV database maintenance for AntiOS.

The updater never invokes a shell and accepts only a regular, non-reparse executable.
On Windows, automatic discovery is deliberately limited to Program Files or an
explicit ANTIOS_FRESHCLAM path so a user-writable PATH entry cannot become an
elevated code-execution primitive.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

from .antivirus import checked_path
from .clamav import ClamAVScanner


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_executable(path: str | Path) -> Path:
    target = checked_path(path)
    if not target.is_file():
        raise FileNotFoundError(f"freshclam executable not found: {target}")
    return target


def find_freshclam(explicit: str | Path | None = None) -> Path:
    """Locate freshclam without trusting a user-writable PATH on Windows."""
    if explicit is not None:
        return _validate_executable(explicit)

    configured = os.environ.get("ANTIOS_FRESHCLAM")
    if configured:
        return _validate_executable(configured)

    if os.name == "nt":
        candidates: list[Path] = []
        for variable in ("ProgramFiles", "ProgramW6432"):
            root = os.environ.get(variable)
            if root:
                candidates.append(Path(root) / "ClamAV" / "freshclam.exe")
        for candidate in candidates:
            try:
                return _validate_executable(candidate)
            except (OSError, ValueError):
                pass
        raise FileNotFoundError(
            "freshclam was not found in Program Files; set ANTIOS_FRESHCLAM "
            "or pass --freshclam with the trusted ClamAV installation path"
        )

    found = shutil.which("freshclam")
    if not found:
        raise FileNotFoundError("freshclam was not found")
    return _validate_executable(found)


def update_clamav_database(
    *,
    executable: str | Path | None = None,
    config_file: str | Path | None = None,
    timeout: float = 300,
    engine_service: str | None = None,
    scanner_factory=ClamAVScanner,
) -> dict[str, Any]:
    if not 1 <= timeout <= 1800:
        raise ValueError("Update timeout must be between 1 and 1800 seconds")

    freshclam = find_freshclam(executable)
    command = [str(freshclam), "--stdout"]
    if config_file is not None:
        config = checked_path(config_file)
        if not config.is_file():
            raise FileNotFoundError(f"freshclam config not found: {config}")
        command.append(f"--config-file={config}")

    started_at = _utc_now()
    try:
        process = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("freshclam database update timed out") from exc

    result: dict[str, Any] = {
        "schema": 1,
        "kind": "antios-engine-update",
        "started_at": started_at,
        "finished_at": _utc_now(),
        "freshclam": str(freshclam),
        "exit_code": process.returncode,
        "stdout": process.stdout[-4000:],
        "stderr": process.stderr[-4000:],
        "engine": {"available": False},
        "success": False,
    }
    if process.returncode != 0:
        return result

    try:
        scanner = scanner_factory(
            service_name=engine_service,
            require_verified_peer=os.name == "nt",
            timeout=10,
        )
        try:
            result["engine"] = dict(scanner.metadata, available=True)
        finally:
            scanner.close()
    except (OSError, RuntimeError, ValueError) as exc:
        result["engine"] = {"available": False, "detail": str(exc)[:500]}
        return result

    peer_ok = (
        not result["engine"].get("peer_verification_required")
        or result["engine"].get("peer_verified") is True
    )
    result["success"] = bool(
        result["engine"].get("available")
        and result["engine"].get("database_freshness") == "current"
        and peer_ok
    )
    return result


def render_engine_update(result: dict[str, Any]) -> str:
    engine = result.get("engine", {})
    lines = [
        "AntiOS standalone engine update",
        f"freshclam: {result.get('freshclam', 'unknown')}",
        f"Updater exit code: {result.get('exit_code', 'unknown')}",
        f"Engine available: {engine.get('available', False)}",
        f"Database freshness: {engine.get('database_freshness', 'unknown')}",
        f"Trusted engine peer: {engine.get('peer_verified', 'n/a')}",
        f"Ready: {result.get('success', False)}",
    ]
    if result.get("stderr"):
        lines.append("freshclam stderr: " + str(result["stderr"]).strip()[:500])
    if engine.get("detail"):
        lines.append("Engine detail: " + str(engine["detail"])[:500])
    return "\n".join(lines)
