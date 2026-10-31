"""Narrow process boundary between public AntiOS and an optional private core.

The public package deliberately knows only a small versioned RPC surface.  The
private implementation is never imported as Python and production builds accept
only a managed, protected, signer-matched sidecar executable.
"""
from __future__ import annotations

from functools import lru_cache
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from .windows_process import hidden_process_kwargs

INTERFACE_VERSION = 1
CORE_FILENAME = "AntiOS-Core.exe"
MAX_REQUEST_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 15

# Keep this intentionally small.  New private capabilities must be added
# explicitly instead of turning the bridge into an arbitrary command tunnel.
PUBLIC_OPERATIONS = frozenset({
    "core.ping",
    "protection.status",
})


class PrivateCoreError(RuntimeError):
    """Base error for the optional private-core boundary."""


class PrivateCoreUnavailable(PrivateCoreError):
    """No acceptable private core is available for this process."""


class PrivateCoreProtocolError(PrivateCoreError):
    """The private core did not satisfy the public interface contract."""


def _development_core_path() -> Path | None:
    """Allow an explicit source-tree core only for opt-in development/testing.

    Packaged/frozen AntiOS never honors these environment variables.
    """
    if getattr(sys, "frozen", False):
        return None
    if os.environ.get("ANTIOS_ALLOW_PRIVATE_CORE_DEV") != "1":
        return None
    raw = os.environ.get("ANTIOS_PRIVATE_CORE_DEV")
    if not raw:
        return None
    candidate = Path(raw).expanduser().resolve()
    if not candidate.is_file() or candidate.is_symlink():
        raise PrivateCoreUnavailable("Development private core is missing or unsafe")
    return candidate


def _program_files_root() -> Path:
    if os.name != "nt":
        raise PrivateCoreUnavailable("Managed private core requires Windows")
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "ProgramFilesDir")
    except (OSError, ValueError) as exc:
        raise PrivateCoreUnavailable("Cannot resolve the managed install root") from exc
    return Path(value).resolve()


@lru_cache(maxsize=1)
def _trusted_installed_core_path() -> Path | None:
    """Return the production sidecar only after install and signer validation."""
    if os.name != "nt" or not getattr(sys, "frozen", False):
        return None

    from .elevation import managed_cli_path

    try:
        cli = Path(managed_cli_path()).resolve()
    except (OSError, RuntimeError, ValueError, PermissionError) as exc:
        raise PrivateCoreUnavailable("Managed AntiOS installation is not trusted") from exc

    core = (cli.parent / CORE_FILENAME).resolve()
    if not core.is_file() or core.is_symlink() or core.parent != cli.parent:
        return None

    from .windows_acl import assert_protected_install

    try:
        assert_protected_install(core, _program_files_root())
    except (OSError, RuntimeError, ValueError, PermissionError) as exc:
        raise PrivateCoreUnavailable("Private core installation is not protected") from exc

    # Reuse the same publisher identity already trusted for installed AntiOS.
    # This is a trust check, not a secrecy mechanism.
    from .updater import (
        _authenticode,
        _installed_signer_thumbprint,
        _matches_installed_signer,
    )

    try:
        signature = _authenticode(core)
        signer = _installed_signer_thumbprint()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        raise PrivateCoreUnavailable("Private core publisher cannot be verified") from exc
    if not _matches_installed_signer(signature, signer):
        raise PrivateCoreUnavailable("Private core publisher does not match installed AntiOS")
    return core


def _resolve_core_path() -> Path:
    installed = _trusted_installed_core_path()
    if installed is not None:
        return installed
    development = _development_core_path()
    if development is not None:
        return development
    raise PrivateCoreUnavailable("Private core is not installed")


def private_core_status() -> dict:
    """Return a deliberately small, non-sensitive availability summary."""
    try:
        path = _resolve_core_path()
    except PrivateCoreUnavailable:
        return {
            "available": False,
            "interface": INTERFACE_VERSION,
        }
    return {
        "available": True,
        "interface": INTERFACE_VERSION,
        "mode": "installed" if getattr(sys, "frozen", False) else "development",
        "component": path.name,
    }


def invoke_private_core(
    operation: str,
    payload: dict | None = None,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """Invoke one allowlisted operation over a single-use stdio RPC process."""
    if operation not in PUBLIC_OPERATIONS:
        raise ValueError(f"Unsupported private-core operation: {operation}")
    if payload is not None and not isinstance(payload, dict):
        raise TypeError("Private-core payload must be a mapping")
    if not isinstance(timeout_seconds, int) or timeout_seconds <= 0 or timeout_seconds > 120:
        raise ValueError("Private-core timeout is outside the public safety bound")

    core = _resolve_core_path()
    request_id = uuid.uuid4().hex
    request = {
        "schema": INTERFACE_VERSION,
        "request_id": request_id,
        "operation": operation,
        "payload": payload or {},
    }
    wire = (json.dumps(request, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    if len(wire) > MAX_REQUEST_BYTES:
        raise ValueError("Private-core request is too large")

    try:
        completed = subprocess.run(
            [str(core), "--stdio-rpc"],
            input=wire,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(core.parent),
            timeout=timeout_seconds,
            check=False,
            **hidden_process_kwargs(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PrivateCoreUnavailable("Private core could not be started") from exc

    if completed.returncode != 0:
        raise PrivateCoreError("Private core operation failed")
    if len(completed.stdout) > MAX_RESPONSE_BYTES:
        raise PrivateCoreProtocolError("Private core response exceeds the public limit")

    try:
        response = json.loads(completed.stdout.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrivateCoreProtocolError("Private core returned invalid JSON") from exc
    if not isinstance(response, dict):
        raise PrivateCoreProtocolError("Private core response must be an object")
    if response.get("schema") != INTERFACE_VERSION:
        raise PrivateCoreProtocolError("Private core interface version mismatch")
    if response.get("request_id") != request_id:
        raise PrivateCoreProtocolError("Private core response does not match the request")
    if response.get("ok") is not True:
        raise PrivateCoreError("Private core rejected the operation")

    result = response.get("result")
    if not isinstance(result, dict):
        raise PrivateCoreProtocolError("Private core result must be an object")
    return result
