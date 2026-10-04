"""Safe wrapper around the Windows protection-repair PowerShell workflow."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


def _script_path() -> Path:
    if getattr(sys, "frozen", False):
        candidate = Path(sys.executable).resolve().parent / "protection-repair.ps1"
    else:
        candidate = Path(__file__).resolve().parents[1] / "scripts" / "protection-repair.ps1"
    if not candidate.is_file():
        raise FileNotFoundError(f"Protection repair script is missing: {candidate}")
    return candidate


def run_protection_repair(*, apply: bool = False, update_signatures: bool = False,
                          timeout: float = 180.0) -> dict:
    if os.name != "nt":
        raise OSError("Protection repair is available on Windows only")
    powershell = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
    )
    command = [
        powershell,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", str(_script_path()),
        "-Json",
    ]
    if apply:
        command.append("-Apply")
    if update_signatures:
        command.append("-UpdateSignatures")
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Protection repair failed").strip()
        raise RuntimeError(detail[:2000])
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Protection repair returned invalid JSON") from exc
    if not isinstance(payload, dict) or payload.get("kind") != "antios-protection-repair":
        raise RuntimeError("Protection repair returned an unexpected result")
    return payload
