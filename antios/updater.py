"""Release discovery and signature-gated AntiOS update downloads."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.request import Request, urlopen

from . import __version__

RELEASES_API = "https://api.github.com/repos/Dargon777/AntiOS/releases"
MAX_RELEASE_RESPONSE = 2 * 1024 * 1024
MAX_SETUP_BYTES = 512 * 1024 * 1024
MAX_CHECKSUM_BYTES = 4096


def _alpha_number(version: str) -> int:
    match = re.fullmatch(r"2\.0\.0a(\d+)", version)
    if not match:
        raise ValueError(f"Unsupported AntiOS version format: {version}")
    return int(match.group(1))


def _request_json(url: str) -> object:
    request = Request(url, headers={"User-Agent": f"AntiOS/{__version__}", "Accept": "application/vnd.github+json"})
    with urlopen(request, timeout=20) as response:
        content = response.read(MAX_RELEASE_RESPONSE + 1)
    if len(content) > MAX_RELEASE_RESPONSE:
        raise RuntimeError("GitHub release response is too large")
    return json.loads(content)


def latest_alpha() -> dict:
    data = _request_json(RELEASES_API)
    if not isinstance(data, list):
        raise RuntimeError("Unexpected GitHub releases response")
    candidates = []
    for release in data:
        if not isinstance(release, dict) or release.get("draft"):
            continue
        match = re.fullmatch(r"v2\.0\.0-alpha\.(\d+)", str(release.get("tag_name", "")))
        if match:
            candidates.append((int(match.group(1)), release))
    if not candidates:
        raise RuntimeError("No AntiOS alpha releases found")
    number, release = max(candidates, key=lambda item: item[0])
    assets = {}
    for asset in release.get("assets") or []:
        if isinstance(asset, dict) and isinstance(asset.get("name"), str):
            assets[asset["name"]] = {
                "url": asset.get("browser_download_url"),
                "size": asset.get("size"),
                "digest": asset.get("digest"),
            }
    current = _alpha_number(__version__)
    return {
        "current_version": __version__,
        "current_alpha": current,
        "latest_alpha": number,
        "latest_version": f"2.0.0a{number}",
        "tag": release.get("tag_name"),
        "published_at": release.get("published_at"),
        "html_url": release.get("html_url"),
        "update_available": number > current,
        "assets": assets,
    }


def _download(url: str, destination: Path, limit: int) -> None:
    if not isinstance(url, str) or not url.startswith(
        "https://github.com/Dargon777/AntiOS/releases/download/"
    ):
        raise RuntimeError("Refusing an unexpected update download URL")
    request = Request(url, headers={"User-Agent": f"AntiOS/{__version__}"})
    with urlopen(request, timeout=60) as response, destination.open("xb") as stream:
        total = 0
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise RuntimeError("Update download exceeds the safety limit")
            stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _parse_checksum(content: bytes) -> str:
    if len(content) > MAX_CHECKSUM_BYTES:
        raise RuntimeError("Update checksum file is too large")
    text = content.decode("ascii", errors="strict").strip()
    match = re.fullmatch(r"([a-f0-9]{64})\s+\*?AntiOS-Setup\.exe", text)
    if not match:
        raise RuntimeError("Update checksum file has an unexpected format")
    return match.group(1)


def _authenticode(path: Path) -> dict:
    if os.name != "nt":
        raise OSError("Authenticode verification requires Windows")
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    command = (
        "$s=Get-AuthenticodeSignature -LiteralPath $args[0];"
        "[pscustomobject]@{Status=[string]$s.Status;"
        "Subject=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{$null};"
        "Thumbprint=if($s.SignerCertificate){$s.SignerCertificate.Thumbprint}else{$null}}"
        "|ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command", command, str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or "Authenticode verification failed").strip())
    payload = json.loads(result.stdout)
    return payload if isinstance(payload, dict) else {}


def download_update(directory: str | Path | None = None, *, require_signature: bool = True) -> dict:
    release = latest_alpha()
    if not release["update_available"]:
        return dict(release, downloaded=False)

    setup = release["assets"].get("AntiOS-Setup.exe")
    checksum = release["assets"].get("AntiOS-Setup.exe.sha256")
    if not setup or not checksum:
        raise RuntimeError("Latest AntiOS release does not contain Setup/checksum assets")

    target_dir = Path(directory) if directory else Path(tempfile.mkdtemp(prefix="AntiOS-Update-"))
    target_dir.mkdir(parents=True, exist_ok=True)
    setup_path = target_dir / "AntiOS-Setup.exe"
    checksum_path = target_dir / "AntiOS-Setup.exe.sha256"
    if setup_path.exists() or checksum_path.exists():
        raise FileExistsError("Update destination already contains AntiOS update files")

    try:
        _download(str(checksum["url"]), checksum_path, MAX_CHECKSUM_BYTES)
        _download(str(setup["url"]), setup_path, MAX_SETUP_BYTES)
        expected = _parse_checksum(checksum_path.read_bytes())
        actual = _sha256_file(setup_path)
        if actual != expected:
            raise RuntimeError("Downloaded AntiOS Setup failed SHA-256 verification")
        api_digest = setup.get("digest")
        if api_digest and api_digest != f"sha256:{actual}":
            raise RuntimeError("GitHub asset digest does not match downloaded Setup")

        signature = None
        if require_signature:
            signature = _authenticode(setup_path)
            if signature.get("Status") != "Valid":
                raise RuntimeError(
                    "Downloaded Setup is not Authenticode-signed with a valid trusted certificate; "
                    "automatic installation is refused"
                )
        return dict(
            release,
            downloaded=True,
            setup_path=str(setup_path),
            sha256=actual,
            signature=signature,
            signature_required_for_install=True,
            install_ready=bool(signature and signature.get("Status") == "Valid"),
        )
    except Exception:
        setup_path.unlink(missing_ok=True)
        checksum_path.unlink(missing_ok=True)
        raise


def schedule_install(setup_path: str | Path, expected_sha256: str) -> dict:
    """Launch verified Setup only after this AntiOS process exits.

    The helper re-checks SHA-256 and Authenticode immediately before launch to
    close the verification/use race in the user temp directory.
    """
    if os.name != "nt":
        raise OSError("Automatic AntiOS installation requires Windows")
    setup = Path(setup_path).resolve()
    if not setup.is_file():
        raise FileNotFoundError(setup)
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("Invalid expected update digest")

    helper = setup.parent / "install-antios-update.ps1"
    helper.write_text(
        """param([int]$WaitPid,[string]$Setup,[string]$Expected)\n"""
        """$ErrorActionPreference='Stop'\n"""
        """try { Wait-Process -Id $WaitPid -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 750; """
        """$actual=(Get-FileHash -LiteralPath $Setup -Algorithm SHA256).Hash.ToLowerInvariant(); """
        """if($actual -ne $Expected){ throw 'AntiOS update digest changed before install.' }; """
        """$sig=Get-AuthenticodeSignature -LiteralPath $Setup; """
        """if($sig.Status -ne 'Valid'){ throw 'AntiOS update signature is no longer valid.' }; """
        """Start-Process -FilePath $Setup -ArgumentList '/S' -Verb RunAs -Wait } """
        """finally { Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue }\n""",
        encoding="utf-8",
    )
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process = subprocess.Popen(
        [
            str(powershell), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass", "-File", str(helper),
            "-WaitPid", str(os.getpid()), "-Setup", str(setup), "-Expected", expected_sha256,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
        close_fds=True,
    )
    return {
        "scheduled": True,
        "helper_pid": process.pid,
        "setup_path": str(setup),
        "sha256": expected_sha256,
    }
