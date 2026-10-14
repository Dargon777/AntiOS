import hashlib

import pytest

from antios import updater


TRUSTED_CERT = "A" * 40
OTHER_CERT = "B" * 40


def test_latest_alpha_selects_highest_non_draft(monkeypatch):
    monkeypatch.setattr(updater, "_request_json", lambda _url: [
        {"tag_name": "v2.0.0-alpha.14", "draft": False, "assets": []},
        {"tag_name": "v2.0.0-alpha.99", "draft": True, "assets": []},
        {
            "tag_name": "v2.0.0-alpha.28",
            "draft": False,
            "published_at": "2026-10-04T00:00:00Z",
            "html_url": "https://example.invalid/release",
            "assets": [
                {"name": "AntiOS-Setup.exe", "browser_download_url": "https://github.com/Dargon777/AntiOS/releases/download/v2.0.0-alpha.28/AntiOS-Setup.exe", "size": 5, "digest": None},
            ],
        },
    ])
    result = updater.latest_alpha()
    assert result["latest_alpha"] == 28
    assert result["latest_version"] == "2.0.0a28"
    assert result["update_available"] is True


def test_download_update_verifies_hash_and_signature(tmp_path, monkeypatch):
    setup_bytes = b"setup-fixture"
    digest = hashlib.sha256(setup_bytes).hexdigest()
    release = {
        "current_version": "2.0.0a15",
        "current_alpha": 15,
        "latest_alpha": 16,
        "latest_version": "2.0.0a16",
        "tag": "v2.0.0-alpha.16",
        "published_at": None,
        "html_url": None,
        "update_available": True,
        "assets": {
            "AntiOS-Setup.exe": {
                "url": "https://github.com/Dargon777/AntiOS/releases/download/v2.0.0-alpha.16/AntiOS-Setup.exe",
                "size": len(setup_bytes),
                "digest": f"sha256:{digest}",
            },
            "AntiOS-Setup.exe.sha256": {
                "url": "https://github.com/Dargon777/AntiOS/releases/download/v2.0.0-alpha.16/AntiOS-Setup.exe.sha256",
                "size": 90,
                "digest": None,
            },
        },
    }
    monkeypatch.setattr(updater, "latest_alpha", lambda: release)

    def fake_download(_url, destination, _limit):
        if destination.name.endswith(".sha256"):
            destination.write_bytes(f"{digest}  AntiOS-Setup.exe".encode("ascii"))
        else:
            destination.write_bytes(setup_bytes)

    monkeypatch.setattr(updater, "_download", fake_download)
    monkeypatch.setattr(updater, "_authenticode", lambda _path: {
        "Status": "Valid", "Subject": "CN=Test", "Thumbprint": TRUSTED_CERT
    })
    monkeypatch.setattr(updater, "_installed_signer_thumbprint", lambda: TRUSTED_CERT)
    result = updater.download_update(tmp_path, require_signature=True)
    assert result["downloaded"]
    assert result["sha256"] == digest
    assert result["install_ready"] is True


def test_download_update_refuses_unsigned_setup(tmp_path, monkeypatch):
    setup_bytes = b"setup-fixture"
    digest = hashlib.sha256(setup_bytes).hexdigest()
    monkeypatch.setattr(updater, "latest_alpha", lambda: {
        "current_version": "2.0.0a15",
        "current_alpha": 15,
        "latest_alpha": 16,
        "latest_version": "2.0.0a16",
        "tag": "v2.0.0-alpha.16",
        "published_at": None,
        "html_url": None,
        "update_available": True,
        "assets": {
            "AntiOS-Setup.exe": {
                "url": "https://github.com/Dargon777/AntiOS/releases/download/v2.0.0-alpha.16/AntiOS-Setup.exe",
                "size": len(setup_bytes),
                "digest": f"sha256:{digest}",
            },
            "AntiOS-Setup.exe.sha256": {
                "url": "https://github.com/Dargon777/AntiOS/releases/download/v2.0.0-alpha.16/AntiOS-Setup.exe.sha256",
                "size": 90,
                "digest": None,
            },
        },
    })

    def fake_download(_url, destination, _limit):
        destination.write_bytes(
            f"{digest}  AntiOS-Setup.exe".encode("ascii")
            if destination.name.endswith(".sha256") else setup_bytes
        )

    monkeypatch.setattr(updater, "_download", fake_download)
    monkeypatch.setattr(updater, "_authenticode", lambda _path: {"Status": "NotSigned"})
    with pytest.raises(RuntimeError, match="Authenticode"):
        updater.download_update(tmp_path, require_signature=True)
    assert not (tmp_path / "AntiOS-Setup.exe").exists()



def test_download_update_can_replace_cached_files(tmp_path, monkeypatch):
    setup_bytes = b"fresh-setup"
    digest = hashlib.sha256(setup_bytes).hexdigest()
    release = {
        "current_version": "2.0.0a21",
        "current_alpha": 21,
        "latest_alpha": 28,
        "latest_version": "2.0.0a28",
        "tag": "v2.0.0-alpha.28",
        "published_at": None,
        "html_url": None,
        "update_available": True,
        "assets": {
            "AntiOS-Setup.exe": {
                "url": "https://github.com/Dargon777/AntiOS/releases/download/v2.0.0-alpha.28/AntiOS-Setup.exe",
                "size": len(setup_bytes),
                "digest": f"sha256:{digest}",
            },
            "AntiOS-Setup.exe.sha256": {
                "url": "https://github.com/Dargon777/AntiOS/releases/download/v2.0.0-alpha.28/AntiOS-Setup.exe.sha256",
                "size": 90,
                "digest": None,
            },
        },
    }
    monkeypatch.setattr(updater, "latest_alpha", lambda: release)

    def fake_download(_url, destination, _limit):
        destination.write_bytes(
            f"{digest}  AntiOS-Setup.exe".encode("ascii")
            if destination.name.endswith(".sha256") else setup_bytes
        )

    monkeypatch.setattr(updater, "_download", fake_download)
    (tmp_path / "AntiOS-Setup.exe").write_bytes(b"old")
    (tmp_path / "AntiOS-Setup.exe.sha256").write_text("old", encoding="ascii")

    result = updater.download_update(
        tmp_path,
        require_signature=False,
        replace_existing=True,
    )
    assert result["downloaded"] is True
    assert (tmp_path / "AntiOS-Setup.exe").read_bytes() == setup_bytes



def test_update_handoff_uses_bounded_wait_and_verifies_before_install(tmp_path):
    from pathlib import Path

    setup = tmp_path / "AntiOS-Setup.exe"
    script = updater._update_handoff_script(setup, "a" * 64, 12345, TRUSTED_CERT)
    assert "$deadline=(Get-Date).AddSeconds(120)" in script
    assert "AntiOS did not exit; update cancelled." in script
    assert "Get-FileHash -InputStream $file -Algorithm SHA256" in script
    assert "[IO.FileShare]::Read" in script
    assert "Get-AuthenticodeSignature -LiteralPath $setup" in script
    assert "$thumb -cne $trustedThumbprint" in script
    assert "if($installer.ExitCode -ne 0)" in script
    assert "Start-Process -FilePath $setup" in script
    assert "install-antios-update.ps1" not in script
    quoted = updater._update_handoff_script(
        Path("C:/Temp/O'Brien/AntiOS-Setup.exe"), "b" * 64, 22, TRUSTED_CERT
    )
    assert "O''Brien" in quoted


def test_update_handoff_rejects_invalid_inputs(tmp_path):
    with pytest.raises(ValueError, match="digest"):
        updater._update_handoff_script(tmp_path / "AntiOS-Setup.exe", "bad", 123, TRUSTED_CERT)
    with pytest.raises(ValueError, match="parent"):
        updater._update_handoff_script(tmp_path / "AntiOS-Setup.exe", "a" * 64, 0, TRUSTED_CERT)
    with pytest.raises(ValueError, match="publisher thumbprint"):
        updater._update_handoff_script(tmp_path / "AntiOS-Setup.exe", "a" * 64, 1, "00")


def test_schedule_install_does_not_write_user_writable_ps1(tmp_path, monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace

    setup = tmp_path / "AntiOS-Setup.exe"
    setup.write_bytes(b"installer fixture")
    calls = []
    monkeypatch.setattr(updater, "os", SimpleNamespace(name="nt", getpid=lambda: 77))
    monkeypatch.setattr(updater, "system_executable", lambda _name: Path("powershell.exe"))
    monkeypatch.setattr(updater, "hidden_process_kwargs", lambda **_kw: {})
    monkeypatch.setattr(updater, "_installed_signer_thumbprint", lambda: TRUSTED_CERT)
    monkeypatch.setattr(updater, "_authenticode", lambda _p: {"Status": "Valid", "Thumbprint": TRUSTED_CERT})
    monkeypatch.setattr(
        updater.subprocess, "Popen",
        lambda args, **kw: calls.append((args, kw)) or SimpleNamespace(pid=1234),
    )
    expected = hashlib.sha256(setup.read_bytes()).hexdigest()
    result = updater.schedule_install(setup, expected)
    assert result["scheduled"] is True
    assert result["helper_pid"] == 1234
    assert calls[0][0][-2] == "-Command"
    assert "$waitPid=77" in calls[0][0][-1]
    assert not list(tmp_path.glob("*.ps1"))



def test_download_rejects_valid_signature_from_unrelated_publisher(tmp_path, monkeypatch):
    setup_bytes = b"signed-but-not-by-anti-os"
    digest = hashlib.sha256(setup_bytes).hexdigest()
    monkeypatch.setattr(updater, "latest_alpha", lambda: {
        "current_version": "2.0.0a27", "latest_version": "2.0.0a28",
        "update_available": True,
        "assets": {
            "AntiOS-Setup.exe": {"url": "unused", "digest": f"sha256:{digest}"},
            "AntiOS-Setup.exe.sha256": {"url": "unused"},
        },
    })
    def download(_url, path, _limit):
        path.write_bytes(
            f"{digest}  AntiOS-Setup.exe".encode("ascii")
            if path.suffix == ".sha256" else setup_bytes
        )
    monkeypatch.setattr(updater, "_download", download)
    monkeypatch.setattr(updater, "_authenticode", lambda _p: {
        "Status": "Valid", "Thumbprint": OTHER_CERT,
    })
    monkeypatch.setattr(updater, "_installed_signer_thumbprint", lambda: TRUSTED_CERT)
    with pytest.raises(RuntimeError, match="publisher identity"):
        updater.download_update(tmp_path, require_signature=True)
    assert not (tmp_path / "AntiOS-Setup.exe").exists()


def test_unsigned_installation_never_auto_installs_signed_update(tmp_path, monkeypatch):
    setup_bytes = b"signed-fixture"
    digest = hashlib.sha256(setup_bytes).hexdigest()
    monkeypatch.setattr(updater, "latest_alpha", lambda: {
        "current_version": "2.0.0a27", "latest_version": "2.0.0a28",
        "update_available": True,
        "assets": {
            "AntiOS-Setup.exe": {"url": "unused", "digest": f"sha256:{digest}"},
            "AntiOS-Setup.exe.sha256": {"url": "unused"},
        },
    })
    monkeypatch.setattr(
        updater, "_download",
        lambda _url, path, _limit: path.write_bytes(
            f"{digest}  AntiOS-Setup.exe".encode("ascii")
            if path.suffix == ".sha256" else setup_bytes
        ),
    )
    monkeypatch.setattr(updater, "_authenticode", lambda _p: {
        "Status": "Valid", "Thumbprint": TRUSTED_CERT,
    })
    monkeypatch.setattr(
        updater, "_installed_signer_thumbprint",
        lambda: (_ for _ in ()).throw(RuntimeError("Unsigned installed CLI")),
    )
    result = updater.download_update(tmp_path, require_signature=False)
    assert result["downloaded"]
    assert not result["install_ready"]
    assert not result["publisher_verified"]
    assert result["publisher_error"]


def test_installation_refuses_changed_digest_before_spawn(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from pathlib import Path
    setup = tmp_path / "AntiOS-Setup.exe"
    setup.write_bytes(b"tampered")
    monkeypatch.setattr(updater, "os", SimpleNamespace(name="nt", getpid=lambda: 1))
    monkeypatch.setattr(
        updater.subprocess, "Popen",
        lambda *_args, **_kwargs: pytest.fail("tampered update must not execute"),
    )
    with pytest.raises(RuntimeError, match="digest"):
        updater.schedule_install(setup, hashlib.sha256(b"expected").hexdigest())


def test_installation_refuses_other_publisher_before_spawn(tmp_path, monkeypatch):
    from types import SimpleNamespace
    setup = tmp_path / "AntiOS-Setup.exe"
    setup.write_bytes(b"installer fixture")
    monkeypatch.setattr(updater, "os", SimpleNamespace(name="nt", getpid=lambda: 1))
    monkeypatch.setattr(updater, "_installed_signer_thumbprint", lambda: TRUSTED_CERT)
    monkeypatch.setattr(updater, "_authenticode", lambda _p: {
        "Status": "Valid", "Thumbprint": OTHER_CERT,
    })
    monkeypatch.setattr(
        updater.subprocess, "Popen",
        lambda *_args, **_kwargs: pytest.fail("wrong publisher must not execute"),
    )
    with pytest.raises(RuntimeError, match="publisher certificate"):
        updater.schedule_install(setup, hashlib.sha256(setup.read_bytes()).hexdigest())


def test_certificate_identity_requires_valid_signature_and_full_thumbprint():
    assert updater._matches_installed_signer(
        {"Status": "Valid", "Thumbprint": TRUSTED_CERT.lower()},
        TRUSTED_CERT,
    )
    assert not updater._matches_installed_signer(
        {"Status": "Valid", "Thumbprint": OTHER_CERT},
        TRUSTED_CERT,
    )
    assert not updater._matches_installed_signer(
        {"Status": "NotSigned", "Thumbprint": TRUSTED_CERT},
        TRUSTED_CERT,
    )
    assert not updater._matches_installed_signer(
        {"Status": "Valid", "Thumbprint": "0"},
        TRUSTED_CERT,
    )
