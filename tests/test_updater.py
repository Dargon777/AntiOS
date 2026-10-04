import hashlib

import pytest

from antios import updater


def test_latest_alpha_selects_highest_non_draft(monkeypatch):
    monkeypatch.setattr(updater, "_request_json", lambda _url: [
        {"tag_name": "v2.0.0-alpha.14", "draft": False, "assets": []},
        {"tag_name": "v2.0.0-alpha.99", "draft": True, "assets": []},
        {
            "tag_name": "v2.0.0-alpha.19",
            "draft": False,
            "published_at": "2026-10-04T00:00:00Z",
            "html_url": "https://example.invalid/release",
            "assets": [
                {"name": "AntiOS-Setup.exe", "browser_download_url": "https://github.com/Dargon777/AntiOS/releases/download/v2.0.0-alpha.19/AntiOS-Setup.exe", "size": 5, "digest": None},
            ],
        },
    ])
    result = updater.latest_alpha()
    assert result["latest_alpha"] == 19
    assert result["latest_version"] == "2.0.0a19"
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
        "Status": "Valid", "Subject": "CN=Test", "Thumbprint": "00"
    })
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
