import hashlib
import json
import os
from pathlib import Path

import pytest

from antios import antivirus


class Provider:
    def __init__(self, value=0, failure=False):
        self.value, self.failure, self.closed = value, failure, False

    def scan(self, content, name):
        if self.failure:
            raise OSError("provider unavailable")
        return self.value

    def close(self):
        self.closed = True


def unavailable():
    raise OSError("no AMSI provider")


def test_native_provider_no_detection_and_scan_is_read_only(tmp_path):
    target = tmp_path / "safe.txt"
    target.write_bytes(b"harmless test content")
    before = target.read_bytes(), target.stat().st_mtime_ns
    provider = Provider()
    result = antivirus.scan_files(target, provider_factory=lambda: provider)
    assert result["verdict"] == "no-threats-found"
    assert result["coverage"] == "provider-and-signatures"
    assert provider.closed
    assert (target.read_bytes(), target.stat().st_mtime_ns) == before


def test_missing_provider_never_claims_a_clean_scan(tmp_path):
    (tmp_path / "a").write_text("ordinary file")
    result = antivirus.scan_files(tmp_path, provider_factory=unavailable)
    assert result["verdict"] == "incomplete"
    assert result["coverage"] == "limited"
    assert result["summary"]["files_scanned"] == 1
    assert result["engine"]["detail"] == "no AMSI provider"


@pytest.mark.parametrize("value,kind,verdict", [
    (0, None, "no-threats-found"), (1, None, "no-threats-found"),
    (32767, None, "no-threats-found"), (0x4000, "review", "review"),
    (0x4FFF, "review", "review"), (32768, "threat", "threats-found"),
])
def test_provider_policy_blocks_are_not_classified_as_malware(tmp_path, value, kind, verdict):
    target = tmp_path / "fixture.txt"
    target.write_bytes(b"benign mocked provider fixture")
    result = antivirus.scan_files(target, provider_factory=lambda: Provider(value))
    assert result["verdict"] == verdict
    assert [f["kind"] for f in result["findings"]] == ([] if kind is None else [kind])


def test_local_hash_detection_and_finding_digest(tmp_path):
    content = b"benign local signature test"
    target = tmp_path / "sample"
    target.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({"schema": 1, "sha256": {digest.upper(): "Test signature"}}))
    result = antivirus.scan_files(target, signature_path=database, provider_factory=unavailable)
    finding = result["findings"][0]
    assert finding["sha256"] == digest
    assert finding["engine"] == "SHA-256"
    assert finding["name"] == "Test signature"
    assert result["verdict"] == "threats-found"


def test_eicar_whitespace_matching_uses_hash_without_writing_eicar(tmp_path, monkeypatch):
    # Use inert bytes: hosted Windows antivirus must never be disabled for tests.
    sample = b"x" * 68
    monkeypatch.setattr(antivirus, "EICAR_SHA256", hashlib.sha256(sample).hexdigest())
    target = tmp_path / "inert-eicar-surrogate"
    target.write_bytes(sample + b"\r\n \t")
    result = antivirus.scan_files(target, provider_factory=unavailable)
    assert result["summary"]["threats"] == 1
    target.write_bytes(sample + b"x")
    assert not antivirus.scan_files(target, provider_factory=unavailable)["findings"]


@pytest.mark.parametrize("data", [[], {"schema": 2}, {"schema": 1, "sha256": []},
    {"schema": 1, "sha256": {"not-a-hash": "name"}},
    {"schema": 1, "sha256": {"a" * 64: ""}},
    {"schema": 1, "sha256": {"a" * 64: 123}}])
def test_signature_input_is_validated(tmp_path, data):
    database = tmp_path / "bad.json"
    database.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        antivirus.load_signatures(database)


def test_provider_failure_is_reported_and_closed(tmp_path):
    target = tmp_path / "file"
    target.write_bytes(b"fixture")
    provider = Provider(failure=True)
    result = antivirus.scan_files(target, provider_factory=lambda: provider)
    assert result["verdict"] == "incomplete"
    assert result["summary"]["errors"] == 1
    assert result["summary"]["provider_scanned"] == 0
    assert result["issues"][0]["reason"] == "provider unavailable"
    assert provider.closed


def test_size_and_file_count_limits_do_not_hide_incomplete_coverage(tmp_path):
    (tmp_path / "small").write_bytes(b"ok")
    (tmp_path / "large").write_bytes(b"large file")
    result = antivirus.scan_files(tmp_path, max_bytes=2, provider_factory=Provider)
    assert result["summary"]["skipped"] == 1
    assert result["verdict"] == "incomplete"
    result = antivirus.scan_files(tmp_path, max_files=1, provider_factory=Provider)
    assert result["summary"]["limit_reached"]
    assert result["summary"]["files_scanned"] == 1
    assert result["verdict"] == "incomplete"


def test_directory_only_traversal_is_bounded(tmp_path):
    folder = tmp_path
    for _ in range(10):
        folder = folder / "child"
        folder.mkdir()
    result = antivirus.scan_files(tmp_path, max_files=2, provider_factory=Provider)
    assert result["summary"]["entries_seen"] <= 4
    assert result["summary"]["limit_reached"]
    assert result["verdict"] == "incomplete"


def test_cancellation_closes_provider_and_does_not_claim_clean(tmp_path):
    provider = Provider()
    result = antivirus.scan_files(tmp_path, provider_factory=lambda: provider, cancelled=lambda: True)
    assert result["summary"]["cancelled"]
    assert result["verdict"] == "incomplete"
    assert provider.closed


def test_quarantine_tree_is_excluded(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "ciphertext.aq").write_bytes(b"opaque")
    (tmp_path / "normal").write_bytes(b"safe")
    result = antivirus.scan_files(tmp_path, provider_factory=Provider, excluded_paths=(vault,))
    assert result["summary"]["files_scanned"] == 1
    assert result["summary"]["skipped"] == 1
    assert result["issues"][0]["reason"] == "quarantine-excluded"


def test_symlink_root_and_child_are_not_followed(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"benign")
    link = tmp_path / "link"
    try:
        link.symlink_to(original)
    except OSError:
        pytest.skip("Symlink privilege unavailable")
    result = antivirus.scan_files(tmp_path, provider_factory=Provider)
    assert result["summary"]["skipped"] == 1
    with pytest.raises(ValueError, match="links"):
        antivirus.scan_files(link, provider_factory=Provider)


@pytest.mark.skipif(os.name == "nt", reason="POSIX named pipe")
def test_special_files_do_not_block_scan(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    result = antivirus.scan_files(tmp_path, provider_factory=Provider)
    assert result["summary"]["skipped"] == 1
    assert result["summary"]["files_scanned"] == 0


@pytest.mark.parametrize("kwargs", [{"max_bytes": 0}, {"max_bytes": 257 * 1024 * 1024},
                                  {"max_files": 0}, {"max_files": 1_000_001}])
def test_invalid_limits_rejected_before_scanning(tmp_path, kwargs):
    with pytest.raises(ValueError):
        antivirus.scan_files(tmp_path, **kwargs)


def test_cli_scan_exit_codes_and_structured_output(tmp_path, monkeypatch, capsys):
    from antios import cli
    target = tmp_path / "safe"
    target.write_text("benign")
    def fake_scan(path, **options):
        return antivirus.scan_files(path, **options, provider_factory=unavailable)
    monkeypatch.setattr(cli, "scan_files", fake_scan)
    assert cli.main(["--config", str(tmp_path / "none.toml"), "virus-scan", str(target), "--json"]) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["kind"] == "antivirus-scan"
    monkeypatch.setattr(cli, "scan_files", lambda path, **options:
        antivirus.scan_files(path, **options, provider_factory=lambda: Provider(32768)))
    assert cli.main(["--config", str(tmp_path / "none.toml"), "virus-scan", str(target)]) == 1
    assert target.exists()


def test_unreadable_directory_entry_does_not_hide_its_siblings(tmp_path, monkeypatch):
    good = tmp_path / 'good'
    good.write_bytes(b'harmless')
    class Entry:
        def __init__(self, path, broken=False):
            self.path, self.broken = str(path), broken
        def stat(self, **kwargs):
            if self.broken:
                raise PermissionError('unreadable entry')
            return Path(self.path).stat()
    class Entries:
        def __enter__(self):
            return iter([Entry(tmp_path / 'bad', True), Entry(good)])
        def __exit__(self, *args):
            pass
    monkeypatch.setattr(antivirus.os, 'scandir', lambda folder: Entries())
    result = antivirus.scan_files(tmp_path, provider_factory=Provider)
    assert result['summary']['errors'] == 1
    assert result['summary']['files_scanned'] == 1
    assert result['verdict'] == 'incomplete'


def test_unknown_engine_is_rejected(tmp_path):
    with pytest.raises(ValueError, match='engine'):
        antivirus.scan_files(tmp_path, engine='unknown')
