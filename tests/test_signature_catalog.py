"""Signed catalog checks use only ephemeral publishers and inert fixture bytes."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import sqlite3
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from antios import antivirus, cli, guard, scan_process, signature_catalog as catalog


@pytest.fixture
def publisher(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    store = tmp_path / "state" / "signatures.sqlite3"

    def package(version, name=None, content=b"inert fixture"):
        label = name or f"Fixture v{version}"
        body = {
            "schema": 1,
            "version": version,
            "published": "2026-11-10",
            "sha256": {hashlib.sha256(content).hexdigest(): {
                "label": label, "source": "https://example.org/report", "source_date": "2026-01-01",
            }},
        }
        data = json.dumps({"catalog": body, "signature": key.sign(catalog.signed_bytes(body)).hex()})
        path = tmp_path / f"catalog-{version}.antisig"
        path.write_text(data, encoding="utf-8")
        return path

    monkeypatch.setattr(catalog, "PUBLIC_KEY", key.public_key().public_bytes_raw())
    monkeypatch.setattr(catalog, "BUNDLED_PACKAGE", package(1).read_bytes())
    monkeypatch.setattr(catalog, "default_catalog_path", lambda: store)
    catalog.bundled_catalog.cache_clear()
    yield package, store
    catalog.bundled_catalog.cache_clear()


def test_bundled_publisher_catalog_has_provenance():
    body = json.loads(catalog.BUNDLED_PACKAGE)["catalog"]
    baseline = catalog.verify_catalog(catalog.BUNDLED_PACKAGE)
    assert baseline.rules
    assert len(baseline.rules) == len(body["sha256"])
    assert all(rule["source"].startswith("https://www.ncsc.gov.uk/") for rule in body["sha256"].values())
    assert set(antivirus.NCSC_SUPPLEMENT).isdisjoint(baseline.rules)


def test_application_supplement_is_exact_and_new_signed_catalog_supersedes_it(publisher):
    package, _ = publisher
    supplemental = set(antivirus.AKIRA_SUPPLEMENT)
    cisa_2025 = set(antivirus.CISA_2025_SUPPLEMENT)
    ncsc = set(antivirus.NCSC_SUPPLEMENT)
    combined = supplemental | cisa_2025 | ncsc
    assert len(supplemental) == 13
    assert len(cisa_2025) == 21
    assert len(ncsc) == 42
    assert all(len(bytes.fromhex(digest)) == 32 and digest == digest.lower() for digest in combined)
    assert len(combined) == len(supplemental) + len(cisa_2025) + len(ncsc)

    rules, metadata = antivirus.load_managed_signatures()
    assert combined <= rules.keys()
    assert metadata["signature_bundled_supplement_entries"] == 76
    assert metadata["signature_cisa_2025_entries"] == 21
    assert metadata["signature_ncsc_supplement_entries"] == 42
    assert rules["b1b1cf33b8d3da35293d6b74c378f0cd9452a4351e26d07c896c4d9a8257ef89"].endswith(
        "(CISA AR25-261A)"
    )
    # CISA campaign reports also list legitimate tooling. The published PsExec
    # hash must not enter the bundled confirmed-threat rules.
    assert "078163d5c16f64caa5a14784323fd51451b8c831c73396b967b4e35e6879937b" not in rules
    # The NCSC also lists segment-only hashes for Cyclops Blink, which do
    # not describe complete artifacts and do not belong in this catalog.
    assert "50df5734dd0c6c5983c21278f119527f9fdf6ef1d7e808a29754ebc5253e9a86" not in rules

    catalog.install_catalog(package(4))
    rules, metadata = antivirus.load_managed_signatures()
    assert combined.isdisjoint(rules)
    assert metadata["signature_bundled_supplement_entries"] == 0
    assert metadata["signature_cisa_2025_entries"] == 0
    assert metadata["signature_ncsc_supplement_entries"] == 0


def test_bad_signature_and_downgrade_preserve_active_catalog(publisher):
    package, store = publisher
    newer = package(3)
    catalog.install_catalog(newer)
    assert catalog.install_catalog(newer).version == 3
    before = store.read_bytes()
    with pytest.raises(ValueError, match="newer"):
        catalog.install_catalog(package(2))

    bad = package(4)
    bad.write_text(bad.read_text().replace("Fixture v4", "Untrusted label"))
    with pytest.raises(ValueError, match="authentication failed"):
        catalog.install_catalog(bad)
    assert store.read_bytes() == before
    assert catalog.load_active_catalog().version == 3


def test_preflight_blocks_activation_without_exempting_live_scans(publisher, tmp_path, capsys):
    package, store = publisher
    sample = tmp_path / "known-good.txt"
    sample.write_bytes(b"known-good local test file")
    conflicting = package(3, "Regression fixture", sample.read_bytes())
    assert catalog.catalog_preflight(conflicting)["status"] == "no-baseline"
    assert not store.exists()

    catalog.install_catalog(package(2))
    digest = catalog.trust_file(sample)
    assert catalog.trust_file(sample) == digest
    assert cli.main(["signatures", "preflight", str(conflicting), "--json"]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "blocked"
    assert report["trusted_hashes_checked"] == 1
    assert report["conflicts"] == [{"sha256": digest, "label": "Regression fixture"}]
    assert str(sample) not in store.read_bytes().decode("utf-8", errors="ignore")
    with pytest.raises(ValueError, match="trusted-file"):
        catalog.install_catalog(conflicting)
    assert catalog.load_active_catalog().version == 2

    assert catalog.untrust_hash(digest)
    assert not catalog.untrust_hash(digest)
    assert catalog.install_catalog(conflicting).version == 3
    catalog.trust_file(sample)
    assert antivirus.scan_files(sample)["verdict"] == "threats-found"


def test_trusted_baseline_before_first_update_preserves_bundled_status(publisher, tmp_path):
    package, _ = publisher
    sample = tmp_path / "clean-file"
    sample.write_bytes(b"another inert file")
    catalog.trust_file(sample)
    assert catalog.load_active_catalog().metadata()["signature_catalog_status"] == "bundled"
    assert catalog.catalog_preflight(package(2))["status"] == "passed"
    assert catalog.install_catalog(package(2)).version == 2


def test_lookup_trusted_hashes_reads_exact_local_baseline_without_writes(publisher, tmp_path):
    _, store = publisher
    target = tmp_path / "trusted.txt"
    target.write_text("ordinary known file", encoding="utf-8")
    assert catalog.lookup_trusted_hashes(["0" * 64]) == set()
    assert not store.parent.exists()
    digest = catalog.trust_file(target)
    before = store.read_bytes()
    assert catalog.lookup_trusted_hashes([digest, "0" * 64, digest]) == {digest}
    assert store.read_bytes() == before


def test_catalog_replay_uses_verified_whole_file_history_without_touching_originals(
    publisher, tmp_path, capsys,
):
    package, store = publisher
    root = tmp_path / "watched"
    root.mkdir()
    match = b"harmless future match"
    for name in ("one", "two"):
        (root / name).write_bytes(match)
    (root / "three").write_bytes(b"ordinary benign content")
    candidate = package(2, "Fixture after a catalog update", match)
    report = antivirus.scan_files(root, include_hash_history=True)
    assert report["verdict"] == "no-threats-found"
    assert not report["findings"]
    history = tmp_path / "report.json"
    history.write_text(json.dumps(report), encoding="utf-8")
    for path in root.iterdir():
        path.unlink()
    root.rmdir()

    replayed = catalog.replay_catalog(candidate, history)
    assert replayed["status"] == "matches"
    assert replayed["hash_source"] == "scan-hash-history"
    assert replayed["receipt_sha256"] == report["proof_receipt"]["sha256"]
    assert replayed["package_sha256"] == hashlib.sha256(candidate.read_bytes()).hexdigest()
    assert replayed["scope"] == "whole-file-sha256"
    assert replayed["files_scanned"] == replayed["files_with_hash"] == 3
    assert replayed["files_without_hash"] == 0
    assert replayed["archive_members"] == "not-replayed"
    assert replayed["matches"] == [{
        "sha256": hashlib.sha256(match).hexdigest(),
        "label": "Fixture after a catalog update",
        "files": 2,
    }]
    assert not store.parent.exists()
    assert cli.main(["signatures", "replay", str(candidate), str(history), "--json"]) == 1
    assert json.loads(capsys.readouterr().out) == replayed

    report["file_hash_history"]["entries"][0] = "a" * 64
    history.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError, match="proof receipt"):
        catalog.replay_catalog(candidate, history)


def test_catalog_replay_v1_uses_enclosing_hash_and_ignores_unbound_history(publisher, tmp_path):
    package, _ = publisher
    target = tmp_path / "scan"
    target.mkdir()
    match = b"inert fixture"
    whole_archive = target / "record.zip"
    with zipfile.ZipFile(whole_archive, "w") as archive:
        archive.writestr("inner.txt", match)
    (target / "ordinary.txt").write_bytes(b"ordinary content")
    report = antivirus.scan_files(target)
    assert report["verdict"] == "threats-found"
    assert report["findings"][0]["sha256"] == hashlib.sha256(whole_archive.read_bytes()).hexdigest()
    candidate = package(2, "Member-only exact signature", match)
    report["file_hash_history"] = {
        "scope": "whole-file-sha256", "entries": [hashlib.sha256(match).hexdigest()], "omitted": 1,
    }
    history = tmp_path / "report.json"
    history.write_text(json.dumps(report), encoding="utf-8")

    result = catalog.replay_catalog(candidate, history)
    assert result["status"] == "no-matches"
    assert result["hash_source"] == "findings-only"
    assert result["files_with_hash"] == result["files_without_hash"] == 1
    assert result["archive_members"] == "not-replayed"
    candidate = package(3, "Archive container exact signature", whole_archive.read_bytes())
    assert catalog.replay_catalog(candidate, history)["status"] == "matches"


def test_catalog_replay_reports_no_hashes_and_requires_package_authentication(
    publisher, tmp_path, capsys,
):
    package, _ = publisher
    source = tmp_path / "clean.txt"
    source.write_bytes(b"ordinary clean file")
    prior = tmp_path / "report.json"
    prior.write_text(json.dumps(antivirus.scan_files(source)), encoding="utf-8")
    candidate = package(2)
    result = catalog.replay_catalog(candidate, prior)
    assert result["status"] == "no-hashes"
    assert result["files_with_hash"] == 0
    assert result["files_without_hash"] == 1
    assert cli.main(["signatures", "replay", str(candidate), str(prior), "--json"]) == 3
    assert json.loads(capsys.readouterr().out) == result
    candidate.write_text(candidate.read_text().replace("Fixture v2", "Untrusted label"))
    with pytest.raises(ValueError, match="authentication failed"):
        catalog.replay_catalog(candidate, prior)


def test_bad_update_creates_no_user_store(publisher):
    _, store = publisher
    bad = store.parent.parent / "bad.antisig"
    bad.write_text('{"catalog":{},"catalog":{},"signature":""}')
    with pytest.raises(ValueError):
        catalog.install_catalog(bad)
    assert not store.parent.exists()
    assert catalog.load_active_catalog().version == 1


def test_fallback_to_previous_verified_catalog_and_recovery(publisher):
    package, store = publisher
    catalog.install_catalog(package(2))
    catalog.install_catalog(package(3))
    with closing(sqlite3.connect(store)) as db, db:
        db.execute("UPDATE catalogs SET package=? WHERE version=3", (b"corrupt",))
    fallback = catalog.load_active_catalog()
    assert fallback.version == 2
    assert fallback.metadata()["signature_catalog_status"] == "fallback"
    assert fallback.warning
    assert guard.probe_engine()["signature_catalog_status"] == "fallback"

    catalog.install_catalog(package(4))
    assert catalog.load_active_catalog().version == 4
    assert not catalog.load_active_catalog().warning
    with closing(sqlite3.connect(store)) as db:
        assert db.execute("SELECT version FROM catalogs ORDER BY version").fetchall() == [(2,), (4,)]


def test_unreadable_user_store_falls_back_to_bundled(publisher):
    _, store = publisher
    store.parent.mkdir()
    store.write_bytes(b"not a database")
    result = catalog.load_active_catalog()
    assert result.version == 1
    assert result.metadata()["signature_catalog_status"] == "fallback"


def test_failed_transaction_does_not_publish_candidate(publisher):
    package, store = publisher
    catalog.install_catalog(package(2))
    catalog.install_catalog(package(3))
    with closing(sqlite3.connect(store)) as db, db:
        db.execute("""CREATE TRIGGER block_prune BEFORE DELETE ON catalogs
                      BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END""")
    with pytest.raises(OSError, match="could not be committed"):
        catalog.install_catalog(package(4))
    assert catalog.load_active_catalog().version == 3
    with closing(sqlite3.connect(store)) as db:
        assert db.execute("SELECT version FROM catalogs ORDER BY version").fetchall() == [(2,), (3,)]


def test_concurrent_writers_keep_newest_version(publisher):
    package, _ = publisher
    candidates = (package(2), package(3))

    def install(path):
        try:
            return catalog.install_catalog(path).version
        except ValueError as exc:
            assert "newer" in str(exc)
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        installed = list(executor.map(install, candidates))
    assert 3 in installed
    assert catalog.load_active_catalog().version == 3


def test_cli_guard_and_scan_worker_share_catalog(publisher, tmp_path, capsys):
    package, _ = publisher
    target = tmp_path / "sample"
    target.write_bytes(b"another inert fixture")
    bundle = package(2, "Fixture from installed catalog", target.read_bytes())
    assert cli.main(["--config", str(tmp_path / "none.toml"), "signatures", "install",
                     str(bundle), "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["signature_catalog_version"] == guard.probe_engine()["signature_catalog_version"] == 2

    report = antivirus.scan_files(target)
    assert report["engine"]["signature_catalog_version"] == 2
    assert report["findings"][0]["name"] == "Fixture from installed catalog"
    request = tmp_path / "request.json"
    events = tmp_path / "events.jsonl"
    request.write_text(json.dumps({"path": str(target), "use_cache": False}))
    assert scan_process.worker_main(str(request), str(events)) == 0
    reports = [value for kind, value in map(json.loads, events.read_text().splitlines())
               if kind == "checkpoint"]
    assert reports[-1]["engine"]["signature_catalog_version"] == 2
    assert any(finding["name"] == "Fixture from installed catalog"
               for event in reports for finding in event["findings"])
