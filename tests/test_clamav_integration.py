"""Real ClamD, benign custom signature, compressed fixture. No malware/feed needed."""
import os
import shutil
import socket
import subprocess
import time
import zipfile

import pytest

from antios.antivirus import scan_files
from antios.clamav import ClamAVScanner


@pytest.fixture
def real_clamd(tmp_path):
    executable = os.environ.get('ANTIOS_TEST_CLAMD') or shutil.which('clamd')
    if not executable:
        if os.environ.get('ANTIOS_REQUIRE_CLAMD'):
            pytest.fail('Real ClamD is required by this job')
        pytest.skip('ClamD not installed; separate CI integration job requires it')
    database = tmp_path / 'database'
    database.mkdir()
    marker = b'AntiOS inert integration fixture 865bd5ae'
    (database / 'inert.ndb').write_text(f'AntiOS.Inert.Test:0:*:{marker.hex()}\n')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    config = tmp_path / 'clamd.conf'
    config.write_text(f'DatabaseDirectory {database}\nTCPSocket {port}\nTCPAddr 127.0.0.1\n'
                      'Foreground yes\nScanArchive yes\nAlertExceedsMax yes\n'
                      'MaxScanSize 1M\nMaxFileSize 1M\nStreamMaxLength 2M\n'
                      'MaxRecursion 5\nMaxFiles 10\nMaxScanTime 5000\n')
    if os.environ.get('ANTIOS_TEST_CLAMD_CERTS'):
        with config.open('a') as stream:
            stream.write(f"CVDCertsDirectory {os.environ['ANTIOS_TEST_CLAMD_CERTS']}\n")
    log = tmp_path / 'clamd.log'
    with log.open('w') as stream:
        process = subprocess.Popen([str(executable), '--config-file', str(config)],
                                   stdout=stream, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 20
            while True:
                try:
                    ClamAVScanner(port=port, timeout=0.5)
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        pytest.fail(log.read_text())
                    time.sleep(0.05)
            yield port, marker
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def test_real_engine_detects_content_inside_zip_and_reports_limits(tmp_path, real_clamd):
    port, marker = real_clamd
    def scan(path):
        return scan_files(path, engine='clamav', provider_factory=lambda: ClamAVScanner(port=port))

    plain = tmp_path / 'plain.txt'
    plain.write_bytes(marker)
    result = scan(plain)
    assert result['summary']['threats'] == 1
    assert result['findings'][0]['engine'] == 'ClamAV'
    assert 'AntiOS.Inert.Test' in result['findings'][0]['name']
    archive = tmp_path / 'fixture.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('innocent.txt', marker)
    original = archive.read_bytes()
    assert scan(archive)['summary']['threats'] == 1
    assert archive.read_bytes() == original
    safe = tmp_path / 'safe.txt'
    safe.write_bytes(b'Ordinary unrelated content')
    # No official daily database: content was scanned, freshness is unknown.
    benign = scan(safe)
    assert benign['summary']['provider_scanned'] == 1
    assert benign['verdict'] == 'incomplete'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('oversized.txt', b'A' * (2 * 1024 * 1024))
    limited = scan(archive)
    assert limited['summary']['reviews'] == 1
    assert limited['summary']['threats'] == 0
    assert limited['coverage'] == 'limited'


def test_resident_guard_detects_new_archive_with_real_clamd(tmp_path, real_clamd):
    import threading
    from antios.guard import Guard, GuardPolicy
    from antios.guard_notifications import PollNotifications
    port, marker = real_clamd
    root = tmp_path / 'watched'
    root.mkdir()
    def probe():
        engine = ClamAVScanner(port=port)
        return dict(engine.metadata, available=True)
    def scan(path, **options):
        return scan_files(path, engine='clamav', provider_factory=lambda: ClamAVScanner(port=port),
                          cancelled=options['cancelled'])
    guard = Guard(GuardPolicy((root,), interval=0.1, settle=0.05), tmp_path / 'state',
                  scanner=scan, probe=probe, watcher_factory=PollNotifications)
    stop, failures = threading.Event(), []
    def run():
        try:
            guard.run(stop)
        except Exception as exc:
            failures.append(exc)
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        archive = root / 'new.zip'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr('inert.txt', marker)
        deadline = time.monotonic() + 5
        while guard.status['detections'] == 0 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert guard.status['detections'] == 1
        assert archive.exists()
        assert guard.status['engine']['database_freshness'] == 'unknown'
    finally:
        stop.set()
        thread.join(3)
    assert not thread.is_alive()
    assert not failures
