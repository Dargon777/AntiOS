"""Protocol tests use only inert bytes and a private loopback listener."""
from contextlib import contextmanager
from datetime import datetime, timedelta
import socket
import struct
import threading
import time

import pytest

from antios.antivirus import scan_files
from antios.clamav import ClamAVScanner


def version(days=0):
    date = datetime.now() - timedelta(days=days)
    months = 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()
    return f'ClamAV 1.4.3/28000/Mon {months[date.month-1]} {date.day:2} {date:%H:%M:%S %Y}'


def receive(connection, count):
    data = bytearray()
    while len(data) < count:
        block = connection.recv(count - len(data))
        if not block:
            raise EOFError('client disconnected')
        data.extend(block)
    return bytes(data)


@contextmanager
def daemon(reply=b'stream: OK\0', *, banner=None, delay=0):
    received, failures = [], []
    stopped = threading.Event()
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    listener.settimeout(0.1)
    port = listener.getsockname()[1]

    def serve():
        try:
            while not stopped.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(2)
                    command = b''
                    while not command.endswith(b'\0'):
                        command += receive(connection, 1)
                    if command == b'zVERSION\0':
                        connection.sendall((banner or version()).encode() + b'\0')
                    else:
                        assert command == b'zINSTREAM\0'
                        data = bytearray()
                        while True:
                            size = struct.unpack('!I', receive(connection, 4))[0]
                            if not size:
                                break
                            assert size <= 65536
                            data.extend(receive(connection, size))
                        received.append(bytes(data))
                        if delay:
                            stopped.wait(delay)
                        try:
                            # Fragmented responses exercise buffering as on TCP.
                            connection.sendall(reply[:5])
                            connection.sendall(reply[5:])
                        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                            pass
        except Exception as exc:
            failures.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, received
    finally:
        stopped.set()
        thread.join(4)
        listener.close()
        assert not thread.is_alive()
        assert not failures


@pytest.mark.parametrize('payload', [b'', b'inert bytes\x00with nul', b'x' * 150000],
                         ids=['empty', 'embedded-nul', 'multi-chunk'])
def test_streams_exact_snapshot_and_never_sends_filename(payload):
    with daemon() as (port, received):
        engine = ClamAVScanner(port=port)
        assert engine.scan(payload, 'unsafe\nSHUTDOWN\x00filename').kind is None
        assert received == [payload]
        assert engine.metadata['database_freshness'] == 'current'
        engine.close()


@pytest.mark.parametrize('reply,kind', [
    (b'stream: AntiOS.Inert.Test FOUND\0', 'threat'),
    (b'stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0', 'review'),
    (b'stream: Heuristics.Encrypted.Zip FOUND\0', 'review'),
    (b'stream: PUA.Win.Tool FOUND\0', 'review'),
])
def test_findings_and_archive_limit_reviews(tmp_path, reply, kind):
    target = tmp_path / 'fixture'
    target.write_bytes(b'harmless')
    with daemon(reply) as (port, _):
        result = scan_files(target, engine='clamav', provider_factory=lambda: ClamAVScanner(port=port))
    assert result['findings'][0]['kind'] == kind
    assert result['findings'][0]['engine'] == 'ClamAV'
    assert result['summary']['provider_scanned'] == 1
    if kind == 'review':
        assert result['coverage'] == 'limited'
    assert target.read_bytes() == b'harmless'


@pytest.mark.parametrize('reply', [b'', b'stream: OK', b'OK\0', b'stream: OK\0extra',
    b'stream: \xff FOUND\0', b'x' * 4096, b'INSTREAM size limit exceeded. ERROR\0'])
def test_broken_protocol_never_becomes_clean(tmp_path, reply):
    target = tmp_path / 'fixture'
    target.write_bytes(b'harmless')
    with daemon(reply) as (port, _):
        result = scan_files(target, engine='clamav', provider_factory=lambda: ClamAVScanner(port=port))
    assert result['verdict'] == 'incomplete'
    assert result['summary']['provider_scanned'] == 0
    assert result['summary']['errors'] == 1


def test_total_deadline_and_failure_circuit_breaker(tmp_path):
    for number in range(4):
        (tmp_path / str(number)).write_bytes(b'harmless')
    with daemon(delay=2) as (port, received):
        started = time.monotonic()
        result = scan_files(tmp_path, engine='clamav',
                            provider_factory=lambda: ClamAVScanner(port=port, timeout=0.5))
        assert time.monotonic() - started < 1.5
        assert len(received) == 1
    assert result['summary']['files_scanned'] == 4
    assert result['summary']['errors'] == 1
    assert result['engine']['failed_during_scan']
    assert result['verdict'] == 'incomplete'


@pytest.mark.parametrize('banner,freshness', [(version(9), 'stale'), (version(-3), 'future-date'),
    ('ClamAV 1.4.3', 'unknown'), ('ClamAV 1.4.3/12/Mon Xxx 30 00:00:00 2026', 'unknown')])
def test_unverified_database_cannot_produce_clean_verdict(tmp_path, banner, freshness):
    target = tmp_path / 'fixture'
    target.write_bytes(b'harmless')
    with daemon(banner=banner) as (port, _):
        result = scan_files(target, engine='clamav', provider_factory=lambda: ClamAVScanner(port=port))
    assert result['engine']['database_freshness'] == freshness
    assert result['verdict'] == 'incomplete'


def test_valid_database_and_scan_produce_explicit_independent_coverage(tmp_path, monkeypatch):
    from antios import clamav
    monkeypatch.setattr(clamav, '_is_windows', lambda: False)
    target = tmp_path / 'fixture'
    target.write_bytes(b'harmless')
    with daemon() as (port, _):
        result = scan_files(target, engine='clamav', provider_factory=lambda: ClamAVScanner(port=port))
    assert result['coverage'] == 'clamav-and-signatures'
    assert result['verdict'] == 'no-threats-found'


@pytest.mark.parametrize('options', [{'port': 0}, {'port': True}, {'port': 65536},
    {'timeout': 0}, {'timeout': float('nan')}, {'timeout': 301}])
def test_invalid_settings_fail_before_connect(options):
    with pytest.raises(ValueError):
        ClamAVScanner(**options)


def test_hash_detection_does_not_hide_archive_coverage_limit(tmp_path):
    import hashlib
    import json
    target = tmp_path / 'fixture'
    target.write_bytes(b'inert known signature')
    signatures = tmp_path / 'signatures.json'
    signatures.write_text(json.dumps({'schema': 1, 'sha256': {
        hashlib.sha256(target.read_bytes()).hexdigest(): 'Local confirmed detection'}}))
    with daemon(b'stream: Heuristics.Limits.Exceeded FOUND\0') as (port, _):
        result = scan_files(target, engine='clamav', signature_path=signatures,
                            provider_factory=lambda: ClamAVScanner(port=port))
    assert result['summary']['threats'] == 1
    assert result['coverage'] == 'limited'
    assert result['engine']['limited_results'] == 1


def test_cli_selects_independent_engine_and_reports_it(tmp_path, monkeypatch, capsys):
    import json
    from antios import antivirus, cli, clamav
    monkeypatch.setattr(clamav, '_is_windows', lambda: False)
    target = tmp_path / 'fixture'
    target.write_bytes(b'harmless')
    with daemon() as (port, _):
        monkeypatch.setattr(antivirus, 'ClamAVScanner', lambda: ClamAVScanner(port=port))
        assert cli.main(['--config', str(tmp_path / 'none.toml'), 'virus-scan',
                         str(target), '--engine', 'clamav', '--json']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['engine']['provider'] == 'ClamAV'
    assert result['summary']['provider_scanned'] == 1



def test_windows_resident_peer_binding_is_explicit_and_verified(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from antios import clamav

    target = tmp_path / 'fixture'
    target.write_bytes(b'harmless')
    with daemon() as (port, _):
        monkeypatch.setattr(clamav, '_is_windows', lambda: True)
        monkeypatch.setattr(clamav, 'configured_service_name',
                            lambda explicit=None: explicit or 'AntiOSClamD')
        monkeypatch.setattr(clamav, 'query_service_process',
                            lambda name: SimpleNamespace(pid=4242))
        monkeypatch.setattr(clamav, 'verify_connected_socket',
                            lambda connection, pid: pid == 4242)
        result = scan_files(
            target,
            engine='clamav',
            provider_factory=lambda: clamav.ClamAVScanner(
                port=port, service_name='AntiOSClamD', require_verified_peer=True),
        )
    assert result['engine']['peer_verification_required'] is True
    assert result['engine']['peer_verified'] is True
    assert result['engine']['peer_identity'] == 'windows-service:AntiOSClamD'
    assert result['verdict'] == 'no-threats-found'


def test_unverified_windows_loopback_never_produces_clean_verdict(tmp_path, monkeypatch):
    from antios import clamav

    target = tmp_path / 'fixture'
    target.write_bytes(b'harmless')
    with daemon() as (port, _):
        monkeypatch.setattr(clamav, '_is_windows', lambda: True)
        monkeypatch.setattr(clamav, 'configured_service_name', lambda explicit=None: None)
        result = scan_files(
            target,
            engine='clamav',
            provider_factory=lambda: clamav.ClamAVScanner(port=port),
        )
    assert result['engine']['peer_verification_required'] is True
    assert result['engine']['peer_verified'] is False
    assert result['coverage'] == 'limited'
    assert result['verdict'] == 'incomplete'


def test_required_windows_peer_without_service_fails_before_connect(monkeypatch):
    from antios import clamav

    monkeypatch.setattr(clamav, '_is_windows', lambda: True)
    monkeypatch.setattr(clamav, 'configured_service_name', lambda explicit=None: None)
    with pytest.raises(OSError, match='SCM service'):
        clamav.ClamAVScanner(require_verified_peer=True)
