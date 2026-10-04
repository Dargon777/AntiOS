"""Native EXE tests require Windows CI. No service/driver installation or real malware."""
import json
import os
from pathlib import Path
import subprocess
import time

import pytest
from test_native_engine import Daemon


@pytest.fixture
def executable():
    if os.name != 'nt':
        pytest.skip('Windows EXE runtime test')
    path = Path(os.environ.get('ANTIOS_NATIVE_EXE', 'build/native/windows/AntiOS-Service.exe')).resolve()
    if not path.is_file():
        if os.environ.get('ANTIOS_REQUIRE_NATIVE_WINDOWS'):
            pytest.fail('Native EXE required in this job')
        pytest.skip('Native EXE not built')
    return path


def invoke(executable, *args):
    result = subprocess.run([str(executable), *map(str, args)], capture_output=True, text=True, timeout=10)
    return result.returncode, json.loads(result.stdout)


def test_uninstalled_diagnostics_are_not_protection(executable):
    code, status = invoke(executable, '--status')
    assert code == 2 and status['installed'] is False
    code, status = invoke(executable, '--driver-status')
    assert code == 2 and status['driver_available'] is False


@pytest.mark.parametrize('reply,version,expected', [
    (b'stream: OK\0', None, (0, 2)),
    (b'stream: Inert.Test FOUND\0', None, (1, 1)),
    (b'stream: Heuristics.Limits.Exceeded FOUND\0', None, (2, 3)),
    (b'stream: OK\0', b'ClamAV 1.5.3\0', (2, 0)),
    (b'stream: OK\0junk', None, (2, 0)),
])
def test_windows_native_client(executable, tmp_path, reply, version, expected):
    path = tmp_path / 'harmless fixture.txt'
    content = bytes(range(256)) * 400
    path.write_bytes(content)
    with Daemon(port=3310, version=version, verdict=reply) as daemon:
        code, outcome = invoke(executable, '--scan-file', path)
        assert (code, outcome['result']) == expected
        assert daemon.data == content
    assert path.read_bytes() == content


def test_windows_native_timeout(executable, tmp_path):
    path = tmp_path / 'harmless.txt'
    path.write_text('Safe text')
    started = time.monotonic()
    with Daemon(port=3310, stall=True):
        code, outcome = invoke(executable, '--scan-file', path)
        assert code == 2 and outcome['result'] == 0
    assert 2.5 <= time.monotonic() - started < 8


def test_verified_scan_requires_installed_engine_configuration(executable, tmp_path):
    path = tmp_path / 'private.txt'
    path.write_text('Do not send to an unconfigured server')
    with Daemon(port=3310) as daemon:
        code, outcome = invoke(executable, '--scan-file-verified', path)
    assert code == 2 and outcome['result'] == 0
    assert outcome['detail'] == 'trusted engine configuration unavailable'
    assert not daemon.commands and not daemon.data
