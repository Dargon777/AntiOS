"""Execute the native C boundary, including real ClamD; no malware is used."""
import ctypes
import datetime as dt
import gc
import io
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import zipfile

import pytest
from test_clamav_integration import real_clamd  # noqa: F401 -- shared real-engine fixture


class Outcome(ctypes.Structure):
    _fields_ = [('result', ctypes.c_int), ('database_current', ctypes.c_int),
                ('name', ctypes.c_char * 201), ('detail', ctypes.c_char * 160)]


CANCEL = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
PEER = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_size_t, ctypes.c_void_p)


@pytest.fixture(scope='module')
def native(tmp_path_factory):
    # Earlier Tk tests may leave unreachable widget cycles. Finalize them on
    # their owner thread, before the local daemon's transport threads can GC.
    gc.collect()
    compiler = shutil.which('gcc')
    if os.name == 'nt' or not compiler:
        if os.environ.get('ANTIOS_REQUIRE_NATIVE'):
            pytest.fail('Linux GCC native boundary tests required in this job')
        pytest.skip('C boundary integration tests require Linux GCC')
    source = Path(__file__).resolve().parents[1] / 'native/windows/engine'
    library = tmp_path_factory.mktemp('native') / 'engine.so'
    subprocess.run([compiler, '-std=c11', '-D_POSIX_C_SOURCE=200809L', '-Wall', '-Wextra', '-Werror',
                    '-shared', '-fPIC', str(source / 'protocol.c'), str(source / 'clamd.c'),
                    '-o', str(library)], check=True)
    module = ctypes.CDLL(str(library))
    module.ao_parse_reply.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
    module.ao_parse_reply.restype = ctypes.c_int
    module.ao_database_current.argtypes = [ctypes.c_char_p, ctypes.c_long]
    module.ao_database_current.restype = ctypes.c_int
    module.ao_clam_scan.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_ushort, ctypes.c_uint,
                                   CANCEL, ctypes.c_void_p]
    module.ao_clam_scan.restype = Outcome
    module.ao_clam_scan_verified.argtypes = module.ao_clam_scan.argtypes + [PEER, ctypes.c_void_p]
    module.ao_clam_scan_verified.restype = Outcome
    return module


def scan(native, port, data=b'harmless', timeout=800, cancel=lambda: False):
    callback = CANCEL(lambda _: int(cancel()))
    return native.ao_clam_scan(data, len(data), port, timeout, callback, None)


@pytest.mark.parametrize('reply, verdict', [
    (b'stream: OK', 2), (b'stream: AntiOS.Inert.Test.UNOFFICIAL FOUND', 1),
    (b'stream: Heuristics.Limits.Exceeded FOUND', 3), (b'stream: PUA.Test FOUND', 3),
    (b'ERROR', 0), (b'stream: OK\0junk', 0), (b'stream: FOUND', 0),
    (b'stream:   FOUND', 0), (b'stream: a\nFOUND', 0), (b'stream: "malformed" FOUND', 0),
    (b'stream: ' + b'a' * 201 + b' FOUND', 0), (b'stream: OK\n', 0),
])
def test_verdict_boundary(native, reply, verdict):
    name = ctypes.create_string_buffer(201)
    assert native.ao_parse_reply(reply, len(reply), name) == verdict


def current_version(days=0):
    # Engine timestamp uses the local daemon timezone, just as ClamD VERSION does.
    moment = dt.datetime.now() - dt.timedelta(days=days)
    return f'ClamAV 1.5.3/27900/{moment.strftime("%a %b %d %H:%M:%S %Y")}'.encode('ascii')


@pytest.mark.parametrize('version, expected', [
    (lambda: current_version(), 1), (lambda: current_version(8), 0),
    (lambda: current_version(-2), 0), (lambda: b'ClamAV 1.5.3', 0),
    (lambda: b'ClamAV 1.5.3/27900/Tue Feb 31 12:00:00 2026', 0),
    (lambda: b'ClamAV 1.5.3/27900/Tue Feb 01 999999999999:00:00 2026', 0),
    (lambda: current_version() + b' junk', 0),
])
def test_database_dates(native, version, expected):
    assert native.ao_database_current(version(), int(time.time())) == expected


class Daemon:
    def __init__(self, version=None, verdict=b'stream: OK\0', stall=False, fragment=False, port=0):
        self.version = version if version is not None else current_version() + b'\0'
        self.verdict, self.stall, self.fragment = verdict, stall, fragment
        self.data = bytearray()
        self.commands = []
        self.errors = []
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', port))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    @staticmethod
    def exact(connection, size):
        result = bytearray()
        while len(result) < size:
            chunk = connection.recv(size - len(result))
            if not chunk:
                raise EOFError()
            result.extend(chunk)
        return bytes(result)

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(1)
                    command = bytearray()
                    while not command.endswith(b'\0'):
                        command.extend(self.exact(connection, 1))
                    self.commands.append(bytes(command))
                    if self.stall:
                        self.stop.wait(10)
                    elif command == b'zVERSION\0':
                        connection.sendall(self.version)
                    elif command == b'zINSTREAM\0':
                        while True:
                            size = int.from_bytes(self.exact(connection, 4), 'big')
                            if not size:
                                break
                            assert size <= 65536
                            self.data.extend(self.exact(connection, size))
                        if self.fragment:
                            for byte in self.verdict:
                                connection.sendall(bytes([byte]))
                        else:
                            connection.sendall(self.verdict)
                    else:
                        raise AssertionError(command)
        except (EOFError, BrokenPipeError, ConnectionResetError):
            pass  # expected for timeout/cancel tests
        except Exception as error:
            self.errors.append(error)

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(3)
        self.listener.close()
        assert not self.thread.is_alive()
        assert not self.errors


def test_chunked_content_and_fragmented_reply(native):
    data = bytes(range(256)) * 520
    with Daemon(fragment=True) as server:
        result = scan(native, server.port, data)
        assert result.result == 2 and result.database_current
        assert server.data == data
        assert server.commands == [b'zVERSION\0', b'zINSTREAM\0']


@pytest.mark.parametrize('reply', [b'stream: OK\0extra', b'ERROR\0', b'x' * 4096, b'stream: OK'])
def test_invalid_wire_verdict_never_clean(native, reply):
    with Daemon(verdict=reply) as server:
        assert scan(native, server.port).result == 0


def test_stale_database_does_not_hide_positive_detection(native):
    with Daemon(version=current_version(30) + b'\0') as server:
        assert scan(native, server.port).result == 0
    with Daemon(version=current_version(30) + b'\0', verdict=b'stream: Inert.Test FOUND\0') as server:
        result = scan(native, server.port)
        assert result.result == 1 and not result.database_current


@pytest.mark.parametrize('cancel', [False, True])
def test_deadline_and_cancellation(native, cancel):
    start = time.monotonic()
    with Daemon(stall=True) as server:
        result = scan(native, server.port, timeout=250 if not cancel else 3000,
                      cancel=lambda: cancel and time.monotonic() - start > 0.1)
        assert result.result == 0
    assert time.monotonic() - start < 0.8


def test_invalid_size_never_connects(native):
    with Daemon() as server:
        callback = CANCEL(lambda _: 0)
        outcome = native.ao_clam_scan(b'x', 32 * 1024 * 1024 + 1, server.port, 1000, callback, None)
        assert outcome.result == 0
        assert not server.commands


def test_native_real_clamd_archives_and_limits(native, real_clamd):
    port, marker = real_clamd
    plain = scan(native, port, marker, timeout=3000)
    assert plain.result == 1 and b'AntiOS.Inert.Test' in plain.name
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('inert.txt', marker)
    assert scan(native, port, buffer.getvalue(), timeout=3000).result == 1
    assert scan(native, port, b'Unrelated safe text', timeout=3000).result == 0  # custom-only DB freshness unknown
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('large.txt', b'A' * (2 * 1024 * 1024))
    assert scan(native, port, buffer.getvalue(), timeout=3000).result == 3


@pytest.mark.parametrize('reject_connection', [1, 2, 0])
def test_verified_peer_checks_each_connection_before_sending(native, reject_connection):
    checked = []
    def verify(fd, context):
        # Inspect the connected socket without taking ownership of the C socket.
        connection = socket.socket(fileno=fd)
        try:
            assert connection.getpeername()[0] == '127.0.0.1'
        finally:
            connection.detach()
        checked.append(fd)
        return int(len(checked) != reject_connection)
    callback = PEER(verify)
    data = b'private file bytes'
    with Daemon() as server:
        result = native.ao_clam_scan_verified(data, len(data), server.port, 800,
                                              CANCEL(), None, callback, None)
    if reject_connection:
        assert result.result == 0
        assert b'peer identity rejected' in result.detail
        assert not server.data
        assert server.commands == ([] if reject_connection == 1 else [b'zVERSION\0'])
        assert len(checked) == reject_connection
    else:
        assert result.result == 2
        assert len(checked) == 2
        assert server.data == data
        assert server.commands == [b'zVERSION\0', b'zINSTREAM\0']


def test_verified_peer_callback_required(native):
    with Daemon() as server:
        result = native.ao_clam_scan_verified(b'x', 1, server.port, 800,
                                              CANCEL(), None, PEER(), None)
    assert result.result == 0
    assert b'verifier required' in result.detail
    assert not server.commands and not server.data
