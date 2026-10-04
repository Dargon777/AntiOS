"""Read-only ClamD client with loopback-only transport and bounded requests.

ClamD TCP does not authenticate its peer.  On Windows, AntiOS can bind requests
to an administrator-configured running LocalSystem SCM service and verify that
the server side of each established loopback connection belongs to that PID.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import math
import os
import re
import socket
import struct
import time

from .windows_clamd_peer import (
    configured_service_name,
    query_service_process,
    verify_connected_socket,
)


@dataclass(frozen=True)
class ScanOutcome:
    kind: str | None = None
    name: str = ""


def _is_windows() -> bool:
    return os.name == "nt"


class ClamAVScanner:
    name = "ClamAV"

    def __init__(self, *, port: int = 3310, timeout: float = 30,
                 service_name: str | None = None,
                 require_verified_peer: bool = False) -> None:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("ClamAV port must be between 1 and 65535")
        if not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ValueError("ClamAV timeout must be between 0 and 300 seconds")
        self.port, self.timeout = port, timeout
        self.service_name = configured_service_name(service_name) if _is_windows() else None
        self.require_verified_peer = bool(require_verified_peer)
        if _is_windows() and self.require_verified_peer and not self.service_name:
            raise OSError(
                "Resident ClamAV protection requires an administrator-configured "
                "ClamD SCM service (policy engine_service, ANTIOS_CLAMD_SERVICE, "
                "or AntiOS registry binding)"
            )
        version = self._request(b"zVERSION\0")
        if not re.fullmatch(r"ClamAV [ -~]{1,500}", version):
            raise OSError("ClamAV returned an invalid VERSION response")
        peer_required = _is_windows()
        peer_verified = bool(self.service_name) if peer_required else None
        self.metadata = {
            "version": version,
            "endpoint": f"127.0.0.1:{port}",
            "database_freshness": self._freshness(version),
            "archive_policy": "managed-by-clamd.conf",
            "peer_verification_required": peer_required,
            "peer_verified": peer_verified,
            "peer_identity": (
                f"windows-service:{self.service_name}" if peer_verified
                else "unverified-loopback" if peer_required
                else "not-enforced-on-this-platform"
            ),
        }

    @staticmethod
    def _freshness(version: str) -> str:
        # VERSION uses the daemon's local ctime. Both endpoints are on this
        # machine. Parse English month names without changing process locale.
        match = re.fullmatch(r"ClamAV [^/]+/\d+/\w{3} (\w{3}) +([0-9]{1,2}) "
                             r"(\d{2}):(\d{2}):(\d{2}) (\d{4})", version)
        if not match:
            return "unknown"
        month, day, hour, minute, second, year = match.groups()
        try:
            month_number = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split().index(month) + 1
            published = datetime(int(year), month_number, int(day), int(hour), int(minute), int(second))
        except ValueError:
            return "unknown"
        age = (datetime.now() - published).total_seconds()
        if age < -86400:
            return "future-date"
        return "current" if age <= 7 * 86400 else "stale"

    def _request(self, command: bytes, content: bytes | None = None) -> str:
        deadline = time.monotonic() + self.timeout
        expected_pid = None
        if self.service_name:
            expected_pid = query_service_process(self.service_name).pid
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            def remaining() -> None:
                seconds = deadline - time.monotonic()
                if seconds <= 0:
                    raise TimeoutError("ClamAV request deadline exceeded")
                connection.settimeout(seconds)

            remaining()
            connection.connect(("127.0.0.1", self.port))
            if expected_pid is not None and not verify_connected_socket(connection, expected_pid):
                raise OSError("ClamD loopback peer is not owned by the configured SCM service")
            remaining()
            connection.sendall(command)
            if content is not None:
                view = memoryview(content)
                for offset in range(0, len(view), 64 * 1024):
                    chunk = view[offset:offset + 64 * 1024]
                    remaining()
                    connection.sendall(struct.pack("!I", len(chunk)))
                    remaining()
                    connection.sendall(chunk)
                remaining()
                connection.sendall(b"\0\0\0\0")
            reply = bytearray()
            while len(reply) < 4096:
                remaining()
                block = connection.recv(4096 - len(reply))
                if not block:
                    raise OSError("ClamAV closed the connection without a complete response")
                reply.extend(block)
                if b"\0" in block:
                    if not reply.endswith(b"\0") or reply.count(0) != 1:
                        raise OSError("ClamAV returned multiple or malformed responses")
                    if expected_pid is not None:
                        current = query_service_process(self.service_name)
                        if current.pid != expected_pid:
                            raise OSError("Configured ClamD service changed during the request")
                    try:
                        return reply[:-1].decode("utf-8", errors="strict")
                    except UnicodeDecodeError as exc:
                        raise OSError("ClamAV returned invalid UTF-8") from exc
            raise OSError("ClamAV response exceeds 4096 bytes")

    def scan(self, content: bytes, name: str) -> ScanOutcome:
        # Never send a path or ask the daemon to open/change/delete a file.
        reply = self._request(b"zINSTREAM\0", content)
        if reply == "stream: OK":
            return ScanOutcome()
        match = re.fullmatch(r"stream: ([A-Za-z0-9_.:+/() -]{1,200}) FOUND", reply)
        if match:
            label = match[1]
            # Limits, encrypted content and heuristics require review.
            return ScanOutcome("review" if label.startswith(("Heuristics.", "PUA.")) else "threat", label)
        raise OSError(f"ClamAV scan failed: {reply[:500]!r}")

    def close(self) -> None:
        # Every request owns and closes its socket, including error paths.
        pass
