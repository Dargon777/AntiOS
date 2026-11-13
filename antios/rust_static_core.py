"""Load the versioned static core from the AntiOS package directory."""
from __future__ import annotations

import ctypes
from functools import lru_cache
from pathlib import Path
import sys


class RustStaticCore:
    def __init__(self, path: Path) -> None:
        library = ctypes.CDLL(str(path.resolve(strict=True)))
        version = library.antios_core_abi_version
        version.argtypes = ()
        version.restype = ctypes.c_uint32
        if version() != 1:
            raise ValueError("Unsupported AntiOS static core ABI")

        self._sha256 = library.antios_sha256
        self._sha256.argtypes = (ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p)
        self._sha256.restype = ctypes.c_uint32
        self._inspect = library.antios_static_scan
        self._inspect.argtypes = (ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint8)
        self._inspect.restype = ctypes.c_uint32
        if (
            self.digest(b"abc") != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            or self.inspect(b"MZ", False) != (0, 1)
        ):
            raise ValueError("AntiOS static core self-test failed")

    def digest(self, content: bytes) -> str:
        output = (ctypes.c_ubyte * 32)()
        if self._sha256(content, len(content), output):
            raise ValueError("AntiOS static core rejected the hash request")
        return bytes(output).hex()

    def inspect(self, content: bytes, is_script: bool) -> tuple[int, int]:
        code = self._inspect(content, len(content), is_script)
        script, executable = code & 0xFF, code >> 8
        if script > 3 or executable > 10 or (script and not is_script):
            raise ValueError("AntiOS static core returned an invalid inspection result")
        return script, executable


@lru_cache(maxsize=1)
def load_static_core() -> RustStaticCore | None:
    name = {
        "win32": "antios_static_core.dll",
        "linux": "libantios_static_core.so",
    }.get(sys.platform)
    if name is None:
        return None
    path = Path(__file__).resolve().parent / "_native" / name
    try:
        if path.parent.is_symlink() or path.is_symlink():
            return None
        return RustStaticCore(path)
    except (OSError, ValueError, AttributeError):
        return None
