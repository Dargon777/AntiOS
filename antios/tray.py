"""Windows Resident Guard system-tray status icon."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import threading
from typing import Any


def icon_asset(name: str) -> Path:
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        path = base / "antios" / "assets" / "icons" / name
    else:
        path = Path(__file__).resolve().parent / "assets" / "icons" / name
    if not path.is_file():
        raise FileNotFoundError(f"AntiOS icon asset is missing: {path}")
    return path


def tray_variant(state: str | None) -> str:
    return "ok" if state in {"monitoring", "scanning"} else "alert"


class GuardTray:
    """Small best-effort UI surface for the frozen Windows Guard.

    Tray failures never weaken or stop protection; the Guard remains authoritative.
    """

    def __init__(self) -> None:
        self._icon: Any | None = None
        self._thread: threading.Thread | None = None
        self._state: str | None = None
        self._lock = threading.Lock()

    def _image(self, variant: str):
        from PIL import Image

        return Image.open(icon_asset(f"tray_{variant}.png")).convert("RGBA")

    @staticmethod
    def _title(state: str | None) -> str:
        if state in {"monitoring", "scanning"}:
            return "AntiOS — protection active"
        if state == "attention":
            return "AntiOS — threat requires attention"
        if state == "degraded":
            return "AntiOS — protection degraded"
        if state == "failed":
            return "AntiOS — protection failed"
        if state == "stopped":
            return "AntiOS — protection stopped"
        return "AntiOS — protection starting"

    def start(self, state: str = "starting") -> None:
        if os.name != "nt":
            return
        import pystray

        with self._lock:
            if self._icon is not None:
                self.set_state(state)
                return
            icon = pystray.Icon(
                "AntiOSGuard",
                self._image(tray_variant(state)),
                self._title(state),
            )
            self._icon = icon
            self._state = state

            def runner() -> None:
                try:
                    icon.run()
                except Exception:
                    # Visual status is optional. Guard protection must keep running.
                    pass

            self._thread = threading.Thread(
                target=runner,
                name="AntiOSGuardTray",
                daemon=True,
            )
            self._thread.start()

    def set_state(self, status: dict[str, Any] | str) -> None:
        state = status.get("state") if isinstance(status, dict) else status
        state = str(state or "starting")
        with self._lock:
            icon = self._icon
            if icon is None or state == self._state:
                return
            self._state = state
            try:
                icon.icon = self._image(tray_variant(state))
                icon.title = self._title(state)
            except Exception:
                pass

    def stop(self) -> None:
        with self._lock:
            icon, thread = self._icon, self._thread
            self._icon = None
            self._thread = None
        if icon is not None:
            try:
                icon.stop()
            except Exception:
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1)
