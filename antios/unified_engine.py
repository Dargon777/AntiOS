"""Read-only, unified AntiOS scanner over independent detection providers.

This adapter does not claim to replace signatures or unpackers supplied by its
providers. Missing or failed providers must never produce a fully clean verdict.
"""
from __future__ import annotations

import os
import threading
from typing import Callable

from .clamav import ClamAVScanner, ScanOutcome
from .windows_antivirus import AmsiScanner


class UnifiedScanner:
    """Return one conservative result for ClamAV and optional Windows AMSI."""

    name = "AntiOS unified"

    def __init__(
        self,
        *,
        engine_service: str | None = None,
        require_verified_peer: bool = False,
        clamav_factory: Callable | None = None,
        amsi_factory: Callable | None = None,
        use_amsi: bool | None = None,
    ) -> None:
        self._clamav = None
        self._amsi = None
        self._clamav_failed = threading.Event()
        self._amsi_failed = threading.Event()
        self._amsi_required = (os.name == "nt") if use_amsi is None else bool(use_amsi)
        errors = []
        try:
            self._clamav = (clamav_factory or ClamAVScanner)(
                service_name=engine_service,
                require_verified_peer=(require_verified_peer or os.name == "nt"),
            )
        except (OSError, RuntimeError) as exc:
            errors.append(f"ClamAV: {exc}")
        if self._amsi_required:
            try:
                self._amsi = (amsi_factory or AmsiScanner)()
            except (OSError, RuntimeError) as exc:
                errors.append(f"AMSI: {exc}")
        if self._clamav is None and self._amsi is None:
            raise OSError("AntiOS unified providers unavailable: " + "; ".join(errors))

        metadata = dict(getattr(self._clamav, "metadata", {})) if self._clamav else {}
        self.metadata = {
            **metadata,
            "database_freshness": metadata.get("database_freshness", "unknown"),
            "components": {"clamav": self._clamav is not None,
                           "amsi": self._amsi is not None,
                           "amsi_required": self._amsi_required},
        }
        if errors:
            self.metadata["degraded_detail"] = "; ".join(errors)[:500]

    def scan(self, content: bytes, name: str) -> ScanOutcome:
        findings: list[ScanOutcome] = []
        errors: list[str] = []
        complete = True
        if self._clamav is None or self._clamav_failed.is_set():
            complete = False
        else:
            try:
                outcome = self._clamav.scan(content, name)
                if not isinstance(outcome, ScanOutcome):
                    raise OSError("Invalid ClamAV scan result")
                complete = complete and outcome.complete
                if outcome.detail:
                    errors.append(outcome.detail)
                if outcome.kind:
                    findings.append(outcome)
            except (OSError, RuntimeError) as exc:
                self._clamav_failed.set()
                complete = False
                errors.append(f"ClamAV: {exc}")
        if self._amsi_required:
            if self._amsi is None or self._amsi_failed.is_set():
                complete = False
            else:
                try:
                    value = self._amsi.scan(content, name)
                    if type(value) is not int:
                        raise OSError("Invalid AMSI scan result")
                    if value >= 32768:
                        findings.append(ScanOutcome("threat", "AMSI malware detection", "Windows AMSI"))
                    elif 0x4000 <= value <= 0x4FFF:
                        findings.append(ScanOutcome("review", "Blocked by administrator policy", "Windows AMSI"))
                except (OSError, RuntimeError) as exc:
                    self._amsi_failed.set()
                    complete = False
                    errors.append(f"AMSI: {exc}")
        # A confirmed signature is stronger evidence than an advisory signal.
        chosen = next((f for f in findings if f.kind == "threat"), None)
        if chosen is None:
            chosen = next((f for f in findings if f.kind == "review"), None)
        return ScanOutcome(
            chosen.kind if chosen else None,
            chosen.name if chosen else "",
            chosen.engine if chosen else "AntiOS unified",
            complete,
            "; ".join(errors)[:500],
        )

    def scan_stream(self, chunks) -> ScanOutcome:
        if self._clamav is None or self._clamav_failed.is_set():
            raise OSError("ClamAV is unavailable for streamed scans")
        try:
            outcome = self._clamav.scan_stream(chunks)
            if not isinstance(outcome, ScanOutcome):
                raise OSError("Invalid ClamAV scan result")
            # AMSI exposes a buffer API, not a streaming API. Do not silently
            # claim full unified coverage for a file only checked by ClamAV.
            return ScanOutcome(outcome.kind, outcome.name, outcome.engine,
                               outcome.complete and not self._amsi_required,
                               outcome.detail)
        except (OSError, RuntimeError):
            self._clamav_failed.set()
            raise

    def close(self) -> None:
        for provider in (self._amsi, self._clamav):
            if provider is not None:
                provider.close()
