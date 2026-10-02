"""Isolate read-only scans so a blocked filesystem/AMSI call can be terminated.

The child appends JSON events to a private temporary directory. This works with
windowed frozen executables (which have no stdout), and killing a writer cannot
strand the parent in a partially written pipe message.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Callable

from .antivirus import scan_files, utc_now
from .quarantine import default_quarantine_path

WORKER_FLAG = "--antios-scan-worker"


def worker_main(request_path: str, events_path: str) -> int:
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    with open(events_path, "w", encoding="utf-8") as stream:
        def emit(kind, value):
            stream.write(json.dumps([kind, value], ensure_ascii=True) + "\n")
            stream.flush()

        counts = [0, 0]
        last_sent = [0.0]

        def checkpoint(result):
            now = time.monotonic()
            if (now - last_sent[0] < 0.1 and not result["finished_at"]
                    and counts == [len(result["findings"]), len(result["issues"])]):
                return
            last_sent[0] = now
            # Send only new findings/issues: large scans must not copy their
            # entire accumulated report for every progress update.
            event = {k: v for k, v in result.items() if k not in {"findings", "issues"}}
            for index, key in enumerate(("findings", "issues")):
                event[key] = result[key][counts[index]:]
                counts[index] = len(result[key])
            emit("checkpoint", event)

        try:
            scan_files(request["path"], signature_path=request.get("signatures"),
                       excluded_paths=(default_quarantine_path(),), checkpoint=checkpoint)
            emit("done", None)
            return 0
        except Exception as exc:
            emit("error", str(exc))
            return 1


def worker_command(request: Path, events: Path) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, WORKER_FLAG, str(request), str(events)]
    # pythonw has no console, but our transport does not rely on stdio.
    return [sys.executable, "-m", "antios.scan_process", str(request), str(events)]


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def run_scan_process(path: Path, *, signature_path: Path | None = None,
                     cancelled: Callable[[], bool] = lambda: False,
                     progress: Callable[[dict], None] | None = None) -> dict:
    result = None
    done, failure = False, None
    with tempfile.TemporaryDirectory(prefix="antios-scan-") as folder:
        request, events = Path(folder) / "request.json", Path(folder) / "events.jsonl"
        request.write_text(json.dumps({"path": str(Path(path).absolute()),
                                      "signatures": str(signature_path.absolute()) if signature_path else None}),
                           encoding="utf-8")
        events.touch()
        process = subprocess.Popen(worker_command(request, events), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        forced = False
        pending = ""
        try:
            with events.open(encoding="utf-8") as stream:
                while True:
                    if cancelled() and process.poll() is None:
                        forced = True
                        _terminate(process)
                    # Once it has exited, drain the final complete records.
                    exited = process.poll() is not None
                    pending += stream.read()
                    lines = pending.split("\n")
                    pending = lines.pop()
                    for line in lines:
                        kind, value = json.loads(line)
                        if kind == "checkpoint":
                            if result is None:
                                result = value
                            else:
                                for key in ("findings", "issues"):
                                    value[key] = result[key] + value[key]
                                result = value
                            if progress:
                                progress(result["summary"])
                        elif kind == "done":
                            done = True
                        elif kind == "error":
                            failure = value
                    if exited:
                        break
                    time.sleep(0.05)
            if forced:
                if result is None:
                    # Cancellation can arrive before the interpreter starts.
                    result = {"schema": 1, "kind": "antivirus-scan", "path": str(path),
                              "started_at": utc_now(), "engine": {}, "limits": {},
                              "summary": {"files_seen": 0, "entries_seen": 0, "files_scanned": 0,
                                          "provider_scanned": 0, "bytes_scanned": 0, "threats": 0,
                                          "reviews": 0, "skipped": 0, "errors": 0, "limit_reached": False},
                              "findings": [], "issues": []}
                result["summary"].update(cancelled=True, forced_stop=True)
                result.update(coverage="limited", finished_at=utc_now(),
                              verdict="threats-found" if result["summary"]["threats"] else
                              "review" if result["summary"]["reviews"] else "incomplete")
                return result
            if failure or not done or result is None or process.returncode != 0:
                raise RuntimeError(failure or f"Scan worker exited unexpectedly ({process.returncode})")
            return result
        finally:
            _terminate(process)


if __name__ == "__main__":
    raise SystemExit(worker_main(*sys.argv[1:]))
