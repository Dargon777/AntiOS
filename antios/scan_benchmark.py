"""Deterministic, inert detection controls for the built-in scanner."""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
from statistics import median
import tarfile
import tempfile
import time
import zipfile

from .antivirus import SCAN_PROFILE_WORKERS, scan_files
from .engine import zstd
from .scan_acceleration import GPU_MODES
from .scan_verdict import replay_scan_report


_CLEAN = ("no-threats-found", "complete", "no-indicators")
_MATCH = ("threats-found", "complete", "confirmed-signature")
_ADVISORY = ("review", "complete", "suspicious")
_LIMITED = ("review", "limited", "undetermined")
_PREVIEW = ("incomplete", "limited", "undetermined")
_PARTIAL_ADVISORY = ("review", "limited", "suspicious")


def _zip_member(name: str, content: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(zipfile.ZipInfo(name), content)
    return output.getvalue()


def _write_large(target: Path, trailer: bytes) -> str:
    block = bytes(1024 * 1024)
    digest = hashlib.sha256()
    with target.open("wb") as stream:
        for _ in range(16):
            stream.write(block)
            digest.update(block)
        stream.write(trailer)
    digest.update(trailer)
    return digest.hexdigest()


def _tar_member(name: str, content: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo(name)
        entry.size = len(content)
        archive.addfile(entry, io.BytesIO(content))
    return output.getvalue()


def _ar_member(name: str, content: bytes) -> bytes:
    header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(content):<10}\x60\n"
    return b"!<arch>\n" + header.encode("ascii") + content + (b"\n" if len(content) % 2 else b"")


def _cpio_member(name: str, content: bytes, mode: int) -> bytes:
    encoded = name.encode("ascii") + b"\0"
    fields = (0, mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(encoded), 0)
    header = b"070701" + "".join(f"{field:08x}" for field in fields).encode("ascii")
    entry = header + encoded
    return entry + bytes(-len(entry) % 4) + content + bytes(-len(content) % 4)


def _build_corpus(folder: Path) -> tuple[Path, Path, dict]:
    fixtures = folder / "corpus"
    fixtures.mkdir()
    positive = b"AntiOS inert benchmark signature fixture\n"
    nested = _zip_member("fixture.txt", positive)
    for _ in range(4):
        nested = _zip_member("nested.zip", nested)

    inputs = {
        "benign.txt": b"Ordinary benchmark text\n",
        "benign.ps1": b"Write-Output 'ordinary benchmark text'\n",
        "benign.zip": _zip_member("ordinary.txt", b"Ordinary archive content\n"),
        "exact-match.txt": positive,
        "nested-five.zip": nested,
        "office-review.docm": _zip_member("word/vbaProject.bin", bytes.fromhex("d0cf11e0a1b11ae1") + b"inert"),
        "unsupported.7z": b"Inert unsupported format fixture\n",
        "unreadable.zip": b"Inert invalid archive fixture\n",
        "signature.jar": _zip_member("data/fixture.txt", positive),
        "signature.apk": _zip_member("assets/fixture.txt", positive),
        "signature.docx": _zip_member("word/media/fixture.txt", positive),
        "signature.odt": _zip_member("Pictures/fixture.txt", positive),
        "signature.tar": _tar_member("fixture.txt", positive),
        "signature.tgz": gzip.compress(_tar_member("fixture.txt", positive), mtime=0),
        "signature.bz2": bz2.compress(positive),
        "signature.xz": lzma.compress(positive),
        "signature.ar": _ar_member("fixture.txt", positive),
        "signature.cpio": _cpio_member("fixture.txt", positive, 0o100644)
        + _cpio_member("TRAILER!!!", b"", 0),
        "active.pdf": b"%PDF-1.4\n1 0 obj\n<< /S /JavaScript /JS (ordinary label) >>\nendobj\n%%EOF\n",
        "streams.pdf": b"%PDF-1.4\n1 0 obj\n<< /Length 4 >>\nstream\ntext\nendstream\nendobj\n%%EOF\n",
        "clean.pdf": b"%PDF-1.4\n1 0 obj\n<< /Title (/JavaScript) >>\nendobj\n%%EOF\n",
        "embedded.rtf": b"{\\rtf1{\\object{\\*\\objdata 0011}}}",
        "clean.rtf": b"{\\rtf1\\ansi Ordinary text and an escaped \\\\objdata word.}",
        "clean.svg": b'<svg xmlns="http://www.w3.org/2000/svg"><text>Ordinary text</text></svg>',
        "active.svg": b'<svg xmlns="http://www.w3.org/2000/svg"><script>/* inert */</script></svg>',
    }
    if zstd is not None:
        inputs["signature.zst"] = zstd.compress(positive)
        inputs["signature.tar.zst"] = zstd.compress(_tar_member("fixture.txt", positive))
    for name, content in inputs.items():
        (fixtures / name).write_bytes(content)
    streamed_digest = _write_large(fixtures / "streamed-match.bin", b"signature after the preview")
    _write_large(fixtures / "streamed-benign.bin", b"ordinary trailer")
    signatures = folder / "control-signatures.json"
    signatures.write_text(json.dumps({"schema": 1, "sha256": {
        hashlib.sha256(positive).hexdigest(): "Inert benchmark signature",
        streamed_digest: "Inert streamed benchmark signature",
    }}), encoding="utf-8")

    # Each control has an expected result per depth, independent of the scanner.
    expected = {
        "benign.txt": (_CLEAN, _CLEAN, _CLEAN),
        "benign.ps1": (_CLEAN, _CLEAN, _CLEAN),
        "benign.zip": (_CLEAN, _CLEAN, _CLEAN),
        "exact-match.txt": (_MATCH, _MATCH, _MATCH),
        "nested-five.zip": (_LIMITED, _LIMITED, _MATCH),
        "office-review.docm": (_ADVISORY, _ADVISORY, _ADVISORY),
        "unsupported.7z": (_LIMITED, _LIMITED, _LIMITED),
        "unreadable.zip": (_LIMITED, _LIMITED, _LIMITED),
        "streamed-match.bin": (_MATCH, _MATCH, _MATCH),
        "streamed-benign.bin": (_PREVIEW, _CLEAN, _CLEAN),
        **{name: (_MATCH,) * 3 for name in inputs if name.startswith("signature.")},
        "active.pdf": (_ADVISORY,) * 3,
        "streams.pdf": (_PREVIEW,) * 3,
        "clean.pdf": (_CLEAN,) * 3,
        "embedded.rtf": (_PARTIAL_ADVISORY,) * 3,
        "clean.rtf": (_CLEAN,) * 3,
        "clean.svg": (_CLEAN,) * 3,
        "active.svg": (_ADVISORY,) * 3,
    }
    return fixtures, signatures, expected


def _benchmark_profile(fixtures: Path, signatures: Path, expected: dict, profile: str, repeat: int) -> dict:
    index = ("light", "balanced", "heavy").index(profile)
    options = {"signature_path": signatures, "profile": profile, "use_cache": False}
    cases = []
    metrics = {"signature_controls": 0, "signature_hits": 0, "signature_misses": 0,
               "benign_controls": 0, "benign_confirmed": 0, "benign_review": 0,
               "limited_controls": 0, "files_with_limited_coverage": 0}
    for name, outcomes in expected.items():
        result = scan_files(fixtures / name, **options)
        replay = replay_scan_report(result)
        dimensions = replay["dimensions"]
        observed = (replay["verdict"], dimensions["coverage"], dimensions["maliciousness"])
        wanted = outcomes[index]
        # A nested signature is still a positive control when a shallower
        # profile is deliberately unable to reach it.
        positive = _MATCH in outcomes
        benign = all(outcome in (_CLEAN, _PREVIEW) for outcome in outcomes)
        confirmed = observed[2] == "confirmed-signature"
        metrics["signature_controls"] += positive
        metrics["signature_hits"] += positive and confirmed
        metrics["signature_misses"] += positive and not confirmed
        metrics["benign_controls"] += benign
        metrics["benign_confirmed"] += benign and confirmed
        metrics["benign_review"] += benign and observed[0] == "review"
        metrics["limited_controls"] += wanted[1] == "limited"
        metrics["files_with_limited_coverage"] += observed[1] == "limited"
        cases.append({"name": name, "expected": list(wanted), "observed": list(observed),
                      "passed": observed == wanted})

    # Per-file controls verify answers. Time the folder separately so the
    # selected profile can exercise its real concurrency settings.
    durations, receipts = [], set()
    for _ in range(repeat):
        start = time.perf_counter()
        result = scan_files(fixtures, **options)
        durations.append(time.perf_counter() - start)
        receipts.add(replay_scan_report(result)["receipt_sha256"])
    return {"passed": sum(case["passed"] for case in cases), "total": len(cases),
            "cases": cases, "median_seconds": round(median(durations), 6),
            "effective_workers": result["limits"]["effective_workers"],
            "stable_replay": len(receipts) == 1, "metrics": metrics}


def run_detection_benchmark(*, profile: str | None = None, repeat: int = 3) -> dict:
    if profile is not None and profile not in SCAN_PROFILE_WORKERS:
        raise ValueError("Unsupported scan profile")
    if type(repeat) is not int or not 1 <= repeat <= 5:
        raise ValueError("Benchmark repetitions must be between 1 and 5")
    profiles = (profile,) if profile else tuple(SCAN_PROFILE_WORKERS)
    with tempfile.TemporaryDirectory(prefix="antios-detection-controls-") as folder:
        fixtures, signatures, expected = _build_corpus(Path(folder))
        results = {mode: _benchmark_profile(fixtures, signatures, expected, mode, repeat) for mode in profiles}
    return {"schema": 1, "kind": "antivirus-detection-benchmark", "corpus": "inert-detection-controls-v2",
            "repeat": repeat, "profiles": results,
            "passed": all(item["passed"] == item["total"] and item["stable_replay"] for item in results.values())}


def run_gpu_benchmark(*, profile: str = "balanced", repeat: int = 3) -> dict:
    """Compare complete scan timings and evidence receipts on identical inert input."""
    if profile not in SCAN_PROFILE_WORKERS or type(repeat) is not int or not 1 <= repeat <= 5:
        raise ValueError("Invalid GPU benchmark profile or repetition count")
    file_count = 1536
    measurements = {mode: [] for mode in GPU_MODES}
    receipts = set()
    expected = 0
    correct = True
    with tempfile.TemporaryDirectory(prefix="antios-cuda-controls-") as folder:
        root = Path(folder)
        corpus = root / "files"
        corpus.mkdir()
        signatures = {}
        for index in range(file_count):
            block = hashlib.sha256(f"AntiOS inert GPU benchmark {index}".encode()).hexdigest().encode()
            content = (block + b"\n") * (32 + index % 240)
            (corpus / f"fixture-{index:04}.txt").write_bytes(content)
            if index % 137 == 0:
                signatures[hashlib.sha256(content).hexdigest()] = "Inert CUDA benchmark signature"
                expected += 1
        signature_file = root / "signatures.json"
        signature_file.write_text(json.dumps({"schema": 1, "sha256": signatures}), encoding="utf-8")
        for run in range(repeat):
            for mode in (*GPU_MODES[run % len(GPU_MODES):], *GPU_MODES[:run % len(GPU_MODES)]):
                started = time.perf_counter()
                report = scan_files(corpus, signature_path=signature_file, profile=profile,
                                    gpu_mode=mode, use_cache=False)
                elapsed = time.perf_counter() - started
                acceleration = report["engine"]["acceleration"]
                measurements[mode].append((elapsed, acceleration))
                replay = replay_scan_report(report)
                receipts.add(replay["receipt_sha256"])
                correct &= (replay["dimensions"]["coverage"] == "complete"
                            and report["summary"]["files_scanned"] == file_count
                            and report["summary"]["threats"] == expected)
    modes = {
        mode: {
            "median_seconds": round(median(elapsed for elapsed, _ in runs), 6),
            "gpu_files": int(median(status["gpu_files"] for _, status in runs)),
            "fallback": next((status["fallback"] for _, status in runs if status["fallback"]), ""),
            "calibration": next((status["calibration"] for _, status in runs if status["calibration"]), None),
        }
        for mode, runs in measurements.items()
    }
    return {"schema": 1, "kind": "antivirus-gpu-benchmark", "profile": profile, "repeat": repeat,
            "files": file_count, "expected_matches": expected, "modes": modes,
            "cuda_exercised": bool(modes["accelerated"]["gpu_files"]),
            "passed": bool(correct and len(receipts) == 1)}
