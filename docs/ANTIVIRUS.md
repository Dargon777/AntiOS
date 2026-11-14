# Antivirus

AntiOS has its own local file-inspection engine. Current 3.x builds do not require ClamAV or another external antivirus engine to perform AntiOS scans.

## What a scan does

The engine can:

- calculate full-file SHA-256 hashes for readable files;
- match the bundled and installed AntiOS signature catalog;
- inspect supported PE, ELF and script structures;
- inspect supported ZIP (including BZIP2, LZMA and Zstandard members), GZIP, TAR, BZIP2, XZ, LZMA, Zstandard, ar and newc/CRC CPIO contents within configured limits;
- flag selected structural indicators for review;
- report unreadable, truncated or unsupported content as incomplete coverage rather than clean.

Quarantine and restore are explicit operations. Structural or behavioral review findings are not treated as confirmed malware by themselves.

## Format coverage

| Formats | Inspection |
| --- | --- |
| DOCX, XLSX, PPTX, ODF, JAR, APK, EPUB, WHL, MSIX and other supported ZIP containers | Bounded inspection of ZIP members. Recognized VBA projects are flagged for review. |
| DEB and RPM | Recursive inspection of supported package payloads. RPM header metadata and scriptlets are reported as a gap. |
| PDF, RTF and SVG | Advisory checks for visible PDF action and attachment declarations, RTF objects and SVG active elements. Uninspected streams and embedded objects are reported as coverage gaps. |
| Legacy Office OLE, Outlook MSG and MSI | Exact hash matching and explicit reporting that compound file streams remain uninspected. |
| 7z, RAR, CAB, ISO, DMG and WIM | Exact hash matching and explicit reporting of unsupported container contents. |

Formats without a dedicated parser still receive full SHA-256 hashing when readable. Signature matches and archive members are reported without executing or extracting files to disk.

## Scan profiles

| Profile | Default workers | Full-content inspection limit | Archive nesting |
| --- | ---: | ---: | ---: |
| Light | 2 | 16 MiB | 2 |
| Balanced | 4 | 64 MiB | 4 |
| Heavy | 8 | 96 MiB | 6 |

Large readable files can still receive a full SHA-256 hash while deeper structural inspection stays bounded. Reports show when coverage is partial.

Example command:

    antios virus-scan PATH --profile heavy --workers 12 --json

## Rust static core

Windows desktop packages include a Rust library used by the existing scan worker. It computes SHA-256 for buffered data and checks PE and ELF headers and script indicators. The same checks also run on buffered archive members after bounded decompression. Python still handles archive traversal and budgets, file identity, streaming hashes, signed catalogs and verdicts.

Scan reports show the active backend in `engine.static_core`. Builds without the library use the Python implementation. A rejected native call switches the scan to Python without changing its inspection profile. The Rust library does not change Guard's post-write monitoring model.

## GPU hashing

Manual scans have a GPU mode independent of scan depth and worker count. The Windows scanner can use an NVIDIA CUDA driver to calculate exact SHA-256 hashes for groups of buffered files up to 64 KiB each. Archive and structural inspection still run on the CPU.

| Mode | Behavior |
| --- | --- |
| Automatic | Measures one eligible batch. Uses CUDA when the transfer and worker dispatch estimate indicates a gain. |
| Economy | Uses smaller batches and spaces out CUDA dispatches. Uses the same measured routing. |
| Accelerated | Uses CUDA for eligible batches after a digest parity check. |
| CPU only (default) | Computes hashes on the CPU and skips CUDA initialization. |

The scanner continues on the CPU after a CUDA failure. The report lists the requested mode, CUDA file count, calibration and any fallback. Guard uses the CPU for its single-file background checks.

    antios virus-scan PATH --gpu-mode auto --profile balanced --json
    antios virus-scan-benchmark --gpu --repeat 3 --json

The GPU benchmark compares complete scan times and verdict receipts on identical inert files. Faster hashing can still leave the full scan limited by filesystem reads and CPU inspection.

## Reports and replay

JSON scan reports include findings, issues, coverage and the decision made from that evidence.

The command below checks whether a saved report reproduces the recorded decision under the supported decision policy:

    antios virus-scan-replay REPORT.json --json

The built-in benchmark runs inert controls with known expected outcomes:

    antios virus-scan-benchmark --json

The benchmark reports confirmed signature hits and misses, benign controls flagged for review, and limited coverage per profile. Its synthetic signatures measure whether the scanner reaches and identifies the expected bytes. Real-world malware detection needs a separate representative evaluation.

## Signature updates

Use:

    antios signatures status --json
    antios signatures install PACKAGE

Before installing a signed update, you can register known-good files with
`antios signatures trust-file FILE` and preview the comparison with
`antios signatures preflight PACKAGE --json`. AntiOS records only local SHA-256
hashes and checks them again inside the installation transaction. Any conflict
blocks activation and the active catalog stays in place. Use
`antios signatures untrust-hash SHA256` to remove an entry. This baseline applies
to exact hashes in signed update packages. With no entries the preview reports
`no-baseline`. Adding a file does not exempt it from live scanning.

A rejected or unreadable update must not silently replace a verified catalog. AntiOS can fall back to a verified bundled catalog and report the degraded state.

The starter exact-hash set includes indicators derived from public NCSC and CISA/FBI malware reporting. It is intentionally limited; exact-hash coverage should not be confused with broad malware-family detection.

## Limitations

AntiOS is pre-release software. It does not currently provide certified Windows primary-antivirus registration, ELAM/PPL protection, a kernel minifilter for complete pre-execution blocking or complete boot-time malware coverage.

A clean result means only that the content successfully inspected by the active AntiOS checks did not produce a finding.
