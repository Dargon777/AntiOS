# AntiOS on-demand antivirus — alpha 11

The Antivirus page scans one selected file or folder using Windows AMSI plus local SHA-256 signatures. It never executes selected files. Health checks remain separate from malware scans.

Windows AMSI passes content buffers to an installed antivirus provider. Availability and detection depend on that provider and its configuration. The local built-in signature is only the inert EICAR test-file hash. Offline hash-only fallback is explicitly limited and never produces a clean-scan exit code.

## GUI

Open Antivirus in the sidebar or press `Ctrl+6`. Choose a file or folder, optionally load a local signature database, then scan. Inspect findings and skipped/error details; double-click a row to read its details. The view is capped at 1000 rows; the exported JSON retains all findings and up to 1000 issue details with total counts.

Only a threat finding is eligible for **Quarantine selected**. An AMSI administrator-policy block is a review item, not a malware verdict. Quarantine is manual; no files are deleted automatically on the strength of heuristics.

The Quarantine tab lists locally encrypted items. **Restore selected** asks for confirmation and restores to the original location. It refuses an existing destination. The installed antivirus may detect a restored threat again.

Defender quick/full scan and signature-update buttons run supported Defender operations after confirmation. Those scans follow Defender's own remediation/cloud policy. Their results are viewed in Windows Security; command completion is not treated as a clean verdict. The scan Stop button applies only to AntiOS's file scan, not a running Defender system scan. Defender operations may require administrator rights and continue independently of the app window.

## CLI

```powershell
antios virus-scan "C:\Users\Me\Downloads"
antios virus-scan "C:\Users\Me\Downloads\sample.exe" --json
antios virus-scan "C:\Users\Me\Downloads" --signatures signatures.json --max-mb 64 --max-files 200000

antios quarantine list --json
antios quarantine add "C:\Users\Me\Downloads\sample.exe"
antios quarantine add "C:\Users\Me\Downloads\sample.exe" --yes
antios quarantine restore ITEM_ID
antios quarantine restore ITEM_ID --yes
antios quarantine restore ITEM_ID --to "C:\Users\Me\Recovered\sample.exe" --yes

antios defender quick
antios defender quick --yes
antios defender full --yes
antios defender update --yes
```

File scanning is read-only. Quarantine and Defender commands preview by default; `--yes` performs the operation. `quarantine add` rescans one file immediately before checking its eligibility. Parent directories for alternate restore destinations must already exist. Encrypted quarantine requires Windows.

`virus-scan` exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Provider and signature scans completed without findings, skips or errors |
| 1 | At least one threat or review finding; inspect coverage too |
| 2 | Invalid input or command failure |
| 3 | No findings, but limited/incomplete coverage, cancellation or an empty scan |

## Local signatures

Import only a database you trust. This is a local exact-hash list, not an independently verified public malware feed. JSON schema:

```json
{
  "schema": 1,
  "sha256": {
    "64_HEXADECIMAL_CHARACTERS_HERE": "Detection label"
  }
}
```

Replace the illustrative key with an actual 64-character SHA-256 digest. The loader refuses malformed hashes, empty/oversized labels, oversized input and more than 100,000 entries. No network lookup or automatic feed update is performed by AntiOS.

## Limits and recovery

- Default: 32 MiB per file, 100,000 files and 200,000 traversed directory entries. CLI permits up to 256 MiB per file and 1,000,000 files.
- Symlinks, junctions and reparse points are not followed; inaccessible, oversized and special files are reported. Quarantine storage is excluded.
- Archives are submitted as raw buffers, never unpacked. There is no recursive archive, memory, boot-sector or kernel scan in AntiOS.
- No independent real-time interception or behavioral ransomware protection is provided. Keep an installed antivirus active.
- Current-user DPAPI authenticates file contents and metadata together. Preserve the Windows account profile and quarantine directory if you need recovery.
- The original is removed only after a durable encrypted copy is verified and the isolated source is rechecked. Errors can leave an encrypted recovery item while the original remains in place. If rollback cannot reclaim its original path, the error names the staged `.antios-isolate-*` file and backup ID; preserve both until reviewed.
- A failed restore keeps its encrypted backup. It can leave a partially written destination; review or choose another destination before retrying. AntiOS never overwrites that destination.

Native API references: [AMSI scan buffer](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer), [AMSI results](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result), [DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata), [Start-MpScan](https://learn.microsoft.com/en-us/powershell/module/defender/start-mpscan), [Update-MpSignature](https://learn.microsoft.com/en-us/powershell/module/defender/update-mpsignature).

## Stopping scans and startup permissions

Windows EXEs request UAC Administrator consent before startup. The Python dashboard also requests elevation; cancelling consent cancels launch. Supplying a different administrator account uses that account's settings and DPAPI quarantine, not the original user's vault.

The GUI file scanner runs in a separate read-only process. **Stop** terminates that process, even during a blocked file read or AMSI call. Completed checkpoints are retained; the interrupted file and work since the last checkpoint are not counted as checked. Cancelled reports always have limited coverage. The app waits for the worker to exit before enabling another operation. Closing the window also cancels the file scan. This does not stop independent Microsoft Defender scans, quarantine or restoration.

Executables use directory bundles so elevated launches do not extract executable dependencies into a temporary directory. Keep `_gui` and `_cli` with their EXEs.

## Packaged antivirus validation

CI runs `scripts/smoke-antivirus.py` against both the installed wheel CLI and
frozen CLI. It checks a harmless file and then detects that same file using a
temporary local SHA-256 rule. This checks packaging and detection plumbing; it
is not a malware effectiveness test. The fixture must remain unchanged.

Hosted runners may have no working AMSI provider. In that case the packaging
check accepts only an explicit limited/incomplete result with exit code 3 and
writes a warning and job summary. This is not evidence of working native
antivirus scanning.

Before a release, run the following from an elevated terminal on a Windows
machine with a working, enabled AMSI provider:

```powershell
python scripts/smoke-antivirus.py .\AntiOS.exe --require-amsi
if ($LASTEXITCODE -ne 0) { throw "Native antivirus validation failed" }
```

Strict mode requires successful provider coverage, no errors, and the expected
benign verdict. Separately validate EICAR through the installed provider in a
controlled test environment and record whether the resident antivirus blocks
file creation before AntiOS can read it. The local hash fixture alone does not
validate provider detection. Do not disable Defender to make this test pass.
