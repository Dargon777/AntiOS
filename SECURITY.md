# Security Policy

## Supported versions

AntiOS v2 is pre-release software. Security fixes are made on the latest v2 release line.

| Version | Supported |
| --- | --- |
| 2.0.0 alpha | Yes |
| Legacy v1 | No |

## Reporting a vulnerability

Please avoid posting sensitive exploit details in a public issue.

Preferred reporting route:

1. Use GitHub's private vulnerability reporting / Security Advisory flow for this repository when available.
2. Include the affected version, Windows version/build, reproduction steps, expected behavior, actual behavior, and whether administrator privileges are required.
3. Remove personal identifiers, registry exports, backup files, account data, or other secrets before attaching logs.

AntiOS logs are designed not to include scanned fingerprint values, but users should still review any diagnostic material before sharing it.

## Security boundaries

Advanced identity commands intentionally limit writes to ordinary system metadata:

- `RegisteredOwner` through the Registry;
- computer name through `SetComputerNameExW`.

Identifiers such as `MachineGuid`, `ProductId`, hardware/storage serials, MAC addresses, telemetry/update IDs and similar fingerprint material are read-only or out of scope in v2.

Backup files are treated as untrusted input. Restore ignores Registry paths that are not on the explicit v2 allowlist.

## Antivirus boundaries

On-demand scans are read-only and delegate content detection to the installed Windows AMSI provider. Unavailable providers, scan errors, cancellation and traversal/size limits are reported as incomplete coverage, never as a clean scan. Local signature input is bounded and validated; there is no unsigned automatic signature updater.

Quarantine requires a confirmed finding and revalidates its hash and file identity. Symlinks, Windows reparse points and hard-linked quarantine targets are refused. File content and metadata are authenticated together with current-user DPAPI. A durable decryptable copy is verified before isolating the source; a staged source is rechecked before removal. Restoration uses exclusive creation and refuses existing destinations. Corrupt records cannot be restored. A quarantine transaction that fails may leave a verified encrypted recovery copy; inspect the error before retrying.

AntiOS does not register as a primary Windows Security Center antivirus, install a kernel driver, intercept executions, disable Defender, alter exclusions or provide real-time blocking. AMSI buffer scanning is not a substitute for the installed antivirus's full file/archive engine. The logged-in account and its filesystem permissions are the trust boundary; quarantine is not a sandbox against a malicious process with that user's access.
