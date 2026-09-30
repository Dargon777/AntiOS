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

AntiOS v2 intentionally limits writes to ordinary system metadata:

- `RegisteredOwner` through the Registry;
- computer name through `SetComputerNameExW`.

Identifiers such as `MachineGuid`, `ProductId`, hardware/storage serials, MAC addresses, telemetry/update IDs and similar fingerprint material are read-only or out of scope in v2.

Backup files are treated as untrusted input. Restore ignores Registry paths that are not on the explicit v2 allowlist.
