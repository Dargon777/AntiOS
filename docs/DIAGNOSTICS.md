# AntiOS Diagnostics Center

The **Antivirus → Error journal** button (or **Ctrl+Shift+D** anywhere in the dashboard) opens a searchable, read-only diagnostic console. It does **not** launch PowerShell, execute event content or require administrator rights.

## Workflows

- Filter by severity, component, message and event code; F5 refreshes the view and an open console also refreshes automatically.
- Select an event for a plain-language explanation and recommended action, or switch to Technical data for the structured event.
- Copy the selected event in a redacted format.
- Export report writes a ZIP with README.txt, summary.json and events.json. Review the ZIP before sharing.

A scanner error does not become a clean/protected status merely because it was logged.

## Event storage

- Current-user local state: %LOCALAPPDATA%/AntiOS/Diagnostics/events-PID.jsonl on Windows.
- Per-process files roll over at approximately 1 MiB. Readers inspect at most 24 recent files, 1 MiB per file, returning up to 1000 events.
- Logging is best effort. Unavailable/tampered storage must not stop scanning or crash the dashboard.
- Events contain a UTC timestamp, severity, component, code, message, sanitized technical details, and small allowlisted context.
- Guard state changes and distinct ClamAV probe failures are recorded without flooding the journal.
- The dashboard captures antivirus actions, failed operations and scan completion. CLI and separate Guard processes capture their errors when they run under the same user identity.
- Other Windows accounts and services may use different user profiles; the UI does not pretend to collect privileged service logs outside its identity.
- An elevated Windows process **does not write** its default diagnostics to the interactive user's writable LocalAppData folder, because a low-privilege user could otherwise redirect the administrator's file writes. The ordinary GUI records the error returned by a privileged maintenance operation. Elevated CLI processes only return their normal console/JSON status; a future machine-wide event collector will require its own protected directory and explicit IPC/access rules.
- The legacy configurable CLI file logger also refuses arbitrary file writes while elevated, rather than opening user-supplied paths with administrator permissions. Normal-user file logging remains available.

## Security and privacy

The journal deliberately excludes user configuration files, quarantined content, sampled files, memory images, and arbitrary subprocess output. Credential-like assignments, Authorization bearer headers, URL secrets and email addresses are sanitized before being persisted. Exports additionally redact home-directory usernames, absolute filesystem paths (including custom drives/UNC shares), and contain only limited OS/version metadata. **Always review an exported support ZIP before sharing**; arbitrary error text can still include unrecognized private information.

The panel does not execute shell commands or disable Authenticode/UAC. If clamd.exe or freshclam.exe cannot be authenticated, the dedicated ENGINE_SIGNATURE_INVALID event suggests the explicit Repair protection flow, never skipping signature checks.

## Testing

Tests in tests/test_diagnostics.py cover event format and bounds, failures writing logs, secret masking, support ZIP contents, Authenticode classification and (on machines with a display) native Tk filters, detail view, copy and lifecycle.
