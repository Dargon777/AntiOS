# Behavior monitoring

AntiOS Resident Guard includes a bounded, explainable behavior-correlation layer.
It is **detection-only**. A behavioral signal never terminates a process, deletes
a file, quarantines a file, disables Microsoft Defender, or claims that a file is
malware.

The goal is to connect weak local signals into useful context while keeping the
actual malware verdict and pre-execution enforcement paths separate.

## Inputs

### File-change events

Resident Guard feeds explicit file-change notification paths into the behavior
engine. Only paths inside the selected Guard roots are observed. Notification
overflow/reset events are not converted into fake per-file behavior events
because the exact changed files are unknown.

### Process starts on Windows

The Windows collector uses the documented Tool Help process snapshot APIs:

- `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`
- `Process32FirstW` / `Process32NextW`
- `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`
- `QueryFullProcessImageNameW`

The collector polls every 500 ms. The first snapshot is a baseline and does not
emit findings for already-running processes. Full executable paths are queried
only for newly observed PIDs, so systems with many processes do not perform a
full path lookup for every process twice per second.

The collector does **not** inject into processes, read their memory, install a
kernel hook, change audit policy, or depend on Defender internals.

## Rules

| Rule | Score | Default severity | Meaning |
| --- | ---: | --- | --- |
| `document-spawns-interpreter` | 85 | high | Office/PDF application starts PowerShell, cmd, WSH, mshta, rundll32 or regsvr32 |
| `browser-spawns-interpreter` | 80 | high | Browser starts one of the same interpreter/LOLBin processes |
| `user-writable-execution` | 45 | low | Executable/script starts directly from Downloads or user Temp |
| `changed-then-executed` | 75 | high | Exact executable/script path was changed and then executed within the correlation window |
| `mass-file-changes` | 80 | high | At least 40 distinct watched paths changed inside 10 seconds |
| `interpreter-with-mass-file-changes` | 95 | critical | Script host/interpreter is observed while mass file changes are occurring |

A single launch from Downloads/Temp is deliberately below the UI attention
threshold. Legitimate installers commonly do that. It becomes more meaningful
when combined with a recent write, suspicious parent, or mass file activity.

## Windows and bounds

Defaults:

- general correlation window: 30 seconds;
- mass-change window: 10 seconds;
- mass-change threshold: 40 distinct paths;
- duplicate-finding suppression: 60 seconds per rule + subject;
- recent process ring: 512 entries;
- recent file-change ring: 4096 entries;
- retained behavior findings: 100 entries;
- Guard journal: existing bounded 1000-event store.

These limits make memory consumption deterministic.

## State model

The behavior status is embedded in Guard status:

```json
{
  "behavior": {
    "state": "normal",
    "mode": "detect-only",
    "collector": "toolhelp-snapshot",
    "process_events": 42,
    "file_events": 17,
    "recent_findings": 0,
    "highest_score": 0,
    "collector_errors": 0
  }
}
```

State mapping:

- `normal`: highest recent score below 60;
- `attention`: score 60-89;
- `alert`: score 90+.

If the Windows process collector fails, Guard falls back to
`file-correlation-only` rather than failing resident antivirus scanning.

Behavior findings are written to the Guard journal as `behavior-alert` events.

## Relationship to antivirus verdicts

Behavior findings are **not** ClamAV findings. They are contextual signals.

- ClamAV/native verdicts determine whether content is known malicious.
- Native minifilter enforcement is the only AntiOS pre-execution blocking path.
- Guard confirmed-threat quarantine remains based on scanner findings and the
  user's explicit auto-quarantine policy.
- Behavior signals can make the UI show attention, but never enter automatic
  quarantine on their own.

This separation is intentional to limit false-positive damage.

## Known limitations

Tool Help snapshots are intentionally simple and low-risk, but they are not a
full EDR event stream:

- very short-lived processes can start and exit between 500 ms snapshots;
- command lines are not collected;
- parent relationships are PID-based and can become ambiguous around rare PID
  reuse races;
- file behavior only covers configured Guard roots;
- process ancestry is observational and does not prove malicious intent.

Those limitations are surfaced by describing the feature as behavior
**monitoring/correlation**, not complete process telemetry.

A future collector may use a supported ETW/Event Log source when that can be
added without requiring unsafe hooks or weakening Windows security controls.


## Risk fusion

Path-specific behavior findings can feed the separate
[RiskContext](RISK.md) decision layer after an antivirus scan. RiskContext uses
only fresh findings whose subject exactly matches the scanned path; a global
behavior alert is not blindly assigned to every unrelated file.

Behavior-only evidence remains review-only regardless of score. Automatic
enforcement eligibility still requires a confirmed scanner threat.
