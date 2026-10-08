# AntiOS v2.0.0 alpha 24

Alpha 24 fixes a Resident Guard lifecycle deadlock that could survive upgrades.

## Stale Guard recovery

A Guard with a stale heartbeat can still be alive and hold `guard.lock`.
Previous builds marked that state as `unresponsive` / `running=false` before
processing a stop request, so the old run could remain alive while every new
Guard instance failed with an already-running lock.

Alpha 24 now:

- preserves the stale run identity long enough to send a cooperative stop request;
- stops an existing Scheduled Task before replacing its definition;
- terminates only an orphaned `AntiOS-Guard.exe` whose full image path matches
  the managed installation;
- fails explicitly if the previous Guard task cannot be stopped;
- verifies that the replacement task actually remains running.

## Upgrade cleanup

The Windows installer now removes the previous Resident Guard startup task
before replacing binaries and normalizes the task again with the newly
installed script. This is intended to recover machines upgraded from builds
where Guard stop/uninstall was incomplete.

## Startup diagnostics

If Guard fails before it can publish a heartbeat, it writes a bounded
`startup-error.json` in the Guard state directory. Resident startup surfaces a
recent error instead of leaving the UI with only a generic inactive state.

## Release validation

The Windows release workflow now starts the packaged
`AntiOS-Guard.exe run --policy`, waits for a live heartbeat, sends a real stop
request and verifies a clean exit. This covers the resident executable path that
previous release smoke tests did not exercise.

Microsoft Defender configuration remains unchanged.
