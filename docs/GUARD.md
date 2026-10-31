# Resident Guard

Resident Guard is AntiOS's optional resident protection layer.

## Public behavior

- monitors configured user locations;
- reacts to relevant file activity;
- requests scanning through the available AntiOS protection stack;
- reports detections, errors and incomplete coverage;
- can isolate confirmed threats only according to explicit product policy;
- does not claim complete kernel-level pre-execution blocking.

Guard is designed to fail visibly when protection cannot be established.

## Privacy and coexistence

Guard is local and is intended to coexist with supported security products. AntiOS does not disable Defender or add hidden exclusions as part of normal coexistence.

## Internal design

Public documentation intentionally omits Guard's heartbeat/watchdog behavior, lock/state files, process and task identities, retry timing, event-journal layout, handoff sequencing, collector internals, queue bounds and recovery mechanics.

These details should be discussed only in private engineering documentation.
