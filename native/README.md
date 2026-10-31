# Experimental native protection

This tree contains experimental native Windows protection components used for research and validation.

They are **not** documented as production-certified primary antivirus protection and are not a substitute for Microsoft-required signing, compatibility validation, Driver Verifier/HVCI testing, performance testing and independent security review.

## Public scope

The native layer is intended to explore earlier interception and stronger protection coverage than user-mode post-write monitoring alone.

## Security documentation policy

Public documentation intentionally omits driver/broker protocol fields, minifilter configuration, queue limits, timeout behavior, cache semantics, fail-open/fail-closed conditions, telemetry counters, worker counts, service identities, test-fixture internals and enforcement decision flow.

Because the repository source is public, these omissions are not claimed as cryptographic secrecy. They simply avoid maintaining a ready-made attacker-oriented architecture map in user-facing documentation.
