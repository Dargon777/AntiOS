# AntiOS code-protection model

AntiOS has two different protection problems:

1. **Binary hardening** — make released Windows binaries harder to unpack, patch and
   casually reverse-engineer.
2. **Intellectual-property secrecy** — keep genuinely proprietary algorithms and
   commercial logic out of the public source tree entirely.

They are not the same thing.

## Current public code

The AntiOS v2 source tree already published under Apache-2.0 remains available
under that license. A compiled or obfuscated executable cannot make already
published source secret again.

For that reason, binary hardening must not be described as encryption or as a
guarantee that code cannot be recovered.

## Hardened Windows build

The hardened build uses Nuitka standalone compilation for the AntiOS CLI, GUI
and Resident Guard.

The goals are:

- compile Python program logic through native C/C++ compilation instead of
  shipping the normal PyInstaller PYZ bytecode archive;
- avoid loose `.py` and `.pyc` files in release output;
- retain Windows version metadata, UAC requirements, icons and package data;
- keep the release testable with the same CLI/GUI/Guard smoke paths;
- publish a SHA-256 hardening manifest for generated executables.

This raises the cost of reverse engineering. It does **not** make the program
cryptographically impossible to inspect.

## Proprietary boundary

Future AntiOS know-how that must remain secret should not be committed to this
public repository.

Examples include:

- Causal Behavior Fingerprint / CBF scoring and learned models;
- Business / EDR fleet correlation;
- commercial policy engines;
- license validation implementation details;
- cloud-side detection and response logic.

These components should live in a separate private repository or private build
pipeline and expose only a narrow, versioned interface to the Apache-2.0 core.

A suggested split is:

```
AntiOS public core
  UI / updater / open scanner integrations / public protocols
       |
       +-- signed narrow interface
               |
               +-- AntiOS Proprietary Engine
                   CBF / EDR / commercial correlation
```

## What not to do

AntiOS should not rely on anti-debugger tricks, hidden persistence, process
injection, Defender bypasses, kernel stealth or similar techniques to protect
its code. Apart from product and trust problems, those techniques resemble the
behavior endpoint-security software is supposed to detect.

## Stronger commercial protection later

For Business/Pro builds the useful layers are:

- private proprietary source;
- native compilation;
- Authenticode signing;
- signed release/integrity manifests;
- per-customer build/license identity for leak attribution;
- server-side logic for fleet correlation and licensing;
- trademark protection for AntiOS / DargonITP branding.

No client-side scheme should be treated as absolute secrecy: if code executes
on a customer's computer, a sufficiently capable analyst can eventually study
it. The objective is to raise cost, detect tampering and keep the most valuable
logic off the client whenever possible.
