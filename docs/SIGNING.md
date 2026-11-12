# Signing and release trust

AntiOS release channels have different trust properties.

## Direct GitHub releases

Prerelease Windows binaries can be unsigned. When a release is unsigned, GitHub SHA-256 files verify file integrity but do **not** prove publisher identity.

Signed direct-download builds should be verified with Windows Authenticode in addition to checksum and provenance metadata.

## Microsoft Store

The Store package is built as an MSIX submission artifact. Microsoft signs accepted Store packages as part of the Store distribution process.

## Updates

An update that cannot be verified should not be treated as trusted just because it came from a familiar URL or filename.

Always read the release notes for the signing status of the build you are installing.

## Verifying an unsigned prerelease

Unsigned prerelease assets can be attached to an existing empty release draft only
by the Release workflow running from `master`. Before updating the draft, the
workflow compares embedded build metadata and GitHub attestations against the
**exact commit SHA and master ref** for Windows Setup, Windows portable ZIP,
Linux archive and both Python distributions.

For a downloaded file, first compare its SHA-256 with the accompanying `.sha256`
file when available (integrity only). Then check the corresponding release notes
for the build commit and use GitHub CLI:

```bash
gh attestation verify ./AntiOS-Setup.exe \
  --repo Dargon777/AntiOS \
  --signer-workflow Dargon777/AntiOS/.github/workflows/release.yml \
  --source-ref refs/heads/master \
  --source-digest EXPECTED_40_CHARACTER_COMMIT_SHA
```

Repeat the attestation verification for each downloaded binary or archive.
GitHub Attestations verify build provenance, **not** Windows publisher identity
and **not** the security of the software itself. Unverified files should not be
installed as updates. Windows SmartScreen may warn about unsigned files, and
Smart App Control may block them. Automatic installation of updates still
requires a verified publisher signature.

The workflow **never publishes a draft automatically**. A maintainer must
review the artifacts and explicitly publish the prerelease.
