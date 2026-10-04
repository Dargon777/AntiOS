# Windows code signing

AntiOS has two distribution paths:

1. **Microsoft Store / MSIX** — preferred for ordinary users. The Store signs accepted MSIX packages with a Microsoft-trusted certificate.
2. **Direct GitHub downloads** — the portable EXE files can be signed with Azure Artifact Signing (formerly Trusted Signing).

## Why this matters

An unsigned executable has no stable publisher identity. Microsoft Defender SmartScreen therefore evaluates each new binary mostly by file reputation, so a new release can show an "unrecognized app" warning.

A valid Authenticode signature gives releases a stable publisher identity, but a brand-new non-Store publisher can still need time to build SmartScreen reputation.

The Microsoft Store path avoids that first-download SmartScreen warning because Store packages are signed by Microsoft.

## Direct-download signing with Azure Artifact Signing

The release workflow contains optional signing steps. They remain disabled until the repository variable below is set:

- `ENABLE_ARTIFACT_SIGNING=true`

Configure these GitHub repository variables:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`
- `ARTIFACT_SIGNING_ENDPOINT`
- `ARTIFACT_SIGNING_ACCOUNT`
- `ARTIFACT_SIGNING_PROFILE`

The workflow uses GitHub OIDC through `azure/login`; no long-lived Azure client secret is required.

The Azure identity must have the **Artifact Signing Certificate Profile Signer** role for the selected certificate profile.

When enabled, CI:

1. builds `AntiOS.exe` and `AntiOS-GUI.exe`;
2. authenticates to Azure with OIDC;
3. signs both EXE files with SHA-256;
4. adds an RFC 3161 timestamp;
5. verifies both Authenticode signatures before packaging;
6. publishes the signed binaries inside the normal release ZIP.

## Microsoft Store

See [../store/README.md](../store/README.md).

The Store package contains the antivirus GUI, including confirmed quarantine and restore. Advanced CLI commands remain outside the package. Startup elevation declares `allowElevation`, a restricted capability requiring separate Microsoft approval before Store distribution.

## Local verification

```powershell
Get-AuthenticodeSignature .\AntiOS-GUI.exe |
  Format-List Status,StatusMessage,SignerCertificate,TimeStamperCertificate

Get-AuthenticodeSignature .\AntiOS.exe |
  Format-List Status,StatusMessage,SignerCertificate,TimeStamperCertificate
```

A production-signed direct build should report `Status : Valid`.

## Development certificates

Do not distribute self-signed certificates as a way to suppress warnings. They are appropriate only for local/test machines where the certificate is deliberately installed into a trust store.

## DargonITP identity and the current alpha

`CompanyName`, product metadata, the dashboard and the default MSIX publisher display name are **DargonITP**. The reserved package identity and certificate subject GUID are unchanged. Confirm the display name against Partner Center before submitting.

These resource strings are not a digital signature. Windows derives the verified publisher in UAC from the trusted Authenticode signing certificate, not CompanyName. Configure the signing service using an identity verified for the intended publisher; the repository cannot manufacture a trusted DargonITP certificate. Until then builds remain unsigned and may show Unknown Publisher / SmartScreen warnings. Even a valid signature does not guarantee immediate SmartScreen reputation. BUILD_INFO records the actual signature status of the packaged GUI.

The existing Azure signing path runs on master pushes when configured. Pull request artifacts remain unsigned. Store packaging success is not certification or publication, and `allowElevation` requires Microsoft's approval. Never disable SmartScreen or install a self-signed root certificate to make a public build appear trusted.

References: [SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation), [restricted elevation capability](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations#restricted-capability-list).

## Publishing signing or validation fixes

An existing release is not overwritten by the workflow. After validating fixes,
advance the package/release versions, release tag, Windows version resources and
Store version together before publishing new downloads. Re-running alpha 11
only produces workflow artifacts; it does not repair its existing assets.

Configure the Azure variables and certificate profile before enabling signing.
An unsigned CI build remains a development artifact even when its metadata says
DargonITP. Confirm `Valid` on both released executables, not just a successful CI
job or a GitHub provenance attestation.
