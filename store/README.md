# AntiOS Microsoft Store package

The Store edition is intentionally the **read-only AntiOS GUI**.

It does not package the advanced CLI, so Microsoft Store users receive the consumer health/privacy dashboard without the CLI's administrator-only metadata write commands.

## Why MSIX

Microsoft Store distribution gives AntiOS:

- a trusted Microsoft signature after certification;
- clean install/uninstall;
- Store-managed updates;
- package identity;
- no first-download SmartScreen warning for the Store-delivered package.

## Partner Center values required

After reserving the AntiOS app name in Partner Center, copy these exact values from **Product identity**:

- Package/Identity/Name
- Package/Identity/Publisher
- Publisher display name

Do not guess these values. The Store validates them exactly.

## Build

First build the GUI executable:

```powershell
pyinstaller --clean --noconfirm --onefile --windowed --name AntiOS-GUI antios_gui_entry.py
```

Then:

```powershell
.\scripts\build-store-msix.ps1 `
  -IdentityName "VALUE_FROM_PARTNER_CENTER" `
  -Publisher "VALUE_FROM_PARTNER_CENTER" `
  -PublisherDisplayName "Dargon777" `
  -PackageVersion "2.0.9.0"
```

Output:

```text
store-output\AntiOS.msix
```

The fourth version component is kept at `.0` for Store submission.

The package is intentionally not production-signed by this script. Microsoft Store signs accepted submissions itself.

## CI

`.github/workflows/store-msix.yml` validates that the Store package can be generated.

On pull requests it uses development identity placeholders. For a real Store package, run the workflow manually and enter the exact Partner Center identity values.

The generated artifact is an input for Partner Center, not a substitute for Store certification.
