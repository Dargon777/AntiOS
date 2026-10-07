# Register or remove the AntiOS AMSI coexistence provider.
# This script never changes Defender, Windows Security registration or AMSI FeatureBits.
[CmdletBinding()]
param(
    [string]$ProviderDll = (Join-Path $PSScriptRoot '..\..\..\build\native\windows\AntiOS-AmsiProvider.dll'),
    [switch]$Uninstall,
    [switch]$Apply,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ProviderClsid = '{8E8A9D7D-814F-4A83-A127-8C4894E41121}'
$ProviderKey = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\$ProviderClsid"
$ClassKey = "HKLM:\SOFTWARE\Classes\CLSID\$ProviderClsid"
$InprocKey = Join-Path $ClassKey 'InprocServer32'

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required to register an AMSI provider.'
    }
}

$result = [ordered]@{
    schema = 1
    kind = 'antios-amsi-provider-registration'
    clsid = $ProviderClsid
    action = if ($Uninstall) { 'uninstall' } else { 'install' }
    dry_run = -not [bool]$Apply
    defender = 'unchanged'
    windows_security_center = 'unchanged'
    amsi_feature_bits = 'unchanged'
    provider = $null
    signature = $null
}

if ($Uninstall) {
    if ($Apply) {
        Assert-Administrator
        Remove-Item -LiteralPath $ProviderKey -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ClassKey -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($Json) { $result | ConvertTo-Json -Depth 5 } else { [pscustomobject]$result | Format-List }
    return
}

$dll = (Resolve-Path -LiteralPath $ProviderDll).Path
if ([IO.Path]::GetFileName($dll) -ne 'AntiOS-AmsiProvider.dll') {
    throw 'Expected AntiOS-AmsiProvider.dll.'
}
$signature = Get-AuthenticodeSignature -LiteralPath $dll
$result.provider = $dll
$result.signature = [ordered]@{
    status = [string]$signature.Status
    signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    thumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
}

# Production registration is deliberately stricter than Windows' default AMSI
# configuration. We do not weaken FeatureBits to permit an unsigned provider.
if ($signature.Status -ne 'Valid') {
    throw 'AMSI provider registration requires a valid Authenticode signature. AntiOS will not weaken AMSI signature policy.'
}

if ($Apply) {
    Assert-Administrator
    New-Item -Path $InprocKey -Force | Out-Null
    Set-Item -LiteralPath $ClassKey -Value 'AntiOS ClamAV Coexistence Provider'
    Set-Item -LiteralPath $InprocKey -Value $dll
    New-ItemProperty -LiteralPath $InprocKey -Name 'ThreadingModel' -PropertyType String -Value 'Both' -Force | Out-Null
    New-Item -Path $ProviderKey -Force | Out-Null
    Set-Item -LiteralPath $ProviderKey -Value 'AntiOS ClamAV Coexistence Provider'
}

if ($Json) {
    $result | ConvertTo-Json -Depth 5
} else {
    [pscustomobject]$result | Format-List
}
