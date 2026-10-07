# Register or remove the AntiOS AMSI coexistence provider.
# This script never changes Defender, Windows Security registration or AMSI FeatureBits.
[CmdletBinding()]
param(
    [string]$ProviderDll = (Join-Path $PSScriptRoot 'AntiOS-AmsiProvider.dll'),
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

function Open-Registry64 {
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )
}

function Remove-Registry64Tree([string]$SubKey) {
    $base = Open-Registry64
    try {
        $base.DeleteSubKeyTree($SubKey, $false)
    } finally {
        $base.Dispose()
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
        Remove-Registry64Tree "SOFTWARE\Microsoft\AMSI\Providers\$ProviderClsid"
        Remove-Registry64Tree "SOFTWARE\Classes\CLSID\$ProviderClsid"
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
    $base = Open-Registry64
    try {
        $class = $base.CreateSubKey("SOFTWARE\Classes\CLSID\$ProviderClsid", $true)
        try {
            $class.SetValue('', 'AntiOS ClamAV Coexistence Provider', [Microsoft.Win32.RegistryValueKind]::String)
        } finally {
            $class.Dispose()
        }

        $inproc = $base.CreateSubKey("SOFTWARE\Classes\CLSID\$ProviderClsid\InprocServer32", $true)
        try {
            $inproc.SetValue('', $dll, [Microsoft.Win32.RegistryValueKind]::String)
            $inproc.SetValue('ThreadingModel', 'Both', [Microsoft.Win32.RegistryValueKind]::String)
        } finally {
            $inproc.Dispose()
        }

        $provider = $base.CreateSubKey("SOFTWARE\Microsoft\AMSI\Providers\$ProviderClsid", $true)
        try {
            $provider.SetValue('', 'AntiOS ClamAV Coexistence Provider', [Microsoft.Win32.RegistryValueKind]::String)
        } finally {
            $provider.Dispose()
        }
    } finally {
        $base.Dispose()
    }
}

if ($Json) {
    $result | ConvertTo-Json -Depth 5
} else {
    [pscustomobject]$result | Format-List
}
