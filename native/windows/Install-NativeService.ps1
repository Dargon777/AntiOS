# Service only. The reviewed/signed driver package must already be installed in a disposable VM.
# No Defender changes, auto-start, driver installation or PPL claim.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SignedExecutable,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$SignerThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_-]{1,80}$')][string]$EngineServiceName,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not [Environment]::Is64BitProcess) { throw 'Use x64 PowerShell.' }
$source = (Resolve-Path -LiteralPath $SignedExecutable).Path
$signature = Get-AuthenticodeSignature -LiteralPath $source
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $SignerThumbprint) {
    throw 'The executable must have a valid Authenticode signature from the explicitly expected publisher certificate.'
}
$destination = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AntiOSNative'
$binary = Join-Path $destination 'AntiOS-Service.exe'
if (Get-Service -Name AntiOSNative -ErrorAction SilentlyContinue) { throw 'Service already exists. Stop and remove the old lab install explicitly before replacing it.' }
if (Test-Path -LiteralPath $destination) { throw 'Destination already exists; refusing to overwrite or follow an existing directory/reparse point.' }
if (-not (Get-Service -Name AntiOS-Filter -ErrorAction SilentlyContinue)) { throw 'Install the reviewed/signed driver package first.' }
$driverParameters = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\AntiOS-Filter\\Parameters'
$coexistence = Get-ItemPropertyValue -Path $driverParameters -Name CoexistenceMode -ErrorAction Stop
$maxPending = Get-ItemPropertyValue -Path $driverParameters -Name MaxPendingScans -ErrorAction Stop
$cleanCacheTtl = Get-ItemPropertyValue -Path $driverParameters -Name CleanCacheTtlMs -ErrorAction Stop
if ([int]$coexistence -ne 1) { throw 'AntiOS native service requires CoexistenceMode=1.' }
if ([int]$maxPending -lt 1 -or [int]$maxPending -gt 4) { throw 'MaxPendingScans must remain between 1 and the four native broker workers.' }
if ([long]$cleanCacheTtl -lt 0 -or [long]$cleanCacheTtl -gt 300000) { throw 'CleanCacheTtlMs must stay between 0 and 300000 milliseconds.' }
if ($EngineServiceName -in @('AntiOSNative','AntiOS-Filter')) { throw 'Select the actual ClamD service.' }
$engine = Get-CimInstance Win32_Service -Filter "Name='$EngineServiceName'"
if (-not $engine -or $engine.ServiceType -ne 'Own Process' -or $engine.StartName -ne 'LocalSystem') {
    throw 'ClamD must run directly as an own-process LocalSystem service; wrappers/child processes are unsupported.'
}
if (-not $Apply) {
    Write-Output "Ready to install $binary as LocalSystem, manual start, dependent on AntiOS-Filter and $EngineServiceName. CoexistenceMode=$coexistence; MaxPendingScans=$maxPending; CleanCacheTtlMs=$cleanCacheTtl. Rerun with -Apply in the lab VM."
    return
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator rights required.' }
function Run-Sc([string[]]$Arguments) {
    & "$env:SystemRoot\System32\sc.exe" @Arguments
    if ($LASTEXITCODE) { throw "SCM command failed: $($Arguments[0]) ($LASTEXITCODE)" }
}
$created = $false
$directoryCreated = $false
try {
    # Program Files prevents an ordinary user from replacing the new directory during creation.
    New-Item -ItemType Directory -Path $destination -ErrorAction Stop | Out-Null
    $directoryCreated = $true
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)')
    Set-Acl -LiteralPath $destination -AclObject $acl
    Copy-Item -LiteralPath $source -Destination $binary
    # Revalidate the copied bytes; the original source could have changed during the copy.
    $copied = Get-AuthenticodeSignature -LiteralPath $binary
    if ($copied.Status -ne 'Valid' -or $copied.SignerCertificate.Thumbprint -ne $SignerThumbprint) { throw 'Copied signature verification failed.' }
    Run-Sc -Arguments @('create','AntiOSNative','binPath=',('"' + $binary + '"'),'type=','own','start=','demand','obj=','LocalSystem','depend=',('AntiOS-Filter/' + $EngineServiceName))
    $created = $true
    $parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\AntiOSNative\Parameters'
    New-Item -Path $parameters -Force | Out-Null
    New-ItemProperty -Path $parameters -Name EngineServiceName -PropertyType String -Value $EngineServiceName -Force | Out-Null
    Run-Sc -Arguments @('sdset','AntiOSNative','D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCLORC;;;BU)')
    Run-Sc -Arguments @('description','AntiOSNative','Experimental native execute-open scanner; not a registered primary antivirus. Manual start.')
    Write-Output 'Installed but not started. Complete the audit-mode VM acceptance checks before enabling enforcement.'
} catch {
    # No process was started. Undo only resources created by this invocation.
    if ($created) {
        & "$env:SystemRoot\System32\sc.exe" delete AntiOSNative | Out-Null
        if ($LASTEXITCODE) { throw 'Rollback could not delete AntiOSNative; retained its executable. Inspect SCM before removing files.' }
    }
    if ($directoryCreated -and (Test-Path -LiteralPath $destination)) { Remove-Item -LiteralPath $destination -Recurse -Force }
    throw
}
