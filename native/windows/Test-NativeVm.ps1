# Requires a disposable Windows 11 24H2 x64 NTFS VM and signed, manually installed components.
# Runs ONLY the harmless executable produced from native/tests/inert_program.c.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ServiceExecutable,
    [Parameter(Mandatory)][string]$FixtureDirectory,
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce')][string]$ExpectedMode,
    [Parameter(Mandatory)][string]$ReportPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$exe = (Resolve-Path -LiteralPath $ServiceExecutable).Path
$fixtures = (Resolve-Path -LiteralPath $FixtureDirectory).Path
$report = [ordered]@{ utc = [DateTime]::UtcNow.ToString('o'); mode = $ExpectedMode; passed = $false }
function Driver-Status {
    $json = & $exe --driver-status
    if ($LASTEXITCODE) { throw 'Driver diagnostics failed; run elevated and confirm filter load.' }
    return $json | ConvertFrom-Json
}
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NativeExecuteOpen {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr CreateFileMapping(IntPtr file, IntPtr attributes, uint protect, uint maxHigh, uint maxLow, string name);
}
'@
try {
    $before = Driver-Status
    if ([int]$before.protocol -lt 2) { throw 'Native protocol v2+ is required.' }
    if ([int]$before.coexistence_mode -ne 1) { throw 'CoexistenceMode must stay enabled during VM acceptance.' }
    if (-not [bool]$before.fail_open_on_incomplete) { throw 'Lab filter must not fail closed on incomplete verdicts.' }
    $enforce = $ExpectedMode -eq 'Enforce'
    if ([bool]$before.enforcement -ne $enforce) { throw 'Actual loaded driver policy differs from requested test mode.' }
    $marked = Join-Path $fixtures 'marked.exe'
    $clean = Join-Path $fixtures 'clean.exe'
    $scan = (& $exe --scan-file-verified $marked) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 1 -or $scan.name -notlike 'AntiOS.Native.Lab*') { throw 'Lab ClamD must detect the harmless custom signature before testing the filter.' }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $handle = [NativeExecuteOpen]::CreateFile($marked, 0x20, 7, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $opened = $handle -ne [IntPtr](-1)
    if ($opened) { [void][NativeExecuteOpen]::CloseHandle($handle) }
    $timer.Stop()
    $report.openMilliseconds = $timer.ElapsedMilliseconds
    $report.openError = if ($opened) { 0 } else { $errorCode }
    if ($timer.ElapsedMilliseconds -gt 20000) { throw 'Execute-open exceeded the lab latency limit.' }
    if ($enforce -and ($opened -or $errorCode -ne 225)) { throw 'Expected ERROR_VIRUS_INFECTED for confirmed detection.' }
    if (-not $enforce -and -not $opened) { throw 'Audit must allow the harmless marked file.' }
    # A FILE_EXECUTE open alone is not proof of coverage of the actual Windows loader.
    $started = $false; $startError = 0
    try {
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $marked; $info.UseShellExecute = $false
        $process = [Diagnostics.Process]::Start($info)
        $started = $true
        if (-not $process.WaitForExit(5000)) { throw 'Unexpected fixture process timeout.' }
        if ($process.ExitCode -ne 0) { throw 'Unexpected fixture exit code.' }
        $process.Dispose()
    } catch [ComponentModel.Win32Exception] { $startError = $_.Exception.NativeErrorCode }
    $report.markedProcessStarted = $started; $report.processError = $startError
    if ($enforce -and ($started -or $startError -ne 225)) { throw 'Actual CreateProcess prevention failed.' }
    if (-not $enforce -and -not $started) { throw 'Audit unexpectedly prevented CreateProcess.' }

    # Exercise image-section mapping separately from CreateProcess. A filter that
    # only happens to catch FILE_EXECUTE opens is not sufficient loader coverage.
    $readHandle = [NativeExecuteOpen]::CreateFile($marked, 0x80000000, 7, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
    if ($readHandle -eq [IntPtr](-1)) { throw 'Could not open marked fixture for image-section test.' }
    $mapping = [IntPtr]::Zero
    try {
        $mapping = [NativeExecuteOpen]::CreateFileMapping($readHandle, [IntPtr]::Zero, (0x01000000 -bor 0x02), 0, 0, $null)
        $mappingError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $mapped = $mapping -ne [IntPtr]::Zero
        $report.markedImageMapped = $mapped
        $report.imageMapError = if ($mapped) { 0 } else { $mappingError }
        if ($enforce -and ($mapped -or $mappingError -ne 225)) {
            throw 'SEC_IMAGE mapping prevention failed; loader coverage is incomplete.'
        }
        if (-not $enforce -and -not $mapped) {
            throw 'Audit unexpectedly prevented SEC_IMAGE mapping.'
        }
    } finally {
        if ($mapping -ne [IntPtr]::Zero) { [void][NativeExecuteOpen]::CloseHandle($mapping) }
        [void][NativeExecuteOpen]::CloseHandle($readHandle)
    }

    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $clean; $info.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($info)
    if (-not $process.WaitForExit(5000) -or $process.ExitCode -ne 0) { throw 'Clean fixture did not complete.' }
    $process.Dispose()
    $after = Driver-Status
    $report.driverBefore = $before; $report.driverAfter = $after
    if ($after.detections -le $before.detections) { throw 'No native detection observed.' }
    if ($enforce -and $after.blocked -le $before.blocked) { throw 'No native block observed.' }
    if (-not $enforce -and $after.blocked -ne $before.blocked) { throw 'Audit recorded an unexpected block.' }
    if ([int]$after.pending -ne 0) { throw 'Native scan queue did not drain.' }
    if ([int]$after.peak_pending -gt [int]$after.max_pending) { throw 'Native scan admission exceeded MaxPendingScans.' }
    if ([long]$after.max_wait_ms -gt 15000) { throw 'Native wait telemetry exceeded the VM latency ceiling.' }
    $report.passed = $true
} catch {
    $report.error = $_.Exception.Message
    throw
} finally {
    $report | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 -LiteralPath $ReportPath
}
