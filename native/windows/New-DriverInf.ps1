[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^32[0-9]{4}(\.[0-9]+)?$')][string]$AssignedAltitude,
    [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
# Numeric validation is not evidence that Microsoft assigned this altitude to AntiOS.
# The operator must supply the actual allocation; no borrowed/default sample altitude.
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$template = Get-Content -Raw "$PSScriptRoot\AntiOS-Filter.inf.in"
$template.Replace('@ALTITUDE@', $AssignedAltitude).Replace('@DATE@', (Get-Date -Format 'MM/dd/yyyy')) |
    Set-Content -Encoding ascii (Join-Path $OutputDirectory 'AntiOS-Filter.inf')
Write-Output 'INF generated in audit/manual-start mode. Catalog, driver signing and INF validation are still required.'
