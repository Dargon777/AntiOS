# Produces harmless content and a custom ClamAV rule; does not install/reload a database.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$InertExecutable, [Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a new output directory.' }
$bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $InertExecutable).Path)
if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) { throw 'Expected Native-Inert.exe built from native/tests/inert_program.c.' }
$marker = [Text.Encoding]::ASCII.GetBytes('AntiOS harmless native acceptance fixture 08b96ac6')
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$directory = (Resolve-Path -LiteralPath $OutputDirectory).Path
[IO.File]::WriteAllBytes((Join-Path $directory 'clean.exe'), $bytes)
[IO.File]::WriteAllBytes((Join-Path $directory 'marked.exe'), [byte[]]($bytes + $marker))
$hex = [BitConverter]::ToString($marker).Replace('-', '').ToLowerInvariant()
"AntiOS.Native.Lab:0:*:$hex" | Set-Content -Encoding ascii (Join-Path $directory 'native-lab.ndb')
Write-Output 'Generated clean.exe, marked.exe and native-lab.ndb. Load the rule only into the isolated lab ClamD database. Both executables are harmless when built from the supplied source.'
