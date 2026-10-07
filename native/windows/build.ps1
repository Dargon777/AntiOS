# Unsigned experimental builds only. No installation, signing or Windows policy changes.
[CmdletBinding()]
param(
    [ValidateSet('Service','Driver','Amsi','All')][string]$Target = 'All',
    [string]$Packages = "$PSScriptRoot\..\..\build\native\packages",
    [switch]$Restore
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not [Environment]::Is64BitProcess) { throw 'Use x64 PowerShell.' }
$version = '10.0.26100.2454'
$kit = '10.0.26100.0'
$out = [IO.Path]::GetFullPath("$PSScriptRoot\..\..\build\native\windows")
New-Item -ItemType Directory -Force $out | Out-Null
$Packages = [IO.Path]::GetFullPath($Packages)
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'Install Visual Studio C++ x64 build tools.' }
    $setup = Join-Path $vs 'Common7\Tools\VsDevCmd.bat'
    # Import the compiler environment into this process, without changing machine settings.
    & $env:ComSpec /d /s /c "`"$setup`" -arch=x64 -host_arch=x64 >nul && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
    }
    if ($LASTEXITCODE) { throw 'Could not initialize the MSVC environment.' }
}
function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
if ($Restore) {
    Invoke-Checked -Program 'nuget.exe' -Arguments @('install','Microsoft.Windows.WDK.x64','-Version',$version,
        '-Source','https://api.nuget.org/v3/index.json','-OutputDirectory',$Packages,'-NonInteractive')
}
Push-Location $out
try {
    if ($Target -in @('Service','All')) {
        Invoke-Checked -Program 'rc.exe' -Arguments @('/nologo','/fo','service.res',"$PSScriptRoot\service\service.rc")
        Invoke-Checked -Program 'cl.exe' -Arguments @('/nologo','/TC','/W4','/WX','/O2','/MT','/guard:cf','/DUNICODE','/D_UNICODE',
            '/D_WIN32_WINNT=0x0A00','/D_CRT_SECURE_NO_WARNINGS',
            "$PSScriptRoot\service\main.c","$PSScriptRoot\service\userscan.c",
            "$PSScriptRoot\service\engine_peer.c","$PSScriptRoot\engine\protocol.c","$PSScriptRoot\engine\clamd.c",
            '/Fe:AntiOS-Service.exe','/link','service.res','fltlib.lib','ws2_32.lib','iphlpapi.lib','advapi32.lib','/DYNAMICBASE','/NXCOMPAT','/guard:cf')
        Invoke-Checked -Program 'cl.exe' -Arguments @('/nologo','/TC','/W4','/WX','/O2','/MT',"$PSScriptRoot\..\tests\inert_program.c",'/Fe:Native-Inert.exe')
    }
    if ($Target -in @('Amsi','All')) {
        Invoke-Checked -Program 'cl.exe' -Arguments @('/nologo','/TP','/c','/EHsc','/std:c++17','/W4','/WX','/O2','/MT','/guard:cf',
            '/DUNICODE','/D_UNICODE','/D_WIN32_WINNT=0x0A00',
            "$PSScriptRoot\amsi\provider.cpp",'/Fo:amsi-provider.obj')
        Invoke-Checked -Program 'cl.exe' -Arguments @('/nologo','/TC','/c','/W4','/WX','/O2','/MT','/guard:cf',
            '/DUNICODE','/D_UNICODE','/D_WIN32_WINNT=0x0A00','/D_CRT_SECURE_NO_WARNINGS',
            "$PSScriptRoot\service\engine_peer.c",'/Fo:amsi-engine-peer.obj')
        Invoke-Checked -Program 'cl.exe' -Arguments @('/nologo','/TC','/c','/W4','/WX','/O2','/MT','/guard:cf',
            '/D_WIN32_WINNT=0x0A00','/D_CRT_SECURE_NO_WARNINGS',
            "$PSScriptRoot\engine\protocol.c",'/Fo:amsi-protocol.obj')
        Invoke-Checked -Program 'cl.exe' -Arguments @('/nologo','/TC','/c','/W4','/WX','/O2','/MT','/guard:cf',
            '/D_WIN32_WINNT=0x0A00','/D_CRT_SECURE_NO_WARNINGS',
            "$PSScriptRoot\engine\clamd.c",'/Fo:amsi-clamd.obj')
        Invoke-Checked -Program 'link.exe' -Arguments @('/nologo','/dll','/out:AntiOS-AmsiProvider.dll',
            'amsi-provider.obj','amsi-engine-peer.obj','amsi-protocol.obj','amsi-clamd.obj',
            'ws2_32.lib','iphlpapi.lib','advapi32.lib','ole32.lib','/EXPORT:DllGetClassObject,PRIVATE','/EXPORT:DllCanUnloadNow,PRIVATE','/DYNAMICBASE','/NXCOMPAT','/guard:cf')
    }
    if ($Target -in @('Driver','All')) {
        $wdk = Join-Path $Packages "Microsoft.Windows.WDK.x64.$version\c"
        $sdk = Join-Path $Packages "Microsoft.Windows.SDK.CPP.$version\c"
        if (-not (Test-Path "$wdk\Include\$kit\km\fltKernel.h")) { throw 'Missing pinned WDK. Run with -Restore.' }
        Invoke-Checked -Program 'rc.exe' -Arguments @('/nologo','/fo','filter.res',"$PSScriptRoot\filter\avscan.rc")
        $objects = @('filter.res')
        foreach ($source in (Get-ChildItem "$PSScriptRoot\filter\*.c")) {
            $object = "$($source.BaseName)-kernel.obj"
            Invoke-Checked -Program 'cl.exe' -Arguments @('/nologo','/TC','/c','/kernel','/W4','/O2','/GS','/guard:cf','/Zp8',
                '/D_AMD64_','/D_KERNEL_MODE','/D_WIN64','/D_WIN32_WINNT=0x0A00','/DNTDDI_VERSION=0x0A00000C',
                "/I$wdk\Include\$kit\km", "/I$wdk\Include\$kit\km\crt", "/I$sdk\Include\$kit\shared",
                "/I$PSScriptRoot\inc", "/Fo$object",$source.FullName)
            $objects += $object
        }
        Invoke-Checked -Program 'link.exe' -Arguments (@('/nologo','/driver','/subsystem:native','/entry:GsDriverEntry','/nodefaultlib',
            '/DYNAMICBASE','/NXCOMPAT','/guard:cf','/INTEGRITYCHECK','/out:AntiOS-Filter.sys',
            "/libpath:$wdk\Lib\$kit\km\x64",'ntoskrnl.lib','fltMgr.lib','hal.lib','bufferoverflowfastfailk.lib') + $objects)
    }
    Copy-Item "$PSScriptRoot\LICENSE.microsoft" $out -Force
    'EXPERIMENTAL / UNSIGNED. Driver/service/AMSI outputs require the documented signing and deployment gates; Defender remains unchanged.' |
        Set-Content -Encoding utf8 (Join-Path $out 'EXPERIMENTAL.txt')
} finally { Pop-Location }
