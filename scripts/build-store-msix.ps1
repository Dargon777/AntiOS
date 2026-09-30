param(
    [string]$IdentityName = "Dargon777.AntiOS.Development",
    [string]$Publisher = "CN=AntiOS Development",
    [string]$PublisherDisplayName = "Dargon777",
    [string]$PackageVersion = "2.0.9.0",
    [string]$GuiPath = ".\dist\AntiOS-GUI.exe",
    [string]$OutputPath = ".\store-output\AntiOS.msix"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $GuiPath)) {
    throw "GUI executable not found: $GuiPath"
}

if ($PackageVersion -notmatch '^\d+\.\d+\.\d+\.0$') {
    throw "Store package version must be Major.Minor.Build.0"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$templatePath = Join-Path $repoRoot "store\AppxManifest.xml.template"
$stage = Join-Path $repoRoot "store-build"
$assets = Join-Path $stage "Assets"
$output = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputPath))

Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $assets | Out-Null
New-Item -ItemType Directory -Force (Split-Path -Parent $output) | Out-Null

Copy-Item $GuiPath (Join-Path $stage "AntiOS-GUI.exe")
foreach ($doc in @("README.md", "PRIVACY.md", "LICENSE", "NOTICE")) {
    Copy-Item (Join-Path $repoRoot $doc) (Join-Path $stage $doc)
}

Add-Type -AssemblyName System.Drawing

function New-AntiOSAsset {
    param(
        [string]$Path,
        [int]$Width,
        [int]$Height
    )

    $bitmap = New-Object System.Drawing.Bitmap($Width, $Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $graphics.Clear([System.Drawing.Color]::FromArgb(14, 20, 32))

    $size = [Math]::Max(12, [Math]::Floor([Math]::Min($Width, $Height) * 0.48))
    $font = New-Object System.Drawing.Font("Segoe UI", $size, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(110, 168, 254))
    $format = New-Object System.Drawing.StringFormat
    $format.Alignment = [System.Drawing.StringAlignment]::Center
    $format.LineAlignment = [System.Drawing.StringAlignment]::Center

    $rect = New-Object System.Drawing.RectangleF(0, 0, $Width, $Height)
    $graphics.DrawString("A", $font, $brush, $rect, $format)
    $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)

    $format.Dispose()
    $brush.Dispose()
    $font.Dispose()
    $graphics.Dispose()
    $bitmap.Dispose()
}

New-AntiOSAsset (Join-Path $assets "StoreLogo.png") 50 50
New-AntiOSAsset (Join-Path $assets "Square44x44Logo.png") 44 44
New-AntiOSAsset (Join-Path $assets "Square71x71Logo.png") 71 71
New-AntiOSAsset (Join-Path $assets "Square150x150Logo.png") 150 150
New-AntiOSAsset (Join-Path $assets "Wide310x150Logo.png") 310 150
New-AntiOSAsset (Join-Path $assets "Square310x310Logo.png") 310 310

function Escape-XmlAttribute([string]$Value) {
    return [System.Security.SecurityElement]::Escape($Value)
}

$manifest = Get-Content $templatePath -Raw
$manifest = $manifest.Replace("__IDENTITY_NAME__", (Escape-XmlAttribute $IdentityName))
$manifest = $manifest.Replace("__PUBLISHER__", (Escape-XmlAttribute $Publisher))
$manifest = $manifest.Replace("__PUBLISHER_DISPLAY_NAME__", (Escape-XmlAttribute $PublisherDisplayName))
$manifest = $manifest.Replace("__PACKAGE_VERSION__", $PackageVersion)
Set-Content -Path (Join-Path $stage "AppxManifest.xml") -Value $manifest -Encoding UTF8

$kitsRoot = Join-Path ([Environment]::GetFolderPath("ProgramFilesX86")) "Windows Kits\10\bin"
$makeAppx = Get-ChildItem $kitsRoot -Recurse -Filter MakeAppx.exe -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending |
    Select-Object -First 1

if (-not $makeAppx) {
    throw "MakeAppx.exe was not found. Install the Windows SDK."
}

if (Test-Path $output) {
    Remove-Item -Force $output
}

& $makeAppx.FullName pack /d $stage /p $output /o
if ($LASTEXITCODE -ne 0) {
    throw "MakeAppx failed with exit code $LASTEXITCODE"
}

Write-Host "Built Store MSIX: $output"
Write-Host "Identity: $IdentityName"
Write-Host "Publisher: $Publisher"
Write-Host "Version: $PackageVersion"
Write-Host "Package is unsigned; Microsoft Store signs accepted submissions."
