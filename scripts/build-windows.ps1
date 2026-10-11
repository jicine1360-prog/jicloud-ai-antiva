param(
    [string]$OutputDirectory = "dist/windows",
    [string]$PythonCommand = "py",
    [string]$PythonVersion = "3"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BuildDirectory = Join-Path $ProjectRoot "build/windows"
$SpecDirectory = Join-Path $BuildDirectory "spec"
$OutputPath = Join-Path $ProjectRoot $OutputDirectory

Set-Location $ProjectRoot

function Invoke-PythonModule {
    param([string]$Module, [string[]]$ModuleArgs)
    if ($PythonVersion) {
        & $PythonCommand -$PythonVersion -m $Module @ModuleArgs
    } else {
        & $PythonCommand -m $Module @ModuleArgs
    }
    if ($LASTEXITCODE -ne 0) {
        throw "python -m $Module exited with code $LASTEXITCODE"
    }
}

Write-Host "Installing build dependencies with $PythonCommand..."
Invoke-PythonModule pip @("install", "--quiet", ".[build]")

foreach ($Tool in @("ai-model-scan", "ai-model-guard")) {
    $EntryPoint = Join-Path $ProjectRoot "scripts/entrypoints/$($Tool -replace '-', '_').py"
    Write-Host "Building $Tool..."
    Invoke-PythonModule PyInstaller @(
        "--noconfirm", "--clean", "--onefile", "--name", $Tool,
        "--paths", "src", "--distpath", $OutputPath,
        "--workpath", $BuildDirectory, "--specpath", $SpecDirectory, $EntryPoint
    )
    Write-Host "Built $Tool"
}

if (-not (Test-Path (Join-Path $OutputPath "ai-model-scan.exe"))) {
    throw "ai-model-scan.exe was not created in $OutputPath"
}

Write-Host "Windows executables built in $OutputPath"