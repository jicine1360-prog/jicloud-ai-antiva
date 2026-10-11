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

$PythonInvocation = @($PythonCommand)
if ($PythonVersion) {
    $PythonInvocation += "-$PythonVersion"
}
$RunPython = {
    param([string[]]$Args)
    & $PythonInvocation @Args
    if ($LASTEXITCODE -ne 0) { throw "python exited with code $LASTEXITCODE" }
}

Set-Location $ProjectRoot
& $RunPython @("-m", "pip", "install", "--quiet", ".[build]")
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

foreach ($Tool in @("ai-model-scan", "ai-model-guard")) {
    $EntryPoint = Join-Path $ProjectRoot "scripts/entrypoints/$($Tool -replace '-', '_').py"
    & $RunPython @(
        "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--name", $Tool,
        "--paths", "src", "--distpath", $OutputPath,
        "--workpath", $BuildDirectory, "--specpath", $SpecDirectory, $EntryPoint
    )
}

Write-Host "Windows executables built in $OutputPath"