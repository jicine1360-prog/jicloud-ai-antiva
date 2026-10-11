param(
    [string[]]$WatchPath = @("$HOME\models"),
    [string]$QuarantineDirectory = "$HOME\AI-Antiva-Quarantine",
    [ValidateRange(1, 3600)]
    [int]$WatchInterval = 5,
    [ValidateRange(1024, 65535)]
    [int]$Port = 8765
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TaskName = "JICloud AI Antiva Guard"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Executable = Join-Path $ProjectRoot "dist\windows\ai-model-guard.exe"
$LocalAppData = [Environment]::GetFolderPath("LocalApplicationData")
$AuditLog = Join-Path $LocalAppData "JICloud\AI Antiva\audit.jsonl"

if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
    throw "Guard executable not found: $Executable. Run .\scripts\build-windows.ps1 first."
}

$ResolvedWatchPaths = @()
foreach ($Path in $WatchPath) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $ResolvedWatchPaths += (Resolve-Path -LiteralPath $Path).Path
}
New-Item -ItemType Directory -Force -Path $QuarantineDirectory | Out-Null
$ResolvedQuarantineDirectory = (Resolve-Path -LiteralPath $QuarantineDirectory).Path
foreach ($Path in $ResolvedWatchPaths) {
    $WatchPrefix = $Path.TrimEnd("\\", "/") + "\\"
    if ($ResolvedQuarantineDirectory -eq $Path -or $ResolvedQuarantineDirectory.StartsWith($WatchPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Quarantine directory must be outside each watched model directory."
    }
}

$Arguments = @(
    "--port", "$Port",
    "--watch-interval", "$WatchInterval",
    "--audit-log", "`"$AuditLog`"",
    "--quarantine-dir", "`"$ResolvedQuarantineDirectory`""
)
foreach ($Path in $ResolvedWatchPaths) {
    $Arguments += "--watch-path", "`"$Path`""
}

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$Action = New-ScheduledTaskAction -Execute $Executable -Argument ($Arguments -join " ")
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "JICloud AI Antiva local model guard" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "JICloud AI Antiva guard installed and started."
Write-Host "Model folders: $($ResolvedWatchPaths -join ', ')"
Write-Host "Quarantine: $ResolvedQuarantineDirectory"
Write-Host "Audit log: $AuditLog"
Write-Host "Status: http://127.0.0.1:$Port/v1/status"
