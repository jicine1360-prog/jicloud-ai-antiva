Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TaskName = "JICloud AI Antiva Guard"
$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -eq $Task) {
    Write-Host "JICloud AI Antiva guard is not installed."
    exit 0
}

if ($Task.State -eq "Running") {
    Stop-ScheduledTask -TaskName $TaskName
}
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
Write-Host "JICloud AI Antiva guard removed. Audit and quarantine files were kept."
