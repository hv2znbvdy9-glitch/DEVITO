#requires -Version 5.1
# ==========================================
# AVA AUTO START + 5 MIN REPEAT
# ==========================================

$TaskName = "AVA_SOC_V7_SAFE"

$ScriptPath = $MyInvocation.MyCommand.Path

if (-not $ScriptPath) {
    Write-Host "Script muss als .ps1 gespeichert werden."
    exit
}

$Action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

$Trigger = New-ScheduledTaskTrigger -Once `
    -At (Get-Date).AddMinutes(1)

$Trigger.Repetition.Interval = "PT5M"
$Trigger.Repetition.Duration = "P36500D"

$Settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -RunLevel Highest `
    -Force

Write-Host ""
Write-Host "AVA Scheduler installiert." -ForegroundColor Green
Write-Host "Intervall: alle 5 Minuten" -ForegroundColor Cyan
Write-Host "Task Name: $TaskName" -ForegroundColor Cyan
Write-Host ""
