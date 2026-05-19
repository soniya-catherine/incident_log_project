<#
collect_windows_security.ps1

Purpose:
Collect selected Windows Security Event Logs for a specific time period.

This script is safe because:
- It only reads Windows Event Logs.
- It does not delete or modify logs.
- It exports selected events to a CSV file.

Events collected:
- 4624 = Successful logon
- 4625 = Failed logon

Output:
C:\incident_log_project\collected_logs\windows_security_events.csv
#>

Write-Host "Windows Security Log Collector"
Write-Host "Time format example: 2026-04-22 00:00:00"
Write-Host ""

# Ask the user for the time range.
$StartText = Read-Host "Enter start time"
$EndText   = Read-Host "Enter end time"

# Try to convert the entered text into real date/time values.
try {
    $StartTime = [datetime]::Parse($StartText)
    $EndTime   = [datetime]::Parse($EndText)
}
catch {
    Write-Host "ERROR: Invalid time format."
    Write-Host "Use format like: 2026-04-22 00:00:00"
    exit
}

# Stop if the start time is after the end time.
if ($StartTime -gt $EndTime) {
    Write-Host "ERROR: Start time must be before end time."
    exit
}

# Security Event IDs we want to collect.
# 4624 = successful logon
# 4625 = failed logon
$EventIds = 4624, 4625

# Output folder and CSV file path.
# $PSScriptRoot - the folder where this PowerShell script is located.
$OutputDir = Join-Path $PSScriptRoot "collected_logs"
$OutputFile = Join-Path $OutputDir "windows_security_events.csv"

Write-Host ""
Write-Host "Collecting Event IDs: $($EventIds -join ', ')"
Write-Host "Start Time: $StartTime"
Write-Host "End Time: $EndTime"
Write-Host ""

# Read log name, event ID, and start time first, then filter by end time.
# This avoids FilterHashtable errors on some Windows systems.
try {
    $Events = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = $EventIds
        StartTime = $StartTime
    } -ErrorAction Stop | Where-Object {
        $_.TimeCreated -le $EndTime
    }
}
catch {
    Write-Host "ERROR: Could not read Windows Security logs."
    Write-Host "Try running PowerShell as Administrator."
    Write-Host "Details: $($_.Exception.Message)"
    exit
}

# Convert each event into a simple CSV-friendly object.
$Rows = foreach ($Event in $Events) {
    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        Host        = $env:COMPUTERNAME
        EventId     = $Event.Id
        Provider    = $Event.ProviderName
        Message     = ($Event.Message -replace "`r?`n", " ")
    }
}

# Create output folder if it does not already exist.
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Export the collected rows to CSV.
$Rows | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

Write-Host "Collection complete."
Write-Host "Events collected: $($Rows.Count)"
Write-Host "Output saved to: $OutputFile"