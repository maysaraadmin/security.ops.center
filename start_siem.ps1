# Start the SIEM service with logging
$logFile = "siem_service_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$pythonCmd = "python -m src.siem.cli.sysmon_cli start --foreground --log-level DEBUG"

Write-Host "Starting SIEM service..."
Write-Host "Logging to: $logFile"
Write-Host "Press Ctrl+C to stop the service"

# Start the process and redirect output to log file
Start-Process -NoNewWindow -FilePath "python" -ArgumentList "-m src.siem.cli.sysmon_cli start --foreground --log-level DEBUG" -RedirectStandardOutput $logFile -PassThru
