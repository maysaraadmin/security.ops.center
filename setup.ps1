# Create virtual environment if it doesn't exist
if (-not (Test-Path .venv)) {
    python -m venv .venv
    Write-Host "✅ Created virtual environment" -ForegroundColor Green
}

# Activate virtual environment
.venv\Scripts\Activate.ps1

# Install required packages
pip install -r requirements.txt

# Create necessary directories
$directories = @(
    "logs",
    "data",
    "rules/correlation_rules"
)

foreach ($dir in $directories) {
    $fullPath = Join-Path -Path $PWD -ChildPath $dir
    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
        Write-Host "✅ Created directory: $dir" -ForegroundColor Green
    }
}

Write-Host "`nSetup complete! To start the SIEM web interface, run:" -ForegroundColor Cyan
Write-Host "1. .\.venv\Scripts\Activate.ps1" -ForegroundColor Yellow
Write-Host "2. python -m src.siem.web.run" -ForegroundColor Yellow
