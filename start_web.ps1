# Set environment variables
$env:FLASK_APP = "src.siem.web"
$env:FLASK_ENV = "development"
$env:FLASK_DEBUG = "1"

# Print configuration
Write-Host "Starting SIEM web interface..."
Write-Host "FLASK_APP: $env:FLASK_APP"
Write-Host "FLASK_ENV: $env:FLASK_ENV"
Write-Host "FLASK_DEBUG: $env:FLASK_DEBUG"
Write-Host ""
Write-Host "Access the web interface at: http://localhost:5000"
Write-Host "Press Ctrl+C to stop the server"

# Start the Flask development server
python -m flask run --host=0.0.0.0 --port=5000
