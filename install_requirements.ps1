# Activate virtual environment
. \.venv\Scripts\Activate.ps1

# Upgrade pip
python -m pip install --upgrade pip

# Install wheel first to avoid build issues
pip install wheel

# Install core requirements
pip install flask flask-cors pyyaml python-dotenv

# Install remaining requirements
pip install -r requirements.txt

Write-Host "`n✅ Dependencies installed successfully!" -ForegroundColor Green
Write-Host "You can now start the SIEM web interface with:" -ForegroundColor Cyan
Write-Host "python -m src.siem.web.run" -ForegroundColor Yellow
