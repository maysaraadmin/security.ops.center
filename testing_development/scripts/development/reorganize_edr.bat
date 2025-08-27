@echo off
REM Create necessary directories
mkdir "d:\\siem\\src\\services\\edr\\core"
mkdir "d:\\siem\\src\\services\\edr\\models"
mkdir "d:\\siem\\src\\services\\edr\\detectors"
mkdir "d:\\siem\\src\\services\\edr\\collectors"
mkdir "d:\\siem\\src\\services\\edr\\utils"

REM Create __init__.py files
echo. > "d:\\siem\\src\\services\\edr\\__init__.py"
echo. > "d:\\siem\\src\\services\\edr\\core\\__init__.py"
echo. > "d:\\siem\\src\\services\\edr\\models\\__init__.py"
echo. > "d:\\siem\\src\\services\\edr\\detectors\\__init__.py"
echo. > "d:\\siem\\src\\services\\edr\\collectors\\__init__.py"
echo. > "d:\\siem\\src\\services\\edr\\utils\\__init__.py"

REM Move the main service file
move /Y "d:\\siem\\services\\edr\\__init__.py" "d:\\siem\\src\\services\\edr\\core\\service.py"

REM Create a proper __init__.py for the EDR package
(
echo """
EDR (Endpoint Detection and Response) Service

This package provides endpoint monitoring, threat detection, and response capabilities.
"""

echo from .core.service import EDRService as EDRService
) > "d:\\siem\\src\\services\\edr\\__init__.py"

echo EDR service files reorganized successfully!
pause
