@echo off
REM Create necessary directories
mkdir "d:\\siem\\src\\services\\fim\\core"
mkdir "d:\\siem\\src\\services\\fim\\models"
mkdir "d:\\siem\\src\\services\\fim\\monitors"
mkdir "d:\\siem\\src\\services\\fim\\scanners"
mkdir "d:\\siem\\src\\services\\fim\\utils"

REM Create __init__.py files
echo. > "d:\\siem\\src\\services\\fim\\__init__.py"
echo. > "d:\\siem\\src\\services\\fim\\core\\__init__.py"
echo. > "d:\\siem\\src\\services\\fim\\models\\__init__.py"
echo. > "d:\\siem\\src\\services\\fim\\monitors\\__init__.py"
echo. > "d:\\siem\\src\\services\\fim\\scanners\\__init__.py"
echo. > "d:\\siem\\src\\services\\fim\\utils\\__init__.py"

REM Move the main service file
if exist "d:\\siem\\services\\fim\\__init__.py" (
    move /Y "d:\\siem\\services\\fim\\__init__.py" "d:\\siem\\src\\services\\fim\\core\\service.py"
)

REM Create a proper __init__.py for the FIM package
(
echo """
FIM (File Integrity Monitoring) Service

This package provides file integrity monitoring and change detection capabilities.
"""

echo from .core.service import FIMService as FIMService
) > "d:\\siem\\src\\services\\fim\\__init__.py"

echo FIM service files reorganized successfully!
pause
