@echo off
REM Create necessary directories
mkdir "d:\\siem\\src\\services\\dlp\\core"
mkdir "d:\\siem\\src\\services\\dlp\\models"
mkdir "d:\\siem\\src\\services\\dlp\\rules"
mkdir "d:\\siem\\src\\services\\dlp\\scanners"
mkdir "d:\\siem\\src\\services\\dlp\\utils"

REM Create __init__.py files
echo. > "d:\\siem\\src\\services\\dlp\\__init__.py"
echo. > "d:\\siem\\src\\services\\dlp\\core\\__init__.py"
echo. > "d:\\siem\\src\\services\\dlp\\models\\__init__.py"
echo. > "d:\\siem\\src\\services\\dlp\\rules\\__init__.py"
echo. > "d:\\siem\\src\\services\\dlp\\scanners\\__init__.py"
echo. > "d:\\siem\\src\\services\\dlp\\utils\\__init__.py"

REM Move the main service file
move /Y "d:\\siem\\services\\dlp\\__init__.py" "d:\\siem\\src\\services\\dlp\\core\\service.py"

REM Create a proper __init__.py for the DLP package
(
echo """
DLP (Data Loss Prevention) Service

This package provides data protection, policy enforcement, and user education capabilities.
"""

echo from .core.service import DLPService as DLPService
) > "d:\\siem\\src\\services\\dlp\\__init__.py"

echo DLP service files reorganized successfully!
pause
