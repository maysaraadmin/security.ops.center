@echo off
REM Create necessary directories
mkdir "d:\\siem\\src\\services\\nips\\core"
mkdir "d:\\siem\\src\\services\\nips\\models"
mkdir "d:\\siem\\src\\services\\nips\\rules"
mkdir "d:\\siem\\src\\services\\nips\\utils"

REM Create __init__.py files
echo. > "d:\\siem\\src\\services\\nips\\__init__.py"
echo. > "d:\\siem\\src\\services\\nips\\core\\__init__.py"
echo. > "d:\\siem\\src\\services\\nips\\models\\__init__.py"
echo. > "d:\\siem\\src\\services\\nips\\rules\\__init__.py"
echo. > "d:\\siem\\src\\services\\nips\\utils\\__init__.py"

REM Move files
move /Y "d:\\siem\\services\\nips\\models.py" "d:\\siem\\src\\services\\nips\\models\\__init__.py"
move /Y "d:\\siem\\services\\nips\\rules.py" "d:\\siem\\src\\services\\nips\\rules\\__init__.py"
move /Y "d:\\siem\\services\\nips\\service.py" "d:\\siem\\src\\services\\nips\\core\\service.py"
move /Y "d:\\siem\\services\\nips\\__init__.py" "d:\\siem\\src\\services\\nips\\__init__.py"

echo NIPS service files reorganized successfully!
pause
