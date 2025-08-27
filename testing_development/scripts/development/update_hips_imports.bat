@echo off
REM Update imports in service.py
powershell -Command "(Get-Content 'd:\siem\src\services\hips\core\service.py') -replace 'from \.models import', 'from ..models import' | Set-Content 'd:\siem\src\services\hips\core\service.py'"
powershell -Command "(Get-Content 'd:\siem\src\services\hips\core\service.py') -replace 'from \.rules import', 'from ..rules import' | Set-Content 'd:\siem\src\services\hips\core\service.py'"

echo HIPS service imports updated successfully!
pause
