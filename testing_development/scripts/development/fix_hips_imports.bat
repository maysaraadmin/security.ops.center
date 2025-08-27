@echo off
echo Updating HIPS service imports...

REM Update service.py
powershell -Command "(Get-Content 'd:\siem\src\services\hips\core\service.py') -replace 'from \.\.models import', 'from ..models import' | Set-Content 'd:\siem\src\services\hips\core\service.py'"
powershell -Command "(Get-Content 'd:\siem\src\services\hips\core\service.py') -replace 'from \.\.rules import', 'from ..rules import' | Set-Content 'd:\siem\src\services\hips\core\service.py'"

REM Update models/__init__.py
powershell -Command "(Get-Content 'd:\siem\src\services\hips\models\__init__.py') -replace 'from \.\.core\.service import', 'from ..core.service import' | Set-Content 'd:\siem\src\services\hips\models\__init__.py'"

REM Update rules/__init__.py
powershell -Command "(Get-Content 'd:\siem\src\services\hips\rules\__init__.py') -replace 'from \.\.core\.service import', 'from ..core.service import' | Set-Content 'd:\siem\src\services\hips\rules\__init__.py'"

echo HIPS service imports updated successfully!
pause
