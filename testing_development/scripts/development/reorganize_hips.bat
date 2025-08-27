@echo off
REM Create necessary directories
mkdir "d:\siem\src\services\hips\core"
mkdir "d:\siem\src\services\hips\models"
mkdir "d:\siem\src\services\hips\rules"
mkdir "d:\siem\src\services\hips\utils"

REM Create __init__.py files
echo. > "d:\siem\src\services\hips\__init__.py"
echo. > "d:\siem\src\services\hips\core\__init__.py"
echo. > "d:\siem\src\services\hips\models\__init__.py"
echo. > "d:\siem\src\services\hips\rules\__init__.py"
echo. > "d:\siem\src\services\hips\utils\__init__.py"

REM Move files
move /Y "d:\siem\services\hips\models.py" "d:\siem\src\services\hips\models\__init__.py"
move /Y "d:\siem\services\hips\rules.py" "d:\siem\src\services\hips\rules\__init__.py"
move /Y "d:\siem\services\hips\service.py" "d:\siem\src\services\hips\core\service.py"
move /Y "d:\siem\services\hips\__init__.py" "d:\siem\src\services\hips\__init__.py"

echo HIPS service files reorganized successfully!
pause
