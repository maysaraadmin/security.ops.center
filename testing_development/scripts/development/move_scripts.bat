@echo off
REM Create category directories
mkdir "d:\\siem\\scripts\\setup"
mkdir "d:\\siem\\scripts\\deployment"
mkdir "d:\\siem\\scripts\\maintenance"
mkdir "d:\\siem\\scripts\\development"
mkdir "d:\\siem\\scripts\\database"
mkdir "d:\\siem\\scripts\\monitoring"
mkdir "d:\\siem\\scripts\\misc"

REM Create __init__.py files in each directory
for /d %%d in (d:\\siem\\scripts\\*) do (
    if not exist "%%d\\__init__.py" (
        echo. > "%%d\\__init__.py"
    )
)

REM Move setup scripts
move "d:\\siem\\scripts\\setup_*.py" "d:\\siem\\scripts\\setup\\" 2>nul
move "d:\\siem\\scripts\\install_*.py" "d:\\siem\\scripts\\setup\\" 2>nul
move "d:\\siem\\scripts\\bootstrap_*.py" "d:\\siem\\scripts\\setup\\" 2>nul

REM Move deployment scripts
move "d:\\siem\\scripts\\deploy_*.py" "d:\\siem\\scripts\\deployment\\" 2>nul
move "d:\\siem\\scripts\\publish_*.py" "d:\\siem\\scripts\\deployment\\" 2>nul
move "d:\\siem\\scripts\\release_*.py" "d:\\siem\\scripts\\deployment\\" 2>nul

REM Move maintenance scripts
move "d:\\siem\\scripts\\clean_*.py" "d:\\siem\\scripts\\maintenance\\" 2>nul
move "d:\\siem\\scripts\\backup_*.py" "d:\\siem\\scripts\\maintenance\\" 2>nul
move "d:\\siem\\scripts\\migrate_*.py" "d:\\siem\\scripts\\maintenance\\" 2>nul
move "d:\\siem\\scripts\\update_*.py" "d:\\siem\\scripts\\maintenance\\" 2>nul

REM Move development scripts
move "d:\\siem\\scripts\\dev_*.py" "d:\\siem\\scripts\\development\\" 2>nul
move "d:\\siem\\scripts\\test_*.py" "d:\\siem\\scripts\\development\\" 2>nul
move "d:\\siem\\scripts\\debug_*.py" "d:\\siem\\scripts\\development\\" 2>nul

REM Move database scripts
move "d:\\siem\\scripts\\db_*.py" "d:\\siem\\scripts\\database\\" 2>nul
move "d:\\siem\\scripts\\migrate_*.py" "d:\\siem\\scripts\\database\\" 2>nul
move "d:\\siem\\scripts\\seed_*.py" "d:\\siem\\scripts\\database\\" 2>nul

REM Move monitoring scripts
move "d:\\siem\\scripts\\monitor_*.py" "d:\\siem\\scripts\\monitoring\\" 2>nul
move "d:\\siem\\scripts\\stats_*.py" "d:\\siem\\scripts\\monitoring\\" 2>nul
move "d:\\siem\\scripts\\metrics_*.py" "d:\\siem\\scripts\\monitoring\\" 2>nul

REM Move remaining Python files to misc
move "d:\\siem\\scripts\\*.py" "d:\\siem\\scripts\\misc\\" 2>nul

echo Scripts have been reorganized into categories.
dir /s /b "d:\\siem\\scripts\\*" | find "/" /v /c
