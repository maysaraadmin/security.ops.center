@echo off
REM Move remaining scripts to appropriate categories

REM Move PowerShell scripts to setup
move "d:\\siem\\scripts\\enable_*.ps1" "d:\\siem\\scripts\\setup\\" 2>nul

REM Move reorganization scripts to development
move "d:\\siem\\scripts\\reorganize_*.bat" "d:\\siem\\scripts\\development\\" 2>nul
move "d:\\siem\\scripts\\fix_*.bat" "d:\\siem\\scripts\\development\\" 2>nul
move "d:\\siem\\scripts\\update_*.bat" "d:\\siem\\scripts\\development\\" 2>nul

REM Move the move_scripts.bat to development
move "d:\\siem\\scripts\\move_scripts.bat" "d:\\siem\\scripts\\development\\" 2>nul
move "d:\\siem\\scripts\\move_remaining_scripts.bat" "d:\\siem\\scripts\\development\\" 2>nul

echo Remaining scripts have been organized into categories.
dir /s /b "d:\\siem\\scripts\\*" | find "/" /v /c
