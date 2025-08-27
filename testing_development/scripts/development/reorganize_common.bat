@echo off
REM Create necessary directories
mkdir "d:\\siem\\src\\common\\config"
mkdir "d:\\siem\\src\\common\\logging"
mkdir "d:\\siem\\src\\common\\security"
mkdir "d:\\siem\\src\\common\\utils"

REM Create __init__.py files
echo. > "d:\\siem\\src\\common\\__init__.py"
echo. > "d:\\siem\\src\\common\\config\\__init__.py"
echo. > "d:\\siem\\src\\common\\logging\\__init__.py"
echo. > "d:\\siem\\src\\common\\security\\__init__.py"
echo. > "d:\\siem\\src\\common\\utils\\__init__.py"

REM Move files to their new locations
if exist "d:\\siem\\common\\constants.py" (
    move /Y "d:\\siem\\common\\constants.py" "d:\\siem\\src\\common\\config\\"
)

if exist "d:\\siem\\common\\logging_utils.py" (
    move /Y "d:\\siem\\common\\logging_utils.py" "d:\\siem\\src\\common\\logging\\"
)

if exist "d:\\siem\\common\\security.py" (
    move /Y "d:\\siem\\common\\security.py" "d:\\siem\\src\\common\\security\\"
)

if exist "d:\\siem\\common\\utils.py" (
    move /Y "d:\\siem\\common\\utils.py" "d:\\siem\\src\\common\\utils\\"
)

REM Create a proper __init__.py for the common package
(
echo """
Common utilities and libraries for the SIEM system.

This package contains shared code used across multiple components of the SIEM system,
including logging, security, configuration, and general utilities.
"""

echo # Re-export commonly used modules and functions
from .config.constants import *
from .logging.logging_utils import *
from .security import *
from .utils import *
) > "d:\\siem\\src\\common\\__init__.py"

echo Common utilities reorganized successfully!
pause
