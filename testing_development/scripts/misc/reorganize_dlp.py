"""
Reorganize DLP service files into the new directory structure.
"""
import os
import shutil
from pathlib import Path

# Source and destination paths
BASE_DIR = Path(__file__).parent.parent
SRC_DIR = BASE_DIR / 'services' / 'dlp'
DST_DIR = BASE_DIR / 'src' / 'services' / 'dlp'

# Create destination directories
for subdir in ['core', 'models', 'rules', 'scanners', 'utils']:
    (DST_DIR / subdir).mkdir(parents=True, exist_ok=True)
    (DST_DIR / subdir / '__init__.py').touch(exist_ok=True)

# Move the main service file
if (SRC_DIR / '__init__.py').exists():
    shutil.move(str(SRC_DIR / '__init__.py'), str(DST_DIR / 'core' / 'service.py'))

# Create a proper __init__.py for the DLP package
with open(DST_DIR / '__init__.py', 'w', encoding='utf-8') as f:
    f.write('"""\nDLP (Data Loss Prevention) Service\n\nThis package provides data protection, policy enforcement, and user education capabilities.\n"""\
\nfrom src.core.service import DLPService as DLPService\n')

print("DLP service files reorganized successfully!")
