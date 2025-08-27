"""
Fix import statements in the reorganized HIPS service.
"""
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.parent
HIPS_DIR = BASE_DIR / 'src' / 'services' / 'hips'

# Files to update
FILES_TO_UPDATE = [
    HIPS_DIR / 'core' / 'service.py',
    HIPS_DIR / 'models' / '__init__.py',
    HIPS_DIR / 'rules' / '__init__.py'
]

def update_imports(file_path):
    """Update import statements in the specified file."""
    if not file_path.exists():
        print(f"File not found: {file_path}")
        return
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Update relative imports
    replacements = [
        ('from .models import', 'from ..models import'),
        ('from .rules import', 'from ..rules import'),
        ('from .service import', 'from src.core.service import'),
        ('from . import service', 'from .core import service')
    ]
    
    for old, new in replacements:
        content = content.replace(old, new)
    
    # Write updated content back to file
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Updated imports in {file_path}")

def main():
    print("Updating HIPS service imports...")
    for file_path in FILES_TO_UPDATE:
        update_imports(file_path)
    print("Import updates complete!")

if __name__ == "__main__":
    main()
