"""
Reorganize the HIPS service files into the new directory structure.
"""
import os
import shutil
from pathlib import Path

# Source and destination paths
BASE_DIR = Path(__file__).parent.parent
SRC_DIR = BASE_DIR / 'services' / 'hips'
DST_DIR = BASE_DIR / 'src' / 'services' / 'hips'

# File mapping: source -> destination
FILE_MAPPING = {
    'models.py': DST_DIR / 'models' / '__init__.py',
    'rules.py': DST_DIR / 'rules' / '__init__.py',
    'service.py': DST_DIR / 'core' / 'service.py',
    '__init__.py': DST_DIR / '__init__.py',
}

def create_init_files():
    """Create necessary __init__.py files in the new structure."""
    for subdir in ['core', 'models', 'rules', 'utils']:
        init_file = DST_DIR / subdir / '__init__.py'
        init_file.parent.mkdir(parents=True, exist_ok=True)
        if not init_file.exists():
            init_file.touch()

def move_files():
    """Move files to their new locations."""
    for src_file, dst_file in FILE_MAPPING.items():
        src = SRC_DIR / src_file
        if not src.exists():
            print(f"Warning: Source file not found: {src}")
            continue
            
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"Moving {src} -> {dst_file}")
        shutil.move(str(src), str(dst_file))

def update_imports():
    """Update import statements in the moved files."""
    # Update imports in service.py
    service_file = DST_DIR / 'core' / 'service.py'
    if service_file.exists():
        with open(service_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Update imports to reflect new structure
        content = content.replace(
            'from .models import',
            'from ..models import'
        )
        content = content.replace(
            'from .rules import',
            'from ..rules import'
        )
        
        with open(service_file, 'w', encoding='utf-8') as f:
            f.write(content)

def main():
    print("Reorganizing HIPS service files...")
    create_init_files()
    move_files()
    update_imports()
    print("Reorganization complete!")

if __name__ == "__main__":
    main()
