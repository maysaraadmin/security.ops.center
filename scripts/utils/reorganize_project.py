#!/usr/bin/env python3
"""
Script to reorganize the project structure and update imports.
"""
import os
import shutil
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).parent.parent

# New directory structure
NEW_STRUCTURE = {
    'src': {
        'siem': {
            'core': [],
            'services': [],
            'models': [],
            'api': [],
            'utils': []
        },
        'edr': [],
        'dlp': [],
        'hips': [],
        'nips': [],
        'ndr': [],
        'fim': []
    },
    'config': {
        'development': [],
        'production': [],
        'testing': []
    },
    'tests': {
        'unit': [],
        'integration': [],
        'e2e': []
    },
    'docs': {
        'api': [],
        'architecture': [],
        'deployment': []
    },
    'scripts': [],
    'infrastructure': {
        'docker': [],
        'kubernetes': [],
        'terraform': []
    },
    'data': {
        'logs': [],
        'db': [],
        'backups': []
    },
    'tools': {
        'lint': [],
        'docs': [],
        'test': []
    }
}

# Mapping of source directories to destination directories
FILE_MAPPING = {
    # Core SIEM components
    'SIEM/core': 'src/siem/core',
    'SIEM/services': 'src/siem/services',
    'SIEM/models': 'src/siem/models',
    'SIEM/api': 'src/siem/api',
    'SIEM/utils': 'src/siem/utils',
    
    # Security modules
    'edr': 'src/edr',
    'dlp': 'src/dlp',
    'hips': 'src/hips',
    'nips': 'src/nips',
    'ndr': 'src/ndr',
    'fim': 'src/fim',
    
    # Configuration
    'config': 'config/development',
    
    # Tests
    'tests': 'tests/unit',
    'testing_development/tests': 'tests',
    
    # Data
    'data': 'data/db',
    'data_logs': 'data/logs',
    'db_backups': 'data/backups',
    'logs': 'data/logs/siem',
    
    # Other
    'scripts': 'scripts',
    'infrastructure': 'infrastructure',
    'docs': 'docs'
}

def create_directory_structure():
    """Create the new directory structure."""
    print("Creating directory structure...")
    
    def create_dirs(base_path, structure):
        for name, children in structure.items():
            dir_path = base_path / name
            dir_path.mkdir(parents=True, exist_ok=True)
            if isinstance(children, dict):
                create_dirs(dir_path, children)
    
    create_dirs(BASE_DIR, NEW_STRUCTURE)
    print("Directory structure created.")

def move_files():
    """Move files to their new locations."""
    print("\nMoving files...")
    
    for src, dst in FILE_MAPPING.items():
        src_path = BASE_DIR / src
        dst_path = BASE_DIR / dst
        
        if not src_path.exists():
            print(f"Source not found: {src_path}")
            continue
            
        if src_path.is_file():
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src_path), str(dst_path))
            print(f"Moved {src_path} -> {dst_path}")
        else:
            dst_path.mkdir(parents=True, exist_ok=True)
            for item in src_path.glob('*'):
                if item.name in ('__pycache__', '.git', '.idea', '.vscode'):
                    continue
                if item.is_file() and item.suffix in ('.pyc', '.pyo'):
                    continue
                shutil.move(str(item), str(dst_path / item.name))
            print(f"Moved contents of {src_path} -> {dst_path}")

def update_imports():
    """Update import statements in Python files."""
    print("\nUpdating imports in Python files...")
    
    import_mapping = {
        # Old import: New import
        'from src.siem.': 'from src.siem.',
        'import src.siem.': 'import src.siem.',
        'from src.edr.': 'from src.edr.',
        'import src.edr.': 'import src.edr.',
        'from src.dlp.': 'from src.dlp.',
        'import src.dlp.': 'import src.dlp.',
        'from src.hips.': 'from src.hips.',
        'import src.hips.': 'import src.hips.',
        'from src.nips.': 'from src.nips.',
        'import src.nips.': 'import src.nips.',
        'from src.ndr.': 'from src.ndr.',
        'import src.ndr.': 'import src.ndr.',
        'from src.fim.': 'from src.fim.',
        'import src.fim.': 'import src.fim.',
    }
    
    for py_file in BASE_DIR.glob('**/*.py'):
        if 'venv' in str(py_file) or '.venv' in str(py_file) or 'site-packages' in str(py_file):
            continue
            
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            for old, new in import_mapping.items():
                content = content.replace(old, new)
            
            if content != original_content:
                with open(py_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Updated imports in: {py_file.relative_to(BASE_DIR)}")
                
        except Exception as e:
            print(f"Error processing {py_file}: {e}")

def main():
    print("Starting project reorganization...")
    
    # Create the new directory structure
    create_directory_structure()
    
    # Move files to their new locations
    move_files()
    
    # Update import statements
    update_imports()
    
    print("\nReorganization complete!")
    print("Please review the changes and run your tests to ensure everything works.")
    print("You may need to update additional configuration files or scripts.")

if __name__ == "__main__":
    main()
