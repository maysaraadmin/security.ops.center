#!/usr/bin/env python3
"""
Script to reorganize the project structure.
Run this script from the project root directory.
"""
import os
import shutil
from pathlib import Path

# Define the new directory structure
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
        'ndr': []
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

# Mapping of old directories to new locations
MAPPING = {
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
    
    # Documentation
    'docs': 'docs',
    
    # Scripts
    'scripts': 'scripts',
    
    # Infrastructure
    'infrastructure': 'infrastructure',
    
    # Data
    'data': 'data/db',
    'data_logs': 'data/logs',
    'db_backups': 'data/backups',
    'logs': 'data/logs/siem',
    
    # Tools
    'tools': 'tools'
}

def create_directory_structure():
    """Create the new directory structure."""
    base_dir = Path('.')
    
    def create_dirs(root, structure):
        for name, children in structure.items():
            path = root / name
            path.mkdir(parents=True, exist_ok=True)
            if isinstance(children, dict):
                create_dirs(path, children)
    
    print("Creating new directory structure...")
    create_dirs(base_dir, NEW_STRUCTURE)
    print("Directory structure created successfully.")

def move_files():
    """Move files according to the mapping."""
    for src, dst in MAPPING.items():
        src_path = Path(src)
        dst_path = Path(dst)
        
        if not src_path.exists():
            print(f"Source path does not exist: {src}")
            continue
            
        if src_path.is_file():
            # Handle file movement
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src_path), str(dst_path))
            print(f"Moved {src} -> {dst}")
        else:
            # Handle directory movement
            dst_path.mkdir(parents=True, exist_ok=True)
            for item in src_path.glob('*'):
                if item.name == '__pycache__' or item.name.endswith('.pyc'):
                    continue  # Skip Python cache files
                shutil.move(str(item), str(dst_path / item.name))
            print(f"Moved contents of {src} -> {dst}")

def update_imports():
    """Update import statements in Python files."""
    # This is a simplified version - in a real scenario, you'd need to parse the AST
    # and update imports based on the new structure
    print("\nIMPORTANT: You'll need to update import statements in your Python files.")
    print("Consider using tools like 'isort' and 'autoflake' to help with this process.")
    print("Example command after reorganization:")
    print("  find src -name '*.py' | xargs isort")
    print("  find src -name '*.py' | xargs autoflake --in-place --remove-all-unused-imports --remove-unused-variables")

def main():
    print("Starting project reorganization...")
    create_directory_structure()
    move_files()
    update_imports()
    print("\nReorganization complete!")
    print("Please review the changes and update any remaining references manually.")

if __name__ == "__main__":
    main()
