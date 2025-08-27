#!/usr/bin/env python3
"""
Script to update import statements in Python files after reorganization.
"""
import os
import re
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).parent.parent

# Mapping of old import paths to new ones
IMPORT_MAPPING = {
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

def update_imports_in_file(file_path):
    """Update imports in a single file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Update imports based on the mapping
        for old, new in IMPORT_MAPPING.items():
            content = content.replace(old, new)
        
        # Only write if changes were made
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    print("Updating imports in Python files...")
    
    # Find all Python files in the project
    python_files = list(BASE_DIR.glob('**/*.py'))
    
    updated_count = 0
    
    for file_path in python_files:
        # Skip files in virtual environment and other non-project directories
        if 'venv' in str(file_path) or '.venv' in str(file_path) or 'site-packages' in str(file_path):
            continue
            
        if update_imports_in_file(file_path):
            print(f"Updated: {file_path.relative_to(BASE_DIR)}")
            updated_count += 1
    
    print(f"\nUpdate complete! {updated_count} files were updated.")
    print("\nNext steps:")
    print("1. Review the changes made to the files")
    print("2. Run your test suite to ensure everything works")
    print("3. Update any remaining import paths as needed")

if __name__ == "__main__":
    main()
