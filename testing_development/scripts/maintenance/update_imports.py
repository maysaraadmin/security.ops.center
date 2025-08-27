"""
Update import statements in the reorganized project structure.

This script updates import statements across the codebase to use the new
absolute import paths after the project reorganization.
"""
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple, Set, Optional

# Base directory
BASE_DIR = Path(__file__).parent.parent
SRC_DIR = BASE_DIR / 'src'

# Common import patterns to update (old_pattern -> new_pattern)
IMPORT_UPDATES = [
    # Common imports
    (r'from common\.', 'from src.common.'),
    (r'from \.common\.', 'from src.common.'),
    
    # Core imports
    (r'from core\.', 'from src.core.'),
    (r'from \.core\.', 'from src.core.'),
    
    # Service imports (HIPS, NIPS, DLP, EDR, FIM)
    (r'from services\.hips\.', 'from src.services.hips.'),
    (r'from services\.nips\.', 'from src.services.nips.'),
    (r'from services\.dlp\.', 'from src.services.dlp.'),
    (r'from services\.edr\.', 'from src.services.edr.'),
    (r'from services\.fim\.', 'from src.services.fim.'),
    (r'from \.hips\.', 'from src.services.hips.'),
    (r'from \.nips\.', 'from src.services.nips.'),
    (r'from \.dlp\.', 'from src.services.dlp.'),
    (r'from \.edr\.', 'from src.services.edr.'),
    (r'from \.fim\.', 'from src.services.fim.'),
    
    # Update relative imports in service modules
    (r'from \.\.models import', 'from ..models import'),
    (r'from \.\.rules import', 'from ..rules import'),
    (r'from \.\.core import', 'from ..core import'),
    (r'from \.\.utils import', 'from ..utils import'),
]

def update_file_imports(file_path: Path) -> bool:
    """
    Update import statements in a single file.
    
    Args:
        file_path: Path to the file to update
        
    Returns:
        bool: True if the file was modified, False otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Apply all import updates
        for old_pattern, new_pattern in IMPORT_UPDATES:
            content = re.sub(old_pattern, new_pattern, content)
        
        # Only write if changes were made
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
            
    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        
    return False

def update_imports_in_directory(directory: Path, extensions: List[str] = None) -> Tuple[int, int]:
    """
    Recursively update imports in all Python files in a directory.
    
    Args:
        directory: Directory to search for Python files
        extensions: List of file extensions to process (default: ['.py'])
        
    Returns:
        Tuple[int, int]: (files_updated, files_processed)
    """
    if extensions is None:
        extensions = ['.py']
    
    files_updated = 0
    files_processed = 0
    
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_path = Path(root) / file
                if update_file_imports(file_path):
                    files_updated += 1
                    print(f"Updated imports in {file_path.relative_to(BASE_DIR)}")
                files_processed += 1
    
    return files_updated, files_processed

def main():
    print("Updating imports across the codebase...")
    
    # Define directories to process
    directories = [
        SRC_DIR / 'services',
        SRC_DIR / 'core',
        SRC_DIR / 'common',
        BASE_DIR / 'scripts',
        BASE_DIR / 'tests'
    ]
    
    # Process each directory
    total_updated = 0
    total_processed = 0
    
    for directory in directories:
        if directory.exists() and directory.is_dir():
            print(f"\nProcessing directory: {directory.relative_to(BASE_DIR)}")
            updated, processed = update_imports_in_directory(directory)
            total_updated += updated
            total_processed += processed
    
    print(f"\nImport updates complete!")
    print(f"Files updated: {total_updated} out of {total_processed} processed")

if __name__ == "__main__":
    main()
