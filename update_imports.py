import os
import re
from pathlib import Path

# Project root directory
PROJECT_ROOT = Path(__file__).parent
SRC_DIR = PROJECT_ROOT / 'src'

# Map of old import paths to new import paths
IMPORT_MAPPINGS = {
    # Web imports
    r'from web\.': 'from src.web.',
    r'import web\.': 'import src.web.',
    
    # EDR imports
    r'from edr\.': 'from src.edr.',
    r'import edr\.': 'import src.edr.',
    
    # Utils imports
    r'from utils\.': 'from src.utils.',
    r'import utils\.': 'import src.utils.',
    
    # Config imports
    r'from config\.': 'from config.',
    r'import config\.': 'import config.'
}

def update_file_imports(file_path):
    """Update import statements in a single file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        updated = False
        for old, new in IMPORT_MAPPINGS.items():
            new_content, count = re.subn(old, new, content)
            if count > 0:
                content = new_content
                updated = True
        
        if updated:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False

def update_imports_in_directory(directory):
    """Update imports in all Python files in a directory recursively."""
    updated_files = 0
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = Path(root) / file
                if update_file_imports(file_path):
                    print(f"Updated imports in: {file_path.relative_to(PROJECT_ROOT)}")
                    updated_files += 1
    
    return updated_files

def main():
    print("Updating import paths...\n")
    
    # Update imports in src directory
    updated = update_imports_in_directory(SRC_DIR)
    
    # Update imports in tests directory
    tests_dir = PROJECT_ROOT / 'tests'
    if tests_dir.exists():
        updated += update_imports_in_directory(tests_dir)
    
    # Update imports in scripts directory
    scripts_dir = PROJECT_ROOT / 'scripts'
    if scripts_dir.exists():
        updated += update_imports_in_directory(scripts_dir)
    
    print(f"\nUpdated imports in {updated} files.")

if __name__ == "__main__":
    main()
