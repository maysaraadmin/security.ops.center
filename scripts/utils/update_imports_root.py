#!/usr/bin/env python3
"""Script to update import statements after reorganization."""
import re
import os
from pathlib import Path

# Get the root directory of the project
ROOT_DIR = Path(__file__).parent.absolute()

# Mapping of old import paths to new ones
IMPORT_MAPPING = {
    # Old path: New path
    "from src.": "from siem.",
    "import src.": "import siem.",
    "from core.": "from siem.core.",
    "import core.": "import siem.core.",
    "from models.": "from siem.models.",
    "import models.": "import siem.models.",
    "from services.": "from siem.services.",
    "import services.": "import siem.services.",
    "from api.": "from siem.api.",
    "import api.": "import siem.api.",
    "from views.": "from siem.ui.views.",
    "import views.": "import siem.ui.views.",
    "from managers.": "from siem.core.managers.",
    "import managers.": "import siem.core.managers.",
    "from src.utils.": "from infrastructure.utils.",
    "import src.utils.": "import infrastructure.utils.",
}

def update_imports_in_file(file_path):
    """Update import statements in a single file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Update import statements
        for old_import, new_import in IMPORT_MAPPING.items():
            # Handle both 'from x import y' and 'import x.y' patterns
            content = re.sub(
                rf'(^|\n\s*)(from|import)\s+{re.escape(old_import)}',
                rf'\1\2 {new_import}',
                content
            )
        
        # Only write if changes were made
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def update_imports_in_directory(directory):
    """Recursively update imports in all Python files in a directory."""
    updated = 0
    errors = 0
    
    for py_file in directory.rglob('*.py'):
        if '__pycache__' in str(py_file):
            continue
            
        print(f"Updating imports in {py_file.relative_to(ROOT_DIR)}")
        if update_imports_in_file(py_file):
            updated += 1
        else:
            errors += 1
    
    return updated, errors

def main():
    """Main function to update imports."""
    print("Starting import updates...")
    print(f"Root directory: {ROOT_DIR}")
    
    # Update imports in the main package
    updated, errors = update_imports_in_directory(ROOT_DIR / "siem")
    
    # Update imports in security modules
    security_modules = ["edr", "dlp", "fim", "ndr", "nips", "hips", "ueba"]
    for module in security_modules:
        module_path = ROOT_DIR / "security_modules" / module
        if module_path.exists():
            u, e = update_imports_in_directory(module_path)
            updated += u
            errors += e
    
    print("\nImport updates complete!")
    print(f"Updated {updated} files")
    print(f"Encountered {errors} errors")
    
    if errors > 0:
        print("\nSome files could not be updated. Please check the errors above.")
    
    print("\nNext steps:")
    print("1. Review the import changes")
    print("2. Run tests to ensure everything works")
    print("3. Update any remaining import paths manually if needed")

if __name__ == "__main__":
    main()
