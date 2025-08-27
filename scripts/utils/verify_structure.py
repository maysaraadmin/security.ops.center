#!/usr/bin/env python3
"""
Script to verify the project structure and organization.
"""

from pathlib import Path
import sys

# Expected directory structure
EXPECTED_STRUCTURE = {
    'src': {
        'siem': {
            'core': ['__init__.py'],
            'services': ['__init__.py'],
            'models': ['__init__.py'],
            'api': ['__init__.py'],
            'utils': ['__init__.py']
        },
        'edr': ['__init__.py'],
        'dlp': ['__init__.py'],
        'hips': ['__init__.py'],
        'nips': ['__init__.py'],
        'ndr': ['__init__.py'],
        'fim': ['__init__.py']
    },
    'tests': {
        'unit': ['__init__.py'],
        'integration': ['__init__.py'],
        'e2e': ['__init__.py']
    },
    'config': {
        'development': [],
        'production': [],
        'testing': []
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

def check_structure(base_path, structure, path=Path('.')):
    """Recursively check the directory structure."""
    errors = []
    
    for name, contents in structure.items():
        current_path = path / name
        full_path = base_path / current_path
        
        # Check if directory exists
        if not full_path.exists():
            errors.append(f"❌ Missing directory: {current_path}")
            continue
            
        if not full_path.is_dir():
            errors.append(f"❌ Not a directory: {current_path}")
            continue
            
        # Check for required files
        if isinstance(contents, dict):
            # It's a subdirectory, recurse
            errors.extend(check_structure(base_path, contents, current_path))
        else:
            # It's a list of required files
            for filename in contents:
                file_path = full_path / filename
                if not file_path.exists():
                    errors.append(f"❌ Missing file: {current_path / filename}")
    
    return errors

def main():
    print("🔍 Verifying project structure...\n")
    
    base_path = Path(__file__).parent.parent
    errors = check_structure(base_path, EXPECTED_STRUCTURE)
    
    if not errors:
        print("✅ Project structure is valid!")
        print("\nThe project is now properly organized according to Python best practices.")
        print("You can now proceed with development using the new structure.")
        return 0
    else:
        print("\nFound the following issues:")
        for error in errors:
            print(f"  {error}")
        print("\nPlease fix the above issues before proceeding.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
