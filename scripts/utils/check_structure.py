#!/usr/bin/env python3
"""
Project Structure Checker

This script checks the project structure against the defined standards
and reports any files that don't follow the conventions.
"""
import os
import sys
from pathlib import Path

# Define expected directory structure
EXPECTED_DIRS = {
    'config': ['development', 'production', 'testing'],
    'data': ['backups', 'logs'],
    'docs': [],
    'scripts': [],
    'src': ['api', 'core', 'models', 'services', 'utils'],
    'tests': ['unit', 'integration', 'e2e'],
    'web': ['static', 'templates']
}

def check_directory_structure():
    """Check if the project follows the expected directory structure."""
    root = Path('.').resolve()
    issues = []
    
    # Check for missing directories
    for dir_name, subdirs in EXPECTED_DIRS.items():
        dir_path = root / dir_name
        if not dir_path.exists():
            issues.append(f"Missing directory: {dir_name}")
        elif not dir_path.is_dir():
            issues.append(f"Expected directory but found file: {dir_name}")
        else:
            # Check subdirectories
            for subdir in subdirs:
                subdir_path = dir_path / subdir
                if not subdir_path.exists():
                    issues.append(f"Missing subdirectory: {dir_name}/{subdir}")
    
    # Check for unexpected Python files in root
    for item in root.glob('*.py'):
        if item.name not in ['manage.py', 'app.py']:  # Common root-level Python files
            issues.append(f"Python file in root directory: {item.name} (consider moving to scripts/ or src/)")
    
    return issues

def check_file_naming():
    """Check if files follow naming conventions."""
    issues = []
    
    # Check Python files
    for py_file in Path('.').rglob('*.py'):
        if not py_file.name.startswith('test_') and not py_file.name == '__init__.py':
            if not py_file.name.islower() or ' ' in py_file.name:
                issues.append(f"Python file naming issue: {py_file}")
    
    # Check test files
    for test_file in Path('tests').rglob('test_*.py'):
        if not test_file.name.startswith('test_'):
            issues.append(f"Test file should start with 'test_': {test_file}")
    
    return issues

def main():
    """Main function to run all checks."""
    print("\n=== Project Structure Checker ===\n")
    
    # Run checks
    dir_issues = check_directory_structure()
    naming_issues = check_file_naming()
    
    # Report issues
    if dir_issues:
        print("\n=== Directory Structure Issues ===")
        for issue in dir_issues:
            print(f"- {issue}")
    
    if naming_issues:
        print("\n=== File Naming Issues ===")
        for issue in naming_issues:
            print(f"- {issue}")
    
    if not dir_issues and not naming_issues:
        print("✓ Project structure looks good!")
    else:
        print(f"\nFound {len(dir_issues) + len(naming_issues)} issues to address.")
        print("\nRefer to project_structure.md for the expected structure.")
        sys.exit(1)

if __name__ == "__main__":
    main()
