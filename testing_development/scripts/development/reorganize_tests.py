"""
Reorganize test files to match the new project structure.

This script moves test files to mirror the new src/ structure and updates imports.
"""
import os
import shutil
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).parent.parent
SRC_DIR = BASE_DIR / 'src'
TESTS_DIR = BASE_DIR / 'tests'

# Test directory structure to create
TEST_DIRS = [
    'unit/common',
    'unit/core',
    'unit/services/hips',
    'unit/services/nips',
    'unit/services/dlp',
    'unit/services/edr',
    'unit/services/fim',
    'integration',
    'e2e'
]

def create_test_directories():
    """Create the new test directory structure."""
    for test_dir in TEST_DIRS:
        dir_path = TESTS_DIR / test_dir
        dir_path.mkdir(parents=True, exist_ok=True)
        
        # Create __init__.py in each directory
        (dir_path / '__init__.py').touch(exist_ok=True)

def move_test_file(test_file: Path):
    """Move a test file to the appropriate location in the new structure."""
    if not test_file.is_file() or not test_file.suffix == '.py' or test_file.name == '__init__.py':
        return None
    
    # Determine the target directory based on the test file name
    test_name = test_file.stem
    
    # Check for service tests
    for service in ['hips', 'nips', 'dlp', 'edr', 'fim']:
        if service in test_name.lower():
            target_dir = TESTS_DIR / 'unit' / 'services' / service
            break
    else:
        # Check for core tests
        if 'core' in test_name.lower() or 'base' in test_name.lower():
            target_dir = TESTS_DIR / 'unit' / 'core'
        # Check for common tests
        elif 'common' in test_name.lower() or 'util' in test_name.lower():
            target_dir = TESTS_DIR / 'unit' / 'common'
        else:
            # Default to integration tests
            target_dir = TESTS_DIR / 'integration'
    
    # Create target directory if it doesn't exist
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Move the test file
    target_path = target_dir / test_file.name
    shutil.move(str(test_file), str(target_path))
    
    # Update imports in the test file
    update_test_imports(target_path)
    
    return target_path

def update_test_imports(test_file: Path):
    """Update imports in a test file to match the new structure."""
    with open(test_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Update imports to use the new structure
    updates = [
        (r'from \.\.\.src\.', 'from '),
        (r'from \.\.\.', 'from '),
        (r'from \.\.', 'from '),
        (r'from \.', 'from '),
        (r'import \.\.', 'import '),
        (r'import \.', 'import '),
    ]
    
    for old, new in updates:
        content = content.replace(old, new)
    
    # Write the updated content back to the file
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    print("Reorganizing test files...")
    
    # Create the new test directory structure
    create_test_directories()
    
    # Find and move test files
    moved_count = 0
    for test_file in TESTS_DIR.rglob('test_*.py'):
        if test_file.parent.name in ['unit', 'integration', 'e2e']:
            continue  # Skip files already in the correct location
            
        target_path = move_test_file(test_file)
        if target_path:
            print(f"Moved: {test_file.relative_to(BASE_DIR)} -> {target_path.relative_to(BASE_DIR)}")
            moved_count += 1
    
    print(f"\nReorganization complete! Moved {moved_count} test files.")
    print(f"New test structure in: {TESTS_DIR}")

if __name__ == "__main__":
    main()
