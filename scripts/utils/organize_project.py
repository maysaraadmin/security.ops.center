#!/usr/bin/env python3
"""
Script to reorganize the project structure.
This script will move files to their new locations and update import statements.
"""

import os
import shutil
from pathlib import Path
import re

# Base directory
BASE_DIR = Path(__file__).parent.parent

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

# Import patterns to update
IMPORT_PATTERNS = {
    # Old pattern: New pattern
    r'from\s+SIEM\.': 'from src.siem.',
    r'import\s+SIEM\.': 'import src.siem.',
    r'from\s+edr\.': 'from src.edr.',
    r'import\s+edr\.': 'import src.edr.',
    r'from\s+dlp\.': 'from src.dlp.',
    r'import\s+dlp\.': 'import src.dlp.',
    r'from\s+hips\.': 'from src.hips.',
    r'import\s+hips\.': 'import src.hips.',
    r'from\s+nips\.': 'from src.nips.',
    r'import\s+nips\.': 'import src.nips.',
    r'from\s+ndr\.': 'from src.ndr.',
    r'import\s+ndr\.': 'import src.ndr.',
    r'from\s+fim\.': 'from src.fim.',
    r'import\s+fim\.': 'import src.fim.',
}

def create_directories():
    """Create all necessary directories in the new structure."""
    print("🚀 Creating directory structure...")
    
    # Get all unique destination directories
    all_dirs = set()
    for dst in FILE_MAPPING.values():
        path = Path(dst)
        # Add all parent directories
        for i in range(1, len(path.parts) + 1):
            all_dirs.add(str(Path(*path.parts[:i])))
    
    # Create all directories
    for dir_path in sorted(all_dirs):
        full_path = BASE_DIR / dir_path
        full_path.mkdir(parents=True, exist_ok=True)
        if not (full_path / "__init__.py").exists():
            (full_path / "__init__.py").touch()
        print(f"  ✓ Created: {dir_path}")

def move_files():
    """Move files to their new locations."""
    print("\n📂 Moving files to new locations...")
    
    moved_count = 0
    for src, dst in FILE_MAPPING.items():
        src_path = BASE_DIR / src
        dst_path = BASE_DIR / dst
        
        if not src_path.exists():
            print(f"  ⚠️ Source not found: {src}")
            continue
            
        if src_path.is_file():
            # Move single file
            try:
                shutil.move(str(src_path), str(dst_path))
                print(f"  ✓ Moved: {src} -> {dst}")
                moved_count += 1
            except Exception as e:
                print(f"  ❌ Error moving {src}: {e}")
        else:
            # Move directory contents
            try:
                for item in src_path.glob('*'):
                    if item.name in ('__pycache__', '.git', '.idea', '.vscode'):
                        continue
                    if item.is_file() and item.suffix in ('.pyc', '.pyo'):
                        continue
                    
                    dest = dst_path / item.name
                    if dest.exists():
                        if dest.is_file():
                            dest.unlink()
                        else:
                            shutil.rmtree(dest)
                    
                    shutil.move(str(item), str(dest))
                    print(f"  ✓ Moved: {src}/{item.name} -> {dst}")
                    moved_count += 1
            except Exception as e:
                print(f"  ❌ Error moving contents of {src}: {e}")
    
    print(f"\n✅ Successfully moved {moved_count} items.")

def update_imports():
    """Update import statements in Python files."""
    print("\n🔄 Updating import statements...")
    
    updated_files = 0
    
    # Find all Python files in the project
    for py_file in BASE_DIR.glob('**/*.py'):
        # Skip virtual environment and other non-project directories
        if any(part.startswith(('.', '__', 'venv', '.venv', 'site-packages')) 
               for part in py_file.parts):
            continue
        
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            # Update imports based on patterns
            for old_pattern, new_pattern in IMPORT_PATTERNS.items():
                content = re.sub(old_pattern, new_pattern, content)
            
            # Only write if changes were made
            if content != original_content:
                with open(py_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"  ✓ Updated: {py_file.relative_to(BASE_DIR)}")
                updated_files += 1
                
        except Exception as e:
            print(f"  ❌ Error processing {py_file.relative_to(BASE_DIR)}: {e}")
    
    print(f"\n✅ Updated imports in {updated_files} files.")

def main():
    print("=" * 60)
    print("🔧 Project Reorganization Tool")
    print("=" * 60)
    
    # Create directory structure
    create_directories()
    
    # Move files to new locations
    move_files()
    
    # Update import statements
    update_imports()
    
    print("\n" + "=" * 60)
    print("✨ Reorganization complete!")
    print("\nNext steps:")
    print("1. Review the changes made")
    print("2. Run your test suite to verify everything works")
    print("3. Update any remaining configuration or documentation")
    print("=" * 60)

if __name__ == "__main__":
    main()
