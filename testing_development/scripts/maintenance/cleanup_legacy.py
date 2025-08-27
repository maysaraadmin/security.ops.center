"""
Clean up legacy files from old directory structure.

This script identifies and removes or archives files that have been moved to the new
structure under src/. It creates a backup of files before removing them.
"""
import os
import shutil
from pathlib import Path
from datetime import datetime

# Base directories
BASE_DIR = Path(__file__).parent.parent
SRC_DIR = BASE_DIR / 'src'
BACKUP_DIR = BASE_DIR / 'legacy_backup' / datetime.now().strftime('%Y%m%d_%H%M%S')

# Define the mapping of old paths to new paths
# Format: (old_path, new_path, is_dir)
LEGACY_PATHS = [
    # Services
    ('services/hips', 'src/services/hips', True),
    ('services/nips', 'src/services/nips', True),
    ('services/dlp', 'src/services/dlp', True),
    ('services/edr', 'src/services/edr', True),
    ('services/fim', 'src/services/fim', True),
    
    # Core
    ('core', 'src/core', True),
    
    # Common
    ('common', 'src/common', True),
]

def backup_file(file_path: Path):
    """Backup a file to the legacy backup directory."""
    if not file_path.exists():
        return
        
    # Create backup directory if it doesn't exist
    backup_path = BACKUP_DIR / file_path.relative_to(BASE_DIR)
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Copy the file
    if file_path.is_file():
        shutil.copy2(file_path, backup_path)
    elif file_path.is_dir():
        shutil.copytree(file_path, backup_path, dirs_exist_ok=True)

def clean_legacy_files():
    """Clean up legacy files that have been moved to the new structure."""
    print(f"Creating backup in {BACKUP_DIR}...")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    
    removed_count = 0
    skipped_count = 0
    
    for old_path_rel, new_path_rel, is_dir in LEGACY_PATHS:
        old_path = BASE_DIR / old_path_rel
        new_path = BASE_DIR / new_path_rel
        
        if not old_path.exists():
            print(f"Skipping (not found): {old_path}")
            skipped_count += 1
            continue
            
        if not new_path.exists():
            print(f"Warning: New path doesn't exist: {new_path}")
            continue
            
        # Backup the old file/directory
        backup_file(old_path)
        
        try:
            if is_dir:
                # For directories, remove if empty or contains only __pycache__
                has_files = any(
                    f.name != '__pycache__' and not f.name.endswith('.pyc')
                    for f in old_path.glob('*')
                )
                
                if has_files:
                    print(f"Skipping non-empty directory: {old_path}")
                    skipped_count += 1
                else:
                    shutil.rmtree(old_path)
                    print(f"Removed directory: {old_path}")
                    removed_count += 1
            else:
                # For files, just remove them
                old_path.unlink()
                print(f"Removed: {old_path}")
                removed_count += 1
                
        except Exception as e:
            print(f"Error processing {old_path}: {e}")
            skipped_count += 1
    
    print(f"\nCleanup complete!")
    print(f"Removed: {removed_count}")
    print(f"Skipped: {skipped_count}")
    print(f"Backup available at: {BACKUP_DIR}")

def main():
    print("SIEM Project Cleanup Tool")
    print("========================")
    print("This will remove files that have been moved to the new structure under src/")
    print(f"A backup will be created in: {BACKUP_DIR}\n")
    
    response = input("Do you want to continue? (y/n): ")
    if response.lower() == 'y':
        clean_legacy_files()
    else:
        print("Operation cancelled.")

if __name__ == "__main__":
    main()
