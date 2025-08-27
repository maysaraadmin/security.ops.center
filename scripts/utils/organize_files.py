#!/usr/bin/env python3
"""
File Organizer

This script helps organize files in the project according to the defined structure.
"""
import os
import shutil
from pathlib import Path

# Define file type mappings
FILE_MAPPINGS = {
    # Configuration files
    '*.yaml': 'config',
    '*.yml': 'config',
    '*.json': 'config',
    '*.config': 'config',
    
    # Source files
    '*.py': 'src',
    
    # Documentation
    '*.md': 'docs',
    '*.txt': 'docs',
    '*.rst': 'docs',
    
    # Data files
    '*.csv': 'data',
    '*.jsonl': 'data',
    '*.db': 'data',
    '*.sqlite': 'data',
    
    # Logs
    '*.log': 'data/logs',
    
    # Web assets
    '*.html': 'web/templates',
    '*.css': 'web/static/css',
    '*.js': 'web/static/js',
    '*.png': 'web/static/images',
    '*.jpg': 'web/static/images',
    '*.jpeg': 'web/static/images',
    '*.svg': 'web/static/images',
}

def ensure_directories():
    """Ensure all target directories exist."""
    for pattern, target_dir in FILE_MAPPINGS.items():
        target_path = Path(target_dir)
        target_path.mkdir(parents=True, exist_ok=True)

def organize_files():
    """Organize files according to the mappings."""
    moved_files = []
    skipped_files = []
    
    for pattern, target_dir in FILE_MAPPINGS.items():
        for file_path in Path('.').rglob(pattern):
            # Skip files already in the correct location
            if str(file_path.parent).startswith(target_dir):
                continue
                
            # Skip files in .git directory
            if '.git' in file_path.parts:
                continue
                
            target_path = Path(target_dir) / file_path.name
            
            # Handle filename conflicts
            counter = 1
            while target_path.exists():
                name = file_path.stem
                ext = file_path.suffix
                target_path = Path(target_dir) / f"{name}_{counter}{ext}"
                counter += 1
            
            try:
                shutil.move(str(file_path), str(target_path))
                moved_files.append((str(file_path), str(target_path)))
            except Exception as e:
                skipped_files.append((str(file_path), str(e)))
    
    return moved_files, skipped_files

def main():
    """Main function to organize files."""
    print("\n=== File Organizer ===\n")
    
    print("Ensuring directory structure...")
    ensure_directories()
    
    print("Organizing files...")
    moved_files, skipped_files = organize_files()
    
    # Print results
    if moved_files:
        print("\nMoved files:")
        for src, dst in moved_files:
            print(f"- {src} -> {dst}")
    
    if skipped_files:
        print("\nSkipped files:")
        for src, error in skipped_files:
            print(f"- {src} (Error: {error})")
    
    if not moved_files and not skipped_files:
        print("No files needed to be moved.")
    
    print("\nOrganization complete!")

if __name__ == "__main__":
    main()
