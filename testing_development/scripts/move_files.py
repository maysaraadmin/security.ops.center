#!/usr/bin/env python3
"""Script to move files to their new locations based on the mapping."""
import os
import shutil
from pathlib import Path
from file_mapping import FILE_MAPPING, EXCLUDE_FILES

def should_exclude(file_path):
    """Check if a file should be excluded from moving."""
    for pattern in EXCLUDE_FILES:
        if pattern.startswith('*') and file_path.name.endswith(pattern[1:]):
            return True
        if file_path.name == pattern:
            return True
    return False

def move_files(base_path):
    """Move files according to the mapping."""
    moved = 0
    errors = 0
    
    for src_pattern, dest_pattern in FILE_MAPPING.items():
        # Handle directory patterns (ending with /)
        if src_pattern.endswith('/'):
            src_dir = base_path / src_pattern[:-1]
            dest_dir = base_path / dest_pattern[:-1]
            
            if not src_dir.exists():
                print(f"Source directory not found: {src_dir}")
                continue
                
            # Create destination directory if it doesn't exist
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            # Move files from source to destination
            for item in src_dir.iterdir():
                if should_exclude(item):
                    continue
                    
                dest_path = dest_dir / item.name
                try:
                    if item.is_dir():
                        if dest_path.exists():
                            # If destination exists, merge directories
                            for sub_item in item.iterdir():
                                shutil.move(str(sub_item), str(dest_path / sub_item.name))
                            item.rmdir()  # Remove now-empty source directory
                        else:
                            shutil.move(str(item), str(dest_path))
                    else:
                        shutil.move(str(item), str(dest_path))
                    moved += 1
                except Exception as e:
                    print(f"Error moving {item} to {dest_path}: {e}")
                    errors += 1
        
        # Handle individual files
        else:
            src_path = base_path / src_pattern
            dest_path = base_path / dest_pattern
            
            if not src_path.exists():
                print(f"Source file not found: {src_path}")
                continue
                
            # Create parent directory if it doesn't exist
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                shutil.move(str(src_path), str(dest_path))
                moved += 1
            except Exception as e:
                print(f"Error moving {src_path} to {dest_path}: {e}")
                errors += 1
    
    return moved, errors

def main():
    """Main function to run the file movement."""
    base_path = Path(__file__).parent.parent
    
    print("Starting file reorganization...")
    print(f"Base directory: {base_path}")
    
    moved, errors = move_files(base_path)
    
    print("\nReorganization complete!")
    print(f"Moved {moved} files/directories")
    print(f"Encountered {errors} errors")
    
    if errors > 0:
        print("\nSome files could not be moved. Please check the errors above.")
    
    print("\nNext steps:")
    print("1. Review the new directory structure")
    print("2. Update import statements in Python files")
    print("3. Update configuration files with new paths")
    print("4. Run tests to ensure everything works")

if __name__ == "__main__":
    main()
