""
Project Organizer Script

This script organizes the project by:
1. Moving all Python scripts to a 'scripts' directory
2. Moving all log files to a 'logs' directory
3. Cleaning up temporary files
"""
import os
import shutil
from pathlib import Path
import glob

def create_directory(directory):
    """Create a directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")

def move_files(file_pattern, target_dir, file_type="files"):
    ""
    Move files matching a pattern to a target directory.
    
    Args:
        file_pattern: Glob pattern to match files
        target_dir: Target directory to move files to
        file_type: Description of file type for logging
    """
    create_directory(target_dir)
    moved_count = 0
    
    for file_path in glob.glob(file_pattern, recursive=True):
        # Skip files in the target directory or its subdirectories
        if os.path.abspath(target_dir) in os.path.abspath(file_path):
            continue
            
        try:
            target_path = os.path.join(target_dir, os.path.basename(file_path))
            # Handle filename conflicts
            counter = 1
            while os.path.exists(target_path):
                name, ext = os.path.splitext(os.path.basename(file_path))
                target_path = os.path.join(target_dir, f"{name}_{counter}{ext}")
                counter += 1
                
            shutil.move(file_path, target_path)
            print(f"Moved: {file_path} -> {target_path}")
            moved_count += 1
        except Exception as e:
            print(f"Error moving {file_path}: {e}")
    
    print(f"Moved {moved_count} {file_type} to {target_dir}")

def clean_pycache():
    ""Remove all __pycache__ directories and .pyc files."""
    pycache_dirs = []
    pyc_files = []
    
    # Find all __pycache__ directories and .pyc files
    for root, dirs, files in os.walk('.'):
        if '__pycache__' in dirs:
            pycache_dirs.append(os.path.join(root, '__pycache__'))
        
        for file in files:
            if file.endswith('.pyc') or file.endswith('.pyo'):
                pyc_files.append(os.path.join(root, file))
    
    # Remove __pycache__ directories
    for dir_path in pycache_dirs:
        try:
            shutil.rmtree(dir_path)
            print(f"Removed: {dir_path}")
        except Exception as e:
            print(f"Error removing {dir_path}: {e}")
    
    # Remove .pyc and .pyo files
    for file_path in pyc_files:
        try:
            os.remove(file_path)
            print(f"Removed: {file_path}")
        except Exception as e:
            print(f"Error removing {file_path}: {e}")
    
    print(f"Cleaned up {len(pycache_dirs)} __pycache__ directories and {len(pyc_files)} .pyc/.pyo files")

def main():
    ""Main function to organize the project."""
    # Create necessary directories
    script_dir = 'scripts'
    log_dir = 'logs'
    
    # Move Python scripts to scripts directory
    print("\n=== Moving Python scripts ===")
    move_files("**/*.py", script_dir, "Python scripts")
    
    # Move log files to logs directory
    print("\n=== Moving log files ===")
    move_files("**/*.log", log_dir, "log files")
    
    # Clean up Python cache files
    print("\n=== Cleaning Python cache files ===")
    clean_pycache()
    
    print("\nProject organization complete!")

if __name__ == "__main__":
    main()
