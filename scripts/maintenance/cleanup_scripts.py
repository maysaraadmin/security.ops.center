#!/usr/bin/env python3
"""
Script Cleanup Utility

This script identifies and renames any Python files in the scripts directory
that conflict with Python standard library module names.
"""
import os
import shutil
from pathlib import Path

# List of Python standard library module names to avoid
STD_LIB_MODULES = {
    'os', 'sys', 're', 'json', 'collections', 'pathlib', 'threading',
    'warnings', 'typing', 'datetime', 'logging', 'subprocess', 'shutil',
    'argparse', 'itertools', 'functools', 'random', 'time', 'math'
}

def find_conflicting_scripts():
    """Find scripts with names that conflict with Python standard library modules."""
    scripts_dir = Path('scripts')
    conflicts = []
    
    for script_file in scripts_dir.glob('*.py'):
        module_name = script_file.stem
        if module_name in STD_LIB_MODULES:
            conflicts.append(script_file)
    
    return conflicts

def rename_conflicts():
    """Rename conflicting script files."""
    conflicts = find_conflicting_scripts()
    
    if not conflicts:
        print("No conflicting script names found.")
        return
    
    print("Found the following script name conflicts with Python standard library:")
    for script in conflicts:
        print(f"- {script.name}")
    
    print("\nRenaming conflicting files...")
    for script in conflicts:
        new_name = f"{script.stem}_utils.py"
        new_path = script.with_name(new_name)
        
        # Handle case where the target name already exists
        counter = 1
        while new_path.exists():
            new_name = f"{script.stem}_utils_{counter}.py"
            new_path = script.with_name(new_name)
            counter += 1
        
        try:
            script.rename(new_path)
            print(f"Renamed: {script.name} -> {new_path.name}")
        except Exception as e:
            print(f"Error renaming {script}: {e}")

def main():
    """Main function to run the cleanup."""
    print("=== Script Cleanup Utility ===\n")
    rename_conflicts()
    print("\nCleanup complete!")

if __name__ == "__main__":
    main()
