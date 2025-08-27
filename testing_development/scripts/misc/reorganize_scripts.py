"""
Reorganize scripts into logical categories.

This script moves scripts into categorized directories for better organization.
"""
import os
import shutil
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).parent.parent
SCRIPTS_DIR = BASE_DIR / 'scripts'

# Script categories and their patterns
CATEGORIES = {
    'setup': [
        'setup', 'install', 'bootstrap', 'init', 'requirements', 'environment', 'venv'
    ],
    'deployment': [
        'deploy', 'publish', 'release', 'build', 'package', 'container', 'docker', 'kubernetes', 'aws', 'azure', 'gcp'
    ],
    'maintenance': [
        'clean', 'backup', 'migrate', 'update', 'upgrade', 'check', 'verify', 'validate', 'audit', 'cleanup', 'fix', 'repair'
    ],
    'development': [
        'dev', 'test', 'debug', 'generate', 'create', 'new', 'run', 'start', 'stop', 'build', 'format', 'lint', 'typecheck'
    ],
    'database': [
        'db_', 'migrate_', 'seed_', 'backup_', 'restore_', 'sql_', 'mongo_', 'postgres_', 'mysql_'
    ],
    'monitoring': [
        'monitor', 'stats', 'metrics', 'log', 'status', 'health', 'performance'
    ]
}

def categorize_script(script_name: str) -> str:
    """Determine the category for a script based on its name."""
    script_lower = script_name.lower()
    
    for category, patterns in CATEGORIES.items():
        if any(pattern.lower() in script_lower for pattern in patterns):
            return category
    
    return 'misc'

def reorganize_scripts():
    """Reorganize scripts into categorized directories."""
    # Create category directories
    for category in list(CATEGORIES.keys()) + ['misc']:
        (SCRIPTS_DIR / category).mkdir(exist_ok=True)
        (SCRIPTS_DIR / category / '__init__.py').touch(exist_ok=True)
    
    # Move scripts to appropriate categories
    moved_count = 0
    
    for script in SCRIPTS_DIR.glob('*.py'):
        if script.name == '__init__.py' or script.name == 'reorganize_scripts.py':
            continue
            
        category = categorize_script(script.name)
        target_dir = SCRIPTS_DIR / category
        
        # Move the script
        target_path = target_dir / script.name
        shutil.move(str(script), str(target_path))
        print(f"Moved: {script.name} -> {category}/")
        moved_count += 1
    
    print(f"\nReorganization complete! Moved {moved_count} scripts.")
    print("\nScript categories:")
    for category in sorted(list(CATEGORIES.keys()) + ['misc']):
        count = len(list((SCRIPTS_DIR / category).glob('*.py'))) - 1  # Subtract __init__.py
        print(f"- {category}: {count} scripts")

if __name__ == "__main__":
    print("Reorganizing scripts...\n")
    reorganize_scripts()
