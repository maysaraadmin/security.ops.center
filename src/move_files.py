import os
import shutil
from pathlib import Path

# Project root directory
PROJECT_ROOT = Path(__file__).parent

# Define source and destination paths for moving files
MOVE_RULES = [
    # Web files
    ('web/static', 'web/static'),
    ('web/templates', 'web/templates'),
    ('web/*.py', 'src/web'),
    
    # EDR files
    ('edr', 'src/edr'),
    
    # Scripts
    ('scripts', 'scripts'),
    
    # Config
    ('config', 'config'),
    
    # Tests
    ('tests', 'tests'),
    
    # Documentation
    ('docs', 'docs'),
    
    # Root Python files
    ('*.py', 'src')
]

def move_files():
    """Move files to their new locations based on the defined rules."""
    print("Moving files to their new locations...\n")
    
    for src_pattern, dst_dir in MOVE_RULES:
        src_path = PROJECT_ROOT / src_pattern
        dst_path = PROJECT_ROOT / dst_dir
        
        # Create destination directory if it doesn't exist
        dst_path.mkdir(parents=True, exist_ok=True)
        
        # Handle wildcards in source pattern
        if '*' in src_pattern:
            # Get the parent directory of the pattern
            parent_dir = Path(src_pattern).parent
            if parent_dir == Path('.'):
                parent_dir = PROJECT_ROOT
            else:
                parent_dir = PROJECT_ROOT / parent_dir
            
            # Get the pattern to match
            pattern = Path(src_pattern).name
            
            # Find all matching files
            for file_path in parent_dir.glob(pattern):
                if file_path.is_file():
                    try:
                        shutil.move(str(file_path), str(dst_path / file_path.name))
                        print(f"Moved: {file_path} -> {dst_path / file_path.name}")
                    except Exception as e:
                        print(f"Error moving {file_path}: {e}")
        else:
            # Handle directory moves
            if src_path.is_dir():
                for item in src_path.glob('*'):
                    if item.is_file():
                        try:
                            shutil.move(str(item), str(dst_path / item.name))
                            print(f"Moved: {item} -> {dst_path / item.name}")
                        except Exception as e:
                            print(f"Error moving {item}: {e}")
    
    print("\nFile moving completed!")

if __name__ == "__main__":
    print("Starting file reorganization...\n")
    move_files()
    print("\nReorganization complete!")
