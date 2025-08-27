"""
Directory structure setup script for SIEM project.

This script creates the recommended directory structure for the SIEM project.
"""
import os
from pathlib import Path

# Base directories to create
BASE_DIR = Path(__file__).parent
DIRECTORIES = [
    # Configuration
    'config/compliance',
    'config/correlation_rules',
    'config/logging',
    'config/services',
    
    # Documentation
    'docs/architecture',
    'docs/api',
    'docs/deployment',
    
    # Source code
    'src/common/auth',
    'src/common/config',
    'src/common/database',
    'src/common/logging',
    'src/common/utils',
    'src/common/web',
    
    # Core framework
    'src/core/base',
    'src/core/events',
    'src/core/services',
    'src/core/utils',
    
    # Services
    'src/services/hips/core',
    'src/services/hips/models',
    'src/services/hips/rules',
    'src/services/hips/utils',
    
    'src/services/nips/core',
    'src/services/nips/models',
    'src/services/nips/rules',
    'src/services/nips/utils',
    
    'src/services/dlp/core',
    'src/services/dlp/models',
    'src/services/dlp/rules',
    'src/services/dlp/utils',
    
    # API
    'src/api/v1',
    'src/api/middleware',
    
    # Tests
    'tests/unit',
    'tests/integration',
    'tests/e2e',
    
    # Deployments
    'deployments/docker',
    'deployments/kubernetes',
    'deployments/terraform',
    
    # Tools
    'tools/lint',
    'tools/test',
    'tools/docs',
    
    # Scripts
    'scripts/deployment',
    'scripts/database',
    'scripts/tools',
]

def create_directories():
    """Create all directories in the specified structure."""
    created = 0
    skipped = 0
    
    for dir_path in DIRECTORIES:
        full_path = BASE_DIR / dir_path
        try:
            full_path.mkdir(parents=True, exist_ok=True)
            if not (full_path / '.gitkeep').exists():
                (full_path / '.gitkeep').touch()
            print(f"Created: {dir_path}")
            created += 1
        except Exception as e:
            print(f"Error creating {dir_path}: {e}")
            skipped += 1
    
    return created, skipped

if __name__ == "__main__":
    print("Setting up SIEM project directory structure...")
    created, skipped = create_directories()
    print(f"\nDirectory setup complete!")
    print(f"Created: {created} directories")
    print(f"Skipped: {skipped} directories (already exist or error)")
