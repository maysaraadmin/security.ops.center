#!/usr/bin/env python3
"""Script to reorganize the SIEM project structure."""
import os
import shutil
from pathlib import Path

def create_directory_structure(base_path):
    """Create the new directory structure."""
    # Main directories
    dirs = [
        # Main package
        "siem/core",
        "siem/models",
        "siem/services",
        "siem/api",
        "siem/ui",
        
        # Security modules
        "security_modules/edr",
        "security_modules/dlp",
        "security_modules/fim",
        "security_modules/ndr",
        "security_modules/nips",
        "security_modules/hips",
        "security_modules/ueba",
        
        # Infrastructure
        "infrastructure/config",
        "infrastructure/database",
        "infrastructure/deployments",
        "infrastructure/utils",
        
        # Testing & Development
        "testing_development/tests/unit",
        "testing_development/tests/integration",
        "testing_development/scripts",
        "testing_development/docs",
        
        # Data & Logs (will be created at runtime if not exists)
        "data_logs/data",
        "data_logs/logs",
        "data_logs/backups"
    ]
    
    # Create directories
    for directory in dirs:
        path = base_path / directory
        path.mkdir(parents=True, exist_ok=True)
        # Add __init__.py to make them Python packages
        (path / "__init__.py").touch(exist_ok=True)
    
    print("Directory structure created successfully.")

def main():
    """Main function to run the reorganization."""
    base_path = Path(__file__).parent.parent
    create_directory_structure(base_path)
    print("Reorganization script completed.")
    print("Next steps:")
    print("1. Move files to their new locations")
    print("2. Update import statements")
    print("3. Update configuration files")
    print("4. Run tests to ensure everything works")

if __name__ == "__main__":
    main()
