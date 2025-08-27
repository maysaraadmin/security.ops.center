"""
Test script to verify the Python environment and basic imports.
"""

import sys
import os
import platform
import importlib
from pathlib import Path

def print_section(title):
    """Print a section header."""
    print("\n" + "=" * 50)
    print(f"{title.upper()}")
    print("=" * 50)

def test_python_environment():
    """Test the Python environment."""
    print_section("Python Environment")
    print(f"Python Version: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"Current Working Directory: {os.getcwd()}")
    print(f"Python Path: {sys.path}")

def test_imports():
    """Test importing required packages."""
    print_section("Testing Imports")
    
    packages = [
        'yaml',
        'pydantic',
        'fastapi',
        'uvicorn',
        'sqlalchemy',
        'psutil',
        'cryptography',
        'pandas',
        'numpy',
        'requests'
    ]
    
    for pkg in packages:
        try:
            module = importlib.import_module(pkg)
            print(f"✅ {pkg}: {module.__version__ if hasattr(module, '__version__') else 'loaded'}")
        except ImportError as e:
            print(f"❌ {pkg}: {e}")

def test_project_structure():
    """Test the project directory structure."""
    print_section("Project Structure")
    
    required_dirs = [
        'src',
        'config',
        'logs',
        'data',
        'tests'
    ]
    
    for dir_name in required_dirs:
        path = Path(dir_name)
        if path.exists() and path.is_dir():
            print(f"✅ {dir_name}/: Found")
        else:
            print(f"❌ {dir_name}/: Missing")

def main():
    """Main test function."""
    test_python_environment()
    test_imports()
    test_project_structure()
    
    print_section("Test Complete")
    print("Check the output above for any errors.")

if __name__ == "__main__":
    main()
