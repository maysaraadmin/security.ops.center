"""
Simple script to test component imports.
"""

import sys
import importlib
from pathlib import Path

# Add the project root to the Python path
PROJECT_ROOT = str(Path(__file__).parent.absolute())
sys.path.insert(0, PROJECT_ROOT)

# Components to test
COMPONENTS = [
    "src.siem.launcher",
    "src.edr.launcher",
    "src.dlp.launcher",
    "src.hips.launcher",
    "src.nips.launcher",
]

def test_imports():
    """Test importing all component modules."""
    success = True
    
    for module_name in COMPONENTS:
        try:
            print(f"Importing {module_name}...", end=" ")
            importlib.import_module(module_name)
            print("✅")
        except ImportError as e:
            print(f"❌\n  Error: {e}")
            success = False
    
    return success

if __name__ == "__main__":
    print("Testing component imports...\n" + "="*50)
    
    if test_imports():
        print("\n✅ All imports successful!")
        sys.exit(0)
    else:
        print("\n❌ Some imports failed!")
        sys.exit(1)
