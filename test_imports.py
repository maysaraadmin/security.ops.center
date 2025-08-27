#!/usr/bin/env python3
"""Test script to verify all imports and paths in the project."""

import os
import sys
import importlib
from pathlib import Path

# Add the project root to the Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

def test_import(module_name):
    """Test importing a module and print the result."""
    try:
        importlib.import_module(module_name)
        print(f"✅ Successfully imported {module_name}")
        return True
    except ImportError as e:
        print(f"❌ Failed to import {module_name}: {e}")
        return False

def main():
    """Test all imports in the project."""
    print("Testing imports...\n")
    
    # Test core modules
    core_modules = [
        'src.edr.threat_detection',
        'src.edr.rule_manager',
        'src.web.app_enhanced',
        'src.web.config',
    ]
    
    # Test web components
    web_modules = [
        'src.siem.web.routes',
        'src.siem.services.sysmon_service',
    ]
    
    # Test common utilities
    common_modules = [
        'src.common.config',
        'src.common.file_utils',
        'src.common.env_utils',
    ]
    
    # Test SIEM components
    siem_modules = [
        'src.siem.monitoring',
        'src.siem.core.siem',
        'src.siem.collectors.sysmon_collector',
    ]
    
    # Run all tests
    all_modules = core_modules + web_modules + common_modules + siem_modules
    results = [test_import(module) for module in all_modules]
    
    # Print summary
    print("\n" + "="*50)
    print(f"Import test summary: {sum(results)}/{len(results)} modules imported successfully")
    print("="*50)
    
    if all(results):
        print("\n✅ All imports successful!")
        return 0
    else:
        print("\n❌ Some imports failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
