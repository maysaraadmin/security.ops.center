"""
Simple test script to verify launcher functionality.
"""

import sys
import os
import time
from pathlib import Path

# Add the project root to the Python path
PROJECT_ROOT = str(Path(__file__).parent.absolute())
sys.path.insert(0, PROJECT_ROOT)

def test_launcher(component_name, config_path):
    """Test a single component launcher."""
    print(f"\nTesting {component_name} launcher...")
    print("=" * 50)
    
    # Import the launcher module
    try:
        module_name = f"src.{component_name}.launcher"
        print(f"Importing {module_name}...")
        module = __import__(module_name, fromlist=['*'])
        print(f"✅ Successfully imported {module_name}")
        
        # Get the launcher class
        launcher_class = getattr(module, f"{component_name.upper()}Launcher")
        print(f"✅ Found launcher class: {launcher_class.__name__}")
        
        # Create a config dictionary
        config = {
            component_name: {
                "enabled": True,
                "log_level": "DEBUG",
                "log_file": f"logs/{component_name}.log"
            }
        }
        
        # Initialize the launcher
        print(f"\nInitializing {component_name}...")
        launcher = launcher_class(config)
        
        # Test initialization
        if launcher.initialize():
            print(f"✅ {component_name} initialized successfully")
            
            # Test starting
            print(f"\nStarting {component_name}...")
            launcher.start()
            print(f"✅ {component_name} started")
            
            # Let it run for a few seconds
            print(f"\n{component_name} is running for 5 seconds...")
            time.sleep(5)
            
            # Test status
            status = launcher.get_status()
            print(f"\n{component_name} status:")
            for key, value in status.items():
                print(f"  {key}: {value}")
            
            # Test stopping
            print(f"\nStopping {component_name}...")
            launcher.stop()
            print(f"✅ {component_name} stopped")
            
            return True
        else:
            print(f"❌ Failed to initialize {component_name}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing {component_name}: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test function."""
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Test each component
    components = ["siem", "edr", "dlp", "hips", "nips"]
    results = {}
    
    for component in components:
        config_path = os.path.join("config", f"{component}_config.yaml")
        success = test_launcher(component, config_path)
        results[component] = "✅ PASS" if success else "❌ FAIL"
    
    # Print summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    for component, result in results.items():
        print(f"{component.upper()}: {result}")
    print("=" * 50)
    
    # Return appropriate exit code
    if all("PASS" in result for result in results.values()):
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
