"""
Test script for the enhanced SimpleSIEM implementation.
"""

import os
import sys
import time
import logging
import tempfile
import yaml
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import the SimpleSIEM class
from src.siem.core.simple_siem import SimpleSIEM

def test_simple_siem():
    """Test the SimpleSIEM with a basic configuration."""
    print("Testing SimpleSIEM with basic configuration...")
    
    # Create a temporary directory for logs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a test configuration
        config = {
            'logging': {
                'level': 'DEBUG',
                'console': {
                    'enabled': True,
                    'level': 'INFO',
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                },
                'file': {
                    'enabled': True,
                    'path': os.path.join(temp_dir, 'siem.log'),
                    'level': 'DEBUG',
                    'max_size': 1,  # 1 MB
                    'backup_count': 3,
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                }
            },
            'components': {
                'enabled': ['test_component']
            }
        }
        
        # Create and start the SIEM
        siem = SimpleSIEM(config)
        
        try:
            # Start the SIEM in a separate thread
            import threading
            siem_thread = threading.Thread(target=siem.start)
            siem_thread.daemon = True
            siem_thread.start()
            
            # Let it run for a few seconds
            print("SIEM is running (press Ctrl+C to stop)...")
            time.sleep(5)
            
            # Stop the SIEM
            print("Stopping SIEM...")
            siem.stop()
            siem_thread.join(timeout=5)
            
            # Verify log file was created
            log_file = config['logging']['file']['path']
            if os.path.exists(log_file):
                print(f"✅ Log file created: {log_file}")
                with open(log_file, 'r') as f:
                    log_content = f.read()
                    print(f"Log content (first 500 chars):\n{log_content[:500]}...")
            else:
                print(f"❌ Log file not found: {log_file}")
            
            return True
            
        except KeyboardInterrupt:
            print("\nTest interrupted by user")
            siem.stop()
            return False
        except Exception as e:
            print(f"❌ Test failed: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return False

def test_config_loading():
    """Test loading configuration from a YAML file."""
    print("\nTesting configuration loading from YAML file...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        config = {
            'logging': {
                'level': 'INFO',
                'console': {
                    'enabled': True,
                    'level': 'INFO'
                },
                'file': {
                    'enabled': True,
                    'path': 'test_siem.log',
                    'max_size': 5,
                    'backup_count': 2
                }
            },
            'components': {
                'enabled': ['test_component']
            }
        }
        yaml.dump(config, f)
        config_file = f.name
    
    try:
        # Load SIEM with config file
        siem = SimpleSIEM(config_file)
        
        # Verify configuration was loaded
        if siem.config.get('logging.level') == 'INFO':
            print("✅ Configuration loaded successfully from YAML file")
            return True
        else:
            print("❌ Failed to load configuration from YAML file")
            return False
            
    finally:
        # Clean up
        if os.path.exists(config_file):
            os.remove(config_file)

def main():
    """Run all tests."""
    tests = [
        ("SimpleSIEM Basic Test", test_simple_siem),
        ("Configuration Loading Test", test_config_loading)
    ]
    
    passed = 0
    for name, test_func in tests:
        print(f"\n{'='*50}")
        print(f"Running test: {name}")
        print(f"{'='*50}")
        
        if test_func():
            print(f"✅ {name} passed")
            passed += 1
        else:
            print(f"❌ {name} failed")
    
    print(f"\nTest results: {passed}/{len(tests)} tests passed")
    return 0 if passed == len(tests) else 1

if __name__ == "__main__":
    sys.exit(main())
