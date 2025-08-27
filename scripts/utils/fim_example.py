"""
FIM Example - Demonstrates the File Integrity Monitoring (FIM) system.
"""
import os
import time
import tempfile
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_test_files():
    """Create test files for FIM testing."""
    test_dir = Path(tempfile.mkdtemp(prefix="fim_test_"))
    logger.info(f"Created test directory: {test_dir}")
    
    # Create some test files
    test_files = [
        (test_dir / "important_config.ini", "[database]\nhost=localhost\nport=5432\ndbname=mydb"),
        (test_dir / "secret_key.pem", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...\n-----END PRIVATE KEY-----"),
        (test_dir / "app_config.json", '{"api_key": "abc123xyz", "debug": false}'),
        (test_dir / "data.csv", "id,name,email\n1,John Doe,john@example.com\n2,Jane Smith,jane@example.com")
    ]
    
    for file_path, content in test_files:
        with open(file_path, 'w') as f:
            f.write(content)
        logger.debug(f"Created test file: {file_path}")
    
    return test_dir

def test_fim_system():
    """Test the FIM system with sample files."""
    from src.fim.manager import FIMManager
    
    # Create test files
    test_dir = create_test_files()
    
    try:
        # Initialize FIM manager
        fim = FIMManager()
        
        # Add test directory to monitoring
        print(f"\nAdding directory to monitoring: {test_dir}")
        count = fim.add_directory(str(test_dir))
        print(f"Added {count} files to monitoring")
        
        # Start monitoring
        print("\nStarting FIM monitoring...")
        fim.start()
        
        # Let it run for a bit
        print("\nFIM is running. Try modifying the test files in:")
        print(f"  {test_dir}")
        print("\nPress Ctrl+C to stop...")
        
        # Simulate file changes after a delay
        time.sleep(5)
        
        # Modify a file
        test_file = test_dir / "important_config.ini"
        print(f"\nModifying file: {test_file}")
        with open(test_file, 'a') as f:
            f.write("\n# This line was added after monitoring started")
        
        # Wait for detection
        time.sleep(2)
        
        # Verify all files
        print("\nRunning verification...")
        results = fim.verify_all()
        
        # Print results
        print("\nVerification Results:")
        print("-" * 50)
        for is_ok, file_path, result in results:
            status = "OK" if is_ok else "MODIFIED"
            print(f"{file_path}: {status}")
            if not is_ok:
                print(f"  Reason: {result.get('reason', 'Unknown')}")
        
        # Print summary
        modified = sum(1 for r in results if not r[0])
        print(f"\nSummary: {len(results)} files checked, {modified} modified")
        
    except KeyboardInterrupt:
        print("\nStopping FIM...")
    
    finally:
        # Clean up
        if 'fim' in locals():
            fim.stop()
        
        # Remove test files
        try:
            import shutil
            shutil.rmtree(test_dir, ignore_errors=True)
            logger.info(f"Cleaned up test directory: {test_dir}")
        except Exception as e:
            logger.warning(f"Failed to clean up test directory: {e}")

def main():
    """Main function to run the FIM example."""
    print("=== SIEM File Integrity Monitoring (FIM) Test ===\n")
    print("This example demonstrates the File Integrity Monitoring system.")
    print("It will create test files, monitor them, and detect changes.\n")
    
    try:
        test_fim_system()
    except Exception as e:
        print(f"\nError: {e}")
        logger.exception("FIM test failed")
    
    print("\nTest complete. You can now check the FIM view in the SIEM application.")

if __name__ == "__main__":
    main()
