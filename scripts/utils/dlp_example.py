"""
DLP Example - Demonstrates the Data Loss Prevention (DLP) system.
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
    """Create test files with sensitive and non-sensitive content."""
    test_dir = Path(tempfile.mkdtemp(prefix="dlp_test_"))
    logger.info(f"Created test directory: {test_dir}")
    
    # Test files with sensitive data
    sensitive_files = {
        "credit_card.txt": "My credit card number is 4111-1111-1111-1111. Please don't share this.",
        "ssn.txt": "Employee SSN: 123-45-6789. Keep this confidential.",
        "api_keys.txt": "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nAPI_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "config.ini": "[database]\nuser=admin\npassword=supersecret123\nhost=localhost",
        "email_list.csv": "name,email\nJohn Doe,john@example.com\nJane Smith,jane@example.com"
    }
    
    # Test files without sensitive data
    normal_files = {
        "readme.txt": "This is a normal text file without any sensitive information.",
        "config.json": "{\"theme\": \"dark\", \"notifications\": true}",
        "empty.txt": ""
    }
    
    # Create test files
    for filename, content in {**sensitive_files, **normal_files}.items():
        filepath = test_dir / filename
        with open(filepath, 'w') as f:
            f.write(content)
        logger.debug(f"Created test file: {filepath}")
    
    return test_dir

def test_dlp_scanning():
    """Test the DLP scanning functionality."""
    from src.dlp.manager import DLPManager
    
    # Create test files
    test_dir = create_test_files()
    
    try:
        # Initialize DLP manager
        dlp = DLPManager()
        
        # Add a custom rule for testing
        from src.dlp.detection_engine import DLPDetectionEngine, DLPRule
        import re
        
        # Create a custom rule for email addresses
        email_rule = DLPRule(
            rule_id="test-email-001",
            name="Test Email Detection",
            description="Detects email addresses in content",
            severity="medium",
            patterns=[
                re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            ],
            keywords=["email", "e-mail", "@"],
            min_confidence=0.7,
            action="alert"
        )
        
        # Add the custom rule to the detection engine
        dlp.detection_engine.add_rule(email_rule)
        
        # Start DLP monitoring
        dlp.start()
        
        # Add test directory to watch
        dlp.add_watch_directory(str(test_dir), recursive=True)
        
        # Wait a moment for file monitoring to pick up the files
        print("\n=== Starting DLP Test ===")
        print(f"Monitoring directory: {test_dir}")
        print("Waiting for file scans to complete...")
        time.sleep(2)  # Give it time to process files
        
        # Print summary
        status = dlp.get_status()
        print("\n=== DLP Test Results ===")
        print(f"Files scanned: {status.get('files_scanned', 0)}")
        print(f"Alerts triggered: {status.get('alerts_triggered', 0)}")
        print(f"Rules loaded: {status.get('rules_loaded', 0)}")
        
        # Print rules
        print("\n=== DLP Rules ===")
        for rule in dlp.get_rules():
            print(f"- {rule['name']} ({rule['id']}): {rule['description']} (Severity: {rule['severity']}, Enabled: {rule['enabled']})")
        
        # Print last few alerts if any
        print("\n=== Alerts ===")
        if status.get('alerts_triggered', 0) > 0:
            print(f"Last alert at: {status.get('last_alert')}")
            # In a real test, we would have a way to retrieve the alerts
            print("Check the DLP view in the SIEM application for detailed alerts.")
        else:
            print("No alerts triggered.")
        
        print("\nTest completed. Check the SIEM application for more details.")
        
    except Exception as e:
        logger.error(f"Error during DLP test: {e}", exc_info=True)
        raise
    finally:
        # Clean up test files
        try:
            import shutil
            shutil.rmtree(test_dir, ignore_errors=True)
            logger.info(f"Cleaned up test directory: {test_dir}")
        except Exception as e:
            logger.warning(f"Failed to clean up test directory: {e}")

def main():
    """Main function to run the DLP example."""
    print("=== SIEM DLP System Test ===\n")
    print("This example demonstrates the Data Loss Prevention (DLP) system.")
    print("It will create test files with sensitive data and monitor them.")
    print("The DLP system should detect and alert on sensitive information.\n")
    
    try:
        test_dlp_scanning()
    except KeyboardInterrupt:
        print("\nTest interrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")
        logger.exception("DLP test failed")
    
    print("\nTest complete. You can now check the DLP view in the SIEM application.")

if __name__ == "__main__":
    main()
