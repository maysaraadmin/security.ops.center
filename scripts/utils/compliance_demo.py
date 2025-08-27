"""
Compliance Module Demo

This script demonstrates how to use the Compliance Module to manage compliance
with various regulatory standards in a SIEM system.
"""

import os
import json
import logging
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add the parent directory to the path so we can import the compliance module
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compliance.manager import ComplianceManager
from models.database import Database

def setup_compliance_manager():
    """Set up and return a ComplianceManager instance with test data."""
    # Create an in-memory database for testing
    db = Database(":memory:")
    
    # Get the path to the compliance templates directory
    templates_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'compliance',
        'templates'
    )
    
    # Create the ComplianceManager
    manager = ComplianceManager(db, templates_dir)
    
    return manager

def demo_compliance_checks(manager):
    """Demonstrate compliance checking functionality."""
    logger.info("=== Starting Compliance Check Demo ===")
    
    # Get available standards
    standards = manager.get_available_standards()
    logger.info(f"Available compliance standards: {', '.join(standards)}")
    
    # Check compliance for all standards
    logger.info("\n=== Checking Compliance for All Standards ===")
    results = manager.check_compliance()
    
    # Print summary of results
    logger.info("\n=== Compliance Check Results ===")
    for std, status in results['standards'].items():
        logger.info(f"{std.upper()}: {status['status'].upper()}")
    
    # Get detailed status for a specific standard
    if standards:
        std = standards[0]  # Use the first available standard
        logger.info(f"\n=== Detailed Status for {std.upper()} ===")
        status = manager.get_compliance_status(std)
        
        # Print standard info
        logger.info(f"Standard: {status.get('standard', std.upper())}")
        logger.info(f"Version: {status.get('version', 'N/A')}")
        logger.info(f"Status: {status.get('status', 'unknown').upper()}")
        logger.info(f"Last Checked: {status.get('last_checked', 'Never')}")
        
        # Print requirements status
        if 'checks' in status:
            logger.info("\nRequirements:")
            for check in status['checks']:
                logger.info(f"  {check['id']}: {check['description']} - {check['status'].upper()}")
    
    logger.info("\n=== Compliance Check Demo Complete ===\n")

def demo_report_generation(manager):
    """Demonstrate report generation functionality."""
    logger.info("=== Starting Report Generation Demo ===")
    
    # Get available standards
    standards = manager.get_available_standards()
    if not standards:
        logger.warning("No compliance standards available for report generation")
        return
    
    # Generate a report for each standard
    for std in standards:
        logger.info(f"\nGenerating {std.upper()} compliance report...")
        
        # Generate a JSON report
        report = manager.generate_report(std, 'json')
        
        if report['status'] == 'success':
            # Print a summary of the report
            data = report['data']
            metadata = data['metadata']
            
            logger.info(f"Report: {metadata['title']}")
            logger.info(f"Generated at: {metadata['generated_at']}")
            
            # Print compliance status
            status = data['compliance_status'].get(std, {})
            logger.info(f"Status: {status.get('status', 'unknown').upper()}")
            
            # Save the report to a file
            report_dir = os.path.join(os.path.expanduser('~'), 'compliance_reports')
            os.makedirs(report_dir, exist_ok=True)
            
            report_file = os.path.join(
                report_dir, 
                f"{std}_compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Report saved to: {report_file}")
        else:
            logger.error(f"Failed to generate {std.upper()} report: {report.get('message', 'Unknown error')}")
    
    logger.info("\n=== Report Generation Demo Complete ===\n")

def demo_alerting(manager):
    """Demonstrate the alerting functionality."""
    logger.info("=== Starting Alerting Demo ===")
    
    # Define an alert callback function
    def alert_callback(alert):
        logger.warning(f"ALERT: {alert.get('type', 'Unknown')} - {alert.get('message', 'No message')}")
        logger.warning(f"Timestamp: {alert.get('timestamp')}")
    
    # Register the callback
    manager.add_alert_callback(alert_callback)
    
    # Simulate a compliance alert
    logger.info("Sending test alert...")
    manager._notify_alert({
        'type': 'compliance_violation',
        'message': 'Test compliance violation detected',
        'severity': 'high',
        'standard': 'test',
        'requirement': 'REQ-001',
        'timestamp': datetime.utcnow().isoformat()
    })
    
    # Unregister the callback
    manager.remove_alert_callback(alert_callback)
    
    logger.info("=== Alerting Demo Complete ===\n")

def main():
    """Main function to run the compliance demo."""
    try:
        # Set up the compliance manager
        logger.info("Setting up Compliance Manager...")
        manager = setup_compliance_manager()
        
        # Run the demos
        demo_compliance_checks(manager)
        demo_report_generation(manager)
        demo_alerting(manager)
        
        logger.info("Compliance Module Demo Completed Successfully!")
        
    except Exception as e:
        logger.error(f"Error in compliance demo: {str(e)}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
