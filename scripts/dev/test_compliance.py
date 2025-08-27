"""
Test cases for the Compliance Module.
"""

import unittest
import os
import json
import tempfile
import shutil
from datetime import datetime, timedelta

# Add the parent directory to the path so we can import the compliance module
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compliance.manager import ComplianceManager
from models.database import Database

class TestComplianceManager(unittest.TestCase):
    """Test cases for the ComplianceManager class."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures before any tests are run."""
        # Create a temporary directory for test data
        cls.test_dir = tempfile.mkdtemp()
        
        # Create a test database
        cls.db_path = os.path.join(cls.test_dir, 'test_compliance.db')
        cls.db = Database(cls.db_path)
        
        # Set up test templates directory
        cls.templates_dir = os.path.join(cls.test_dir, 'templates')
        os.makedirs(cls.templates_dir, exist_ok=True)
        
        # Create a simple test template
        cls.test_template = {
            "standard": "TEST",
            "version": "1.0",
            "description": "Test compliance standard",
            "requirements": [
                {
                    "id": "REQ-001",
                    "description": "Test requirement 1",
                    "controls": ["control1", "control2"]
                },
                {
                    "id": "REQ-002",
                    "description": "Test requirement 2",
                    "controls": ["control3"]
                }
            ]
        }
        
        # Save the test template
        with open(os.path.join(cls.templates_dir, 'test.json'), 'w') as f:
            json.dump(cls.test_template, f)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests have run."""
        # Remove the temporary directory and all its contents
        shutil.rmtree(cls.test_dir)
    
    def setUp(self):
        """Set up test fixtures before each test method is called."""
        # Create a new ComplianceManager instance for each test
        self.manager = ComplianceManager(self.db, self.templates_dir)
    
    def tearDown(self):
        """Clean up after each test method is called."""
        # Close the database connection
        if hasattr(self, 'manager') and self.manager:
            if hasattr(self.manager, 'db') and self.manager.db:
                self.manager.db.close()
    
    def test_load_templates(self):
        """Test that templates are loaded correctly."""
        # Check that the test template was loaded
        self.assertIn('test', self.manager.templates)
        self.assertEqual(self.manager.templates['test']['standard'], 'TEST')
    
    def test_get_available_standards(self):
        """Test getting the list of available standards."""
        standards = self.manager.get_available_standards()
        self.assertIn('test', standards)
    
    def test_get_standard_template(self):
        """Test getting a specific standard template."""
        template = self.manager.get_standard_template('test')
        self.assertIsNotNone(template)
        self.assertEqual(template['standard'], 'TEST')
        
        # Test with non-existent standard
        self.assertIsNone(self.manager.get_standard_template('nonexistent'))
    
    def test_check_compliance(self):
        """Test checking compliance with a standard."""
        # Check compliance with the test standard
        results = self.manager.check_compliance('test')
        
        # Check the results structure
        self.assertIn('status', results)
        self.assertIn('standards', results)
        self.assertIn('test', results['standards'])
        
        # Check the standard status
        std_status = results['standards']['test']
        self.assertEqual(std_status['standard'], 'TEST')
        self.assertEqual(std_status['version'], '1.0')
        self.assertEqual(std_status['status'], 'compliant')
        
        # Check that requirements were processed
        self.assertEqual(len(std_status['checks']), 2)
        self.assertEqual(std_status['checks'][0]['id'], 'REQ-001')
        self.assertEqual(std_status['checks'][0]['status'], 'compliant')
        self.assertEqual(std_status['checks'][1]['id'], 'REQ-002')
        self.assertEqual(std_status['checks'][1]['status'], 'compliant')
    
    def test_check_compliance_all_standards(self):
        """Test checking compliance with all standards."""
        results = self.manager.check_compliance()
        
        # Check the results structure
        self.assertIn('status', results)
        self.assertIn('standards', results)
        self.assertGreater(len(results['standards']), 0)
        
        # Check that our test standard is included
        self.assertIn('test', results['standards'])
    
    def test_generate_report(self):
        """Test generating a compliance report."""
        # Generate a JSON report
        report = self.manager.generate_report('test', 'json')
        
        # Check the report structure
        self.assertIn('status', report)
        self.assertEqual(report['format'], 'json')
        self.assertIn('data', report)
        
        # Check the report data
        data = report['data']
        self.assertIn('metadata', data)
        self.assertIn('compliance_status', data)
        
        # Check that the standard is included in the report
        self.assertIn('test', data['compliance_status'])
    
    def test_export_report(self):
        """Test exporting a report to a file."""
        # Create a temporary file for the report
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as f:
            report_path = f.name
        
        try:
            # Generate and export a report
            report = self.manager.generate_report('test', 'json')
            success = self.manager.export_report(report, report_path)
            
            # Check that the export was successful
            self.assertTrue(success)
            self.assertTrue(os.path.exists(report_path))
            
            # Check that the file contains valid JSON
            with open(report_path, 'r') as f:
                exported_data = json.load(f)
                self.assertIn('status', exported_data)
                self.assertEqual(exported_data['format'], 'json')
                
        finally:
            # Clean up the temporary file
            if os.path.exists(report_path):
                os.remove(report_path)
    
    def test_alert_callbacks(self):
        """Test alert callbacks."""
        # Create a list to store alerts
        alerts = []
        
        # Define a callback function
        def alert_callback(alert_data):
            alerts.append(alert_data)
        
        # Register the callback
        self.manager.add_alert_callback(alert_callback)
        
        # Generate an alert
        test_alert = {
            'type': 'test_alert',
            'message': 'This is a test alert',
            'timestamp': datetime.utcnow().isoformat()
        }
        self.manager._notify_alert(test_alert)
        
        # Check that the callback was called
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['type'], 'test_alert')
        
        # Test removing the callback
        self.manager.remove_alert_callback(alert_callback)
        self.manager._notify_alert(test_alert)
        self.assertEqual(len(alerts), 1)  # Should still be 1
    
    def test_compliance_status(self):
        """Test getting and updating compliance status."""
        # Get initial status
        status = self.manager.get_compliance_status()
        self.assertIsNotNone(status)
        self.assertIn('last_checked', status)
        self.assertIn('standards', status)
        
        # Run a compliance check to update the status
        self.manager.check_compliance('test')
        
        # Get the updated status
        updated_status = self.manager.get_compliance_status('test')
        self.assertIsNotNone(updated_status)
        self.assertEqual(updated_status['standard'], 'TEST')
        self.assertEqual(updated_status['status'], 'compliant')


if __name__ == '__main__':
    unittest.main()
