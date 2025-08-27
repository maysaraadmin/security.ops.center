"""
Test script for Compliance Module integration with SIEM dashboard.

This script tests the integration of the Compliance Module with the main SIEM application,
including the GUI components and their interaction with the ComplianceManager.
"""

import os
import sys
import unittest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
import tkinter as tk
from tkinter import ttk

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from compliance.manager import ComplianceManager
from views.compliance_view import ComplianceView

class TestComplianceIntegration(unittest.TestCase):
    """Test cases for Compliance Module integration."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment before any tests run."""
        # Create a temporary directory for test data
        cls.test_dir = tempfile.mkdtemp()
        
        # Create a test templates directory
        cls.templates_dir = os.path.join(cls.test_dir, 'templates')
        os.makedirs(cls.templates_dir, exist_ok=True)
        
        # Create a test reports directory
        cls.reports_dir = os.path.join(cls.test_dir, 'reports')
        os.makedirs(cls.reports_dir, exist_ok=True)
        
        # Create a test template
        cls.test_template = {
            "name": "GDPR",
            "version": "1.0",
            "description": "General Data Protection Regulation",
            "checks": [
                {
                    "id": "gdpr_1",
                    "description": "Data encryption in transit",
                    "severity": "high",
                    "remediation": "Enable TLS 1.2 or higher"
                },
                {
                    "id": "gdpr_2",
                    "description": "Data retention policy",
                    "severity": "medium",
                    "remediation": "Define and implement data retention policies"
                }
            ]
        }
        
        # Save test template to file
        with open(os.path.join(cls.templates_dir, 'gdpr.json'), 'w') as f:
            json.dump(cls.test_template, f)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests have run."""
        # Remove the temporary directory and all its contents
        shutil.rmtree(cls.test_dir)
    
    def setUp(self):
        """Set up before each test method."""
        # Create a root window (hidden for testing)
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the root window
        
        # Create a test frame
        self.frame = ttk.Frame(self.root)
        self.frame.pack()
        
        # Initialize ComplianceManager with test paths
        self.compliance_manager = ComplianceManager(
            templates_dir=self.templates_dir,
            reports_dir=self.reports_dir
        )
        
        # Create the ComplianceView
        self.compliance_view = ComplianceView(
            parent=self.frame,
            compliance_manager=self.compliance_manager
        )
    
    def tearDown(self):
        """Clean up after each test method."""
        # Destroy the root window
        self.root.destroy()
    
    def test_initialization(self):
        """Test that the ComplianceView initializes correctly."""
        self.assertIsNotNone(self.compliance_view)
        self.assertIsInstance(self.compliance_view.frame, ttk.Frame)
    
    def test_load_standards(self):
        """Test loading compliance standards."""
        # Trigger the _load_initial_data method
        self.compliance_view._load_initial_data()
        
        # Check if standards are loaded
        standards = self.compliance_view.compliance_manager.get_available_standards()
        self.assertIn("GDPR", standards)
        
        # Check if standards are displayed in the treeview
        items = self.compliance_view.standards_tree.get_children()
        self.assertGreater(len(items), 0)
    
    def test_compliance_check(self):
        """Test running a compliance check."""
        # Mock the check_compliance method
        with patch.object(self.compliance_manager, 'check_compliance') as mock_check:
            # Set up the mock to return a test result
            mock_check.return_value = {
                'status': 'success',
                'standards': {
                    'GDPR': {
                        'status': 'non_compliant',
                        'last_checked': '2023-01-01 12:00:00',
                        'results': [
                            {
                                'id': 'gdpr_1',
                                'status': 'fail',
                                'details': 'TLS not enabled'
                            }
                        ]
                    }
                }
            }
            
            # Run the compliance check
            self.compliance_view.check_compliance()
            
            # Check if the mock was called
            mock_check.assert_called_once()
    
    def test_report_generation(self):
        """Test generating a compliance report."""
        # Mock the generate_report method
        with patch.object(self.compliance_manager, 'generate_report') as mock_generate:
            # Set up the mock to return a test report
            test_report_path = os.path.join(self.reports_dir, 'GDPR_20230101_120000.pdf')
            mock_generate.return_value = {
                'status': 'success',
                'message': 'Report generated successfully',
                'report_path': test_report_path
            }
            
            # Set a current standard
            self.compliance_view.current_standard = 'GDPR'
            
            # Generate a report
            self.compliance_view.generate_report()
            
            # Check if the mock was called
            mock_generate.assert_called_once()
    
    def test_settings_management(self):
        """Test saving and loading settings."""
        # Set test values
        self.compliance_view.auto_check_var.set(False)
        self.compliance_view.report_format_var.set('html')
        self.compliance_view.report_dir_var.set('/custom/reports')
        
        # Save settings
        self.compliance_view.save_settings()
        
        # Reset values
        self.compliance_view.auto_check_var.set(True)
        self.compliance_view.report_format_var.set('pdf')
        self.compliance_view.report_dir_var.set('')
        
        # Load settings
        self.compliance_view.load_settings()
        
        # Check if values were loaded correctly
        self.assertFalse(self.compliance_view.auto_check_var.get())
        self.assertEqual(self.compliance_view.report_format_var.get(), 'html')
        self.assertEqual(self.compliance_view.report_dir_var.get(), '/custom/reports')

if __name__ == '__main__':
    unittest.main()
