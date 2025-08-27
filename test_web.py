#!/usr/bin/env python3
"""Test script to verify the web application functionality."""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

class TestWebApp(unittest.TestCase):
    """Test cases for the web application."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        # Set up test configuration
        os.environ['FLASK_ENV'] = 'testing'
        os.environ['TESTING'] = 'True'
        
        # Import the app after setting up the environment
        from src.web.app import create_app
        cls.app = create_app()
        cls.client = cls.app.test_client()
    
    def test_home_page(self):
        ""Test the home page returns a 200 status code.""
        with self.app.test_client() as client:
            response = client.get('/')
            self.assertEqual(response.status_code, 200)
    
    def test_login_page(self):
        ""Test the login page returns a 200 status code.""
        with self.app.test_client() as client:
            response = client.get('/login')
            self.assertEqual(response.status_code, 200)
    
    @patch('src.web.app.edr_agent')
    def test_api_status(self, mock_edr_agent):
        ""Test the API status endpoint.""
        # Mock the EDR agent response
        mock_edr_agent.get_status.return_value = {
            'status': 'running',
            'version': '1.0.0',
            'uptime': 3600
        }
        
        with self.app.test_client() as client:
            response = client.get('/api/status')
            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            self.assertIn('status', data)
            self.assertEqual(data['status'], 'running')

if __name__ == '__main__':
    unittest.main()
