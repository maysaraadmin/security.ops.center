#!/usr/bin/env python3
"""Test script to verify the EDR agent functionality."""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

class TestEDRAgent(unittest.TestCase):
    """Test cases for the EDR agent."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        # Set up test configuration
        os.environ['EDR_CONFIG'] = str(PROJECT_ROOT / 'config' / 'edr_config.yaml')
    
    def test_agent_initialization(self):
        ""Test that the EDR agent can be initialized.""
        from src.edr.agent import EDRAgent
        
        with patch('src.edr.agent.load_config') as mock_load_config:
            mock_load_config.return_value = {
                'agent': {
                    'name': 'test-agent',
                    'version': '1.0.0'
                },
                'monitoring': {
                    'enabled': True,
                    'scan_interval': 60
                }
            }
            
            agent = EDRAgent()
            self.assertEqual(agent.name, 'test-agent')
            self.assertEqual(agent.version, '1.0.0')
    
    def test_detection_rules_loading(self):
        ""Test that detection rules are loaded correctly.""
        from src.edr.detection import load_detection_rules
        
        with patch('builtins.open', unittest.mock.mock_open(
            read_data='{"suspicious_processes": ["malware.exe"], "suspicious_paths": ["/tmp/"]}'
        )):
            rules = load_detection_rules('dummy_path.json')
            self.assertIn('suspicious_processes', rules)
            self.assertIn('suspicious_paths', rules)
            self.assertIn('malware.exe', rules['suspicious_processes'])

if __name__ == '__main__':
    unittest.main()
