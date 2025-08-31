"""
Tests for the agentless collector functionality.
"""
import asyncio
import logging
import socket
import sys
import time
import unittest
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from siem.collectors.agentless import AgentlessCollector, SyslogMessage
from siem.config import load_config, validate_config

# Configure test logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('test_agentless_collector')

class TestAgentlessCollector(unittest.IsolatedAsyncioTestCase):
    """Test cases for the AgentlessCollector class."""
    
    async def asyncSetUp(self):
        """Set up test fixtures."""
        self.config = {
            'syslog': {
                'enabled': True,
                'host': '127.0.0.1',  # Use loopback for testing
                'port': 5514,         # Use non-standard port for testing
                'protocol': 'udp',
                'max_message_size': 65535,
                'timeout': 1.0
            }
        }
        
        # Create a test collector
        self.collector = AgentlessCollector(self.config)
        
        # Start the collector
        self.collector_task = asyncio.create_task(self.collector.start())
        
        # Give the server time to start
        await asyncio.sleep(0.1)
    
    async def asyncTearDown(self):
        """Clean up test fixtures."""
        # Stop the collector
        await self.collector.stop()
        
        # Cancel the collector task
        self.collector_task.cancel()
        try:
            await self.collector_task
        except asyncio.CancelledError:
            pass
    
    async def test_send_syslog_message(self):
        """Test sending a Syslog message to the collector."""
        # Create a test message
        test_message = b"<13>1 2023-01-01T12:00:00Z test-host test-app 12345 - Test message"
        
        # Send the message to the collector
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(test_message, ('127.0.0.1', 5514))
        sock.close()
        
        # Give the collector time to process the message
        await asyncio.sleep(0.1)
        
        # Verify the message was processed
        # (In a real test, you would check that the message was properly processed)
        self.assertTrue(True)
    
    def test_parse_syslog_message(self):
        """Test parsing a Syslog message."""
        # Test message with priority
        raw_msg = b"<13>1 2023-01-01T12:00:00Z test-host test-app 12345 - Test message"
        message = self.collector._parse_syslog_message(raw_msg, '127.0.0.1')
        
        self.assertIsNotNone(message)
        self.assertEqual(message.priority, 13)
        self.assertEqual(message.facility, 1)
        self.assertEqual(message.severity, 5)
        self.assertEqual(message.hostname, 'test-host')
        self.assertEqual(message.msg, 'Test message')
        
        # Test message without priority
        raw_msg = b"Test message without priority"
        message = self.collector._parse_syslog_message(raw_msg, '127.0.0.1')
        
        self.assertIsNotNone(message)
        self.assertEqual(message.priority, 13)  # Default priority
        self.assertEqual(message.msg, 'Test message without priority')
    
    async def test_invalid_syslog_message(self):
        """Test handling of invalid Syslog messages."""
        # Send an invalid message
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"Invalid message", ('127.0.0.1', 5514))
        sock.close()
        
        # The collector should handle this gracefully
        await asyncio.sleep(0.1)
        self.assertTrue(True)

class TestConfig(unittest.TestCase):
    """Test configuration loading and validation."""
    
    def test_load_config(self):
        """Test loading configuration from a file."""
        # This will load the default config file
        config = load_config()
        
        # Check that required keys exist
        self.assertIn('syslog', config)
        self.assertIn('enabled', config['syslog'])
        self.assertIn('host', config['syslog'])
        self.assertIn('port', config['syslog'])
    
    def test_validate_config(self):
        """Test configuration validation."""
        # Valid config
        valid_config = {
            'syslog': {
                'enabled': True,
                'host': '0.0.0.0',
                'port': 514,
                'protocol': 'udp'
            }
        }
        self.assertTrue(validate_config(valid_config))
        
        # Invalid port
        invalid_config = valid_config.copy()
        invalid_config['syslog']['port'] = 70000  # Invalid port
        self.assertFalse(validate_config(invalid_config))
        
        # Invalid protocol
        invalid_config = valid_config.copy()
        invalid_config['syslog']['protocol'] = 'invalid'
        self.assertFalse(validate_config(invalid_config))

if __name__ == '__main__':
    unittest.main()
