"""
Tests for enhanced response actions.
"""
import os
import sys
import time
import json
import signal
import pytest
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from siem.response.enhanced_actions import TerminateProcessAction, MemoryDumpAction

def test_terminate_process_action():
    """Test the TerminateProcessAction."""
    # Start a test process
    test_process = subprocess.Popen(['ping', '127.0.0.1', '-n', '10'])
    
    # Create a test alert
    test_alert = {
        'process': {
            'pid': test_process.pid,
            'name': 'ping.exe',
            'path': 'C:\\Windows\\System32\\ping.exe'
        },
        'alert_type': 'suspicious_process',
        'severity': 'high'
    }
    
    try:
        # Initialize and execute the action
        action = TerminateProcessAction({
            'whitelisted_processes': ['lsass.exe']
        })
        
        # Verify the process is running
        assert test_process.poll() is None, "Test process should be running"
        
        # Execute the action
        result = action.execute(test_alert)
        
        # Give the process a moment to terminate
        time.sleep(0.5)
        
        # Verify the process was terminated
        assert result is True, "Action should return True on success"
        assert test_process.poll() is not None, "Process should be terminated"
        
    finally:
        # Ensure the process is terminated
        try:
            test_process.terminate()
            test_process.wait(timeout=1)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass

def test_terminate_whitelisted_process():
    """Test that whitelisted processes are not terminated."""
    # Create a test alert for a whitelisted process
    test_alert = {
        'process': {
            'pid': 1234,  # Doesn't matter as we'll mock the whitelist check
            'name': 'lsass.exe',
            'path': 'C:\\Windows\\System32\\lsass.exe'
        },
        'alert_type': 'suspicious_process',
        'severity': 'high'
    }
    
    # Initialize with lsass.exe in the whitelist
    action = TerminateProcessAction({
        'whitelisted_processes': ['lsass.exe', 'csrss.exe']
    })
    
    # Execute the action
    with patch('subprocess.run') as mock_run:
        result = action.execute(test_alert)
        
        # Verify the process was not terminated
        assert result is False, "Should return False for whitelisted process"
        mock_run.assert_not_called()

@pytest.mark.skipif(os.name != 'nt', reason="Test requires Windows")
def test_memory_dump_action_windows():
    """Test the MemoryDumpAction on Windows."""
    # Start a test process
    test_process = subprocess.Popen(['notepad'])
    
    # Create a test alert
    test_alert = {
        'process': {
            'pid': test_process.pid,
            'name': 'notepad.exe',
            'path': 'C:\\Windows\\System32\\notepad.exe'
        },
        'alert_type': 'suspicious_process',
        'severity': 'high'
    }
    
    try:
        # Create a temporary directory for the memory dump
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir: 
            # Initialize and execute the action
            action = MemoryDumpAction({
                'output_dir': temp_dir,
                'compress': False
            })
            
            # Execute the action
            result = action.execute(test_alert)
            
            # Check if procdump is available
            try:
                subprocess.run(['where', 'procdump'], 
                             capture_output=True, 
                             check=True)
                procdump_available = True
            except (subprocess.CalledProcessError, FileNotFoundError):
                procdump_available = False
            
            if procdump_available:
                # If procdump is available, verify the dump was created
                assert 'output_file' in result, "Result should contain output file path"
                assert os.path.exists(result['output_file']), "Memory dump file should exist"
                assert result['size_mb'] > 0, "Memory dump file should have content"
            else:
                # If procdump is not available, verify we get a helpful error message
                assert result['status'] == 'error', "Should return error status when procdump is missing"
                assert 'procdump' in result['message'], "Error message should mention procdump"
                
    finally:
        # Terminate the test process
        try:
            test_process.terminate()
            test_process.wait(timeout=1)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
