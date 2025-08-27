"""
Test script to verify all SOC components can be launched and function correctly.
"""

import unittest
import time
import os
import signal
import subprocess
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

# Add the project root to the Python path
PROJECT_ROOT = str(Path(__file__).parent.parent.absolute())
os.environ["PYTHONPATH"] = PROJECT_ROOT

# Component configurations
COMPONENTS = {
    "siem": {
        "module": "src.siem.launcher",
        "config": "config/siem_config.yaml",
        "timeout": 5,
        "port": 5001,
    },
    "edr": {
        "module": "src.edr.launcher",
        "config": "config/edr_config.yaml",
        "timeout": 5,
        "port": 5002,
    },
    "dlp": {
        "module": "src.dlp.launcher",
        "config": "config/dlp_config.yaml",
        "timeout": 5,
        "port": 5004,
    },
    "hips": {
        "module": "src.hips.launcher",
        "config": "config/hips_config.yaml",
        "timeout": 5,
        "port": 5006,
    },
    "nips": {
        "module": "src.nips.launcher",
        "config": "config/nips_config.yaml",
        "timeout": 5,
        "port": 5007,
    },
}

class TestSOCComponents(unittest.TestCase):
    """Test case for SOC components."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        # Load configurations and update ports for testing
        for comp_name, comp_config in COMPONENTS.items():
            config_path = os.path.join(PROJECT_ROOT, comp_config["config"])
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f) or {}
                
                # Update ports to avoid conflicts
                if comp_name in config:
                    config[comp_name]["port"] = comp_config["port"]
                
                # Save the updated config
                with open(config_path, 'w') as f:
                    yaml.dump(config, f)
    
    def test_component_imports(self):
        """Test that all component modules can be imported."""
        for comp_name, comp_config in COMPONENTS.items():
            with self.subTest(component=comp_name):
                try:
                    __import__(comp_config["module"])
                except ImportError as e:
                    self.fail(f"Failed to import {comp_name} module: {e}")
    
    def test_component_launch(self):
        """Test launching each component in a separate process."""
        processes = {}
        
        try:
            # Start each component in a separate process
            for comp_name, comp_config in COMPONENTS.items():
                cmd = [
                    "python",
                    "-m",
                    comp_config["module"],
                    os.path.join(PROJECT_ROOT, comp_config["config"])
                ]
                
                # Start the process
                proc = subprocess.Popen(
                    cmd,
                    stdout=open(f"logs/{comp_name}_test_stdout.log", "w"),
                    stderr=open(f"logs/{comp_name}_test_stderr.log", "w"),
                )
                processes[comp_name] = proc
                
                # Give the component time to start
                time.sleep(2)
                
                # Check if the process is still running
                self.assertIsNone(
                    proc.poll(),
                    f"{comp_name} process terminated with code {proc.returncode}"
                )
                
                # TODO: Add API health check for each component
                # This would require the components to have health check endpoints
                
            # Let the components run for a short time
            time.sleep(5)
            
        finally:
            # Clean up - terminate all processes
            for comp_name, proc in processes.items():
                if proc.poll() is None:
                    try:
                        # Try graceful shutdown first
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            # Force kill if not terminated
                            proc.kill()
                    except ProcessLookupError:
                        pass  # Process already terminated
    
    def test_unified_launcher(self):
        """Test the unified launcher."""
        # Test listing components
        result = subprocess.run(
            ["python", "launch.py", "list"],
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Available components:", result.stdout)
        
        # Test launching a single component
        result = subprocess.run(
            ["python", "launch.py", "run", "siem", "--config", "config/"],
            timeout=10,
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Starting SIEM component", result.stdout)

if __name__ == "__main__":
    unittest.main()
