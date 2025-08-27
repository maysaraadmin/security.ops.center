"""
EDR (Endpoint Detection and Response) Component Launcher

This module provides a launcher for the EDR component.
"""

import logging
from typing import Dict, Any, Optional
from pathlib import Path
import sys

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent.parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.base_launcher import BaseLauncher

class EDRLauncher(BaseLauncher):
    """Launcher for the EDR component."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the EDR launcher.
        
        Args:
            config: Configuration dictionary for the EDR component.
        """
        super().__init__(config)
        self.edr_server = None
        
    def initialize(self) -> bool:
        """Initialize the EDR component."""
        try:
            from src.edr.server import EDRAgentServer
            self.edr_server = EDRAgentServer(self.config.get('edr', {}))
            self.logger.info("EDR component initialized")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize EDR component: {e}", exc_info=True)
            return False
    
    def start(self) -> None:
        """Start the EDR component."""
        if not self.edr_server:
            self.logger.error("EDR component not initialized")
            return
            
        try:
            self.edr_server.start()
            self._running = True
            self.logger.info("EDR component started")
        except Exception as e:
            self.logger.error(f"Failed to start EDR component: {e}", exc_info=True)
            raise
    
    def stop(self) -> None:
        """Stop the EDR component."""
        if not self.edr_server:
            return
            
        try:
            self.edr_server.stop()
            self._running = False
            self.logger.info("EDR component stopped")
        except Exception as e:
            self.logger.error(f"Error stopping EDR component: {e}", exc_info=True)
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the EDR component."""
        if not self.edr_server:
            return {"status": "not_initialized"}
            
        try:
            return {
                "status": "running" if self._running else "stopped",
                "component": "edr",
                "details": self.edr_server.get_status() if hasattr(self.edr_server, 'get_status') else {}
            }
        except Exception as e:
            self.logger.error(f"Error getting EDR status: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

def run_edr(config_path: Optional[str] = None):
    """Run the EDR component.
    
    Args:
        config_path: Path to the configuration file.
    """
    import yaml
    
    # Load configuration
    config = {}
    if config_path:
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Failed to load configuration from {config_path}: {e}")
            return False
    
    # Configure logging
    log_config = config.get('logging', {
        'level': 'INFO',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': 'edr.log'
    })
    
    logging.basicConfig(
        level=getattr(logging, log_config.get('level', 'INFO')),
        format=log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_config.get('file', 'edr.log'))
        ]
    )
    
    # Create and run the launcher
    launcher = EDRLauncher(config)
    return launcher.run()

if __name__ == "__main__":
    import sys
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(0 if run_edr(config_path) else 1)
