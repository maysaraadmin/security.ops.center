"""
NIPS (Network Intrusion Prevention System) Component Launcher

This module provides a launcher for the NIPS component.
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

class NIPSLauncher(BaseLauncher):
    """Launcher for the NIPS component."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the NIPS launcher.
        
        Args:
            config: Configuration dictionary for the NIPS component.
        """
        super().__init__(config)
        self.nips_manager = None
        
    def initialize(self) -> bool:
        """Initialize the NIPS component."""
        try:
            from src.nips.manager import NIPSManager
            self.nips_manager = NIPSManager(self.config.get('nips', {}))
            self.logger.info("NIPS component initialized")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize NIPS component: {e}", exc_info=True)
            return False
    
    def start(self) -> None:
        """Start the NIPS component."""
        if not self.nips_manager:
            self.logger.error("NIPS component not initialized")
            return
            
        try:
            self.nips_manager.start()
            self._running = True
            self.logger.info("NIPS component started")
        except Exception as e:
            self.logger.error(f"Failed to start NIPS component: {e}", exc_info=True)
            raise
    
    def stop(self) -> None:
        """Stop the NIPS component."""
        if not self.nips_manager:
            return
            
        try:
            self.nips_manager.stop()
            self._running = False
            self.logger.info("NIPS component stopped")
        except Exception as e:
            self.logger.error(f"Error stopping NIPS component: {e}", exc_info=True)
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the NIPS component."""
        if not self.nips_manager:
            return {"status": "not_initialized"}
            
        try:
            return {
                "status": "running" if self._running else "stopped",
                "component": "nips",
                "details": self.nips_manager.get_status() if hasattr(self.nips_manager, 'get_status') else {}
            }
        except Exception as e:
            self.logger.error(f"Error getting NIPS status: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

def run_nips(config_path: Optional[str] = None):
    """Run the NIPS component.
    
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
        'file': 'nips.log'
    })
    
    logging.basicConfig(
        level=getattr(logging, log_config.get('level', 'INFO')),
        format=log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_config.get('file', 'nips.log'))
        ]
    )
    
    # Create and run the launcher
    launcher = NIPSLauncher(config)
    return launcher.run()

if __name__ == "__main__":
    import sys
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(0 if run_nips(config_path) else 1)
