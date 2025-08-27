"""
HIPS (Host-based Intrusion Prevention System) Component Launcher

This module provides a launcher for the HIPS component.
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

class HIPSLauncher(BaseLauncher):
    """Launcher for the HIPS component."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the HIPS launcher.
        
        Args:
            config: Configuration dictionary for the HIPS component.
        """
        super().__init__(config)
        self.hips_manager = None
        
    def initialize(self) -> bool:
        """Initialize the HIPS component."""
        try:
            from src.hips.manager import HIPSManager
            self.hips_manager = HIPSManager(self.config.get('hips', {}))
            self.logger.info("HIPS component initialized")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize HIPS component: {e}", exc_info=True)
            return False
    
    def start(self) -> None:
        """Start the HIPS component."""
        if not self.hips_manager:
            self.logger.error("HIPS component not initialized")
            return
            
        try:
            self.hips_manager.start()
            self._running = True
            self.logger.info("HIPS component started")
        except Exception as e:
            self.logger.error(f"Failed to start HIPS component: {e}", exc_info=True)
            raise
    
    def stop(self) -> None:
        """Stop the HIPS component."""
        if not self.hips_manager:
            return
            
        try:
            self.hips_manager.stop()
            self._running = False
            self.logger.info("HIPS component stopped")
        except Exception as e:
            self.logger.error(f"Error stopping HIPS component: {e}", exc_info=True)
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the HIPS component."""
        if not self.hips_manager:
            return {"status": "not_initialized"}
            
        try:
            return {
                "status": "running" if self._running else "stopped",
                "component": "hips",
                "details": self.hips_manager.get_status() if hasattr(self.hips_manager, 'get_status') else {}
            }
        except Exception as e:
            self.logger.error(f"Error getting HIPS status: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

def run_hips(config_path: Optional[str] = None):
    """Run the HIPS component.
    
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
        'file': 'hips.log'
    })
    
    logging.basicConfig(
        level=getattr(logging, log_config.get('level', 'INFO')),
        format=log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_config.get('file', 'hips.log'))
        ]
    )
    
    # Create and run the launcher
    launcher = HIPSLauncher(config)
    return launcher.run()

if __name__ == "__main__":
    import sys
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(0 if run_hips(config_path) else 1)
