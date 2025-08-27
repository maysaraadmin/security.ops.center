"""
SIEM Core Implementation

This module contains the main SIEM class that coordinates all SIEM components.
"""

import logging
from typing import Dict, Any, Optional
from .component import Component

logger = logging.getLogger(__name__)

class SIEM:
    """Main SIEM class that manages all SIEM components."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the SIEM system with the given configuration.
        
        Args:
            config: Dictionary containing SIEM configuration
        """
        self.config = config
        self.running = False
        self.components: Dict[str, Component] = {}
        self._initialize_components()
    
    def _initialize_components(self) -> None:
        """Initialize all SIEM components based on the configuration."""
        logger.info("Initializing SIEM components...")
        
        # Initialize components based on configuration
        if self.config.get('monitoring', {}).get('enabled', False):
            from ..monitoring import MonitoringService
            self.components['monitoring'] = MonitoringService(
                self.config['monitoring']
            )
            
        if self.config.get('log_collector', {}).get('enabled', False):
            from ..log_collector import LogCollector
            self.components['log_collector'] = LogCollector(
                self.config['log_collector']
            )
            
        if self.config.get('correlation', {}).get('enabled', False):
            from ..correlation import CorrelationEngine
            self.components['correlation'] = CorrelationEngine(
                self.config['correlation']
            )
            
        if self.config.get('edr', {}).get('enabled', False):
            from ..edr import EDRService
            self.components['edr'] = EDRService(
                self.config['edr']
            )
            
        logger.info(f"Initialized {len(self.components)} components")
    
    def start(self) -> None:
        """Start all enabled SIEM components."""
        if self.running:
            logger.warning("SIEM is already running")
            return
            
        logger.info("Starting SIEM system...")
        self.running = True
        
        try:
            # Start all components
            for name, component in self.components.items():
                try:
                    logger.info(f"Starting component: {name}")
                    component.start()
                except Exception as e:
                    logger.error(f"Failed to start component {name}: {e}", exc_info=True)
                    
            logger.info("SIEM system started successfully")
            
        except Exception as e:
            logger.critical(f"Failed to start SIEM system: {e}", exc_info=True)
            self.stop()
            raise
    
    def stop(self) -> None:
        """Stop all running SIEM components."""
        if not self.running:
            return
            
        logger.info("Stopping SIEM system...")
        
        # Stop all components in reverse order
        for name, component in reversed(list(self.components.items())):
            try:
                logger.info(f"Stopping component: {name}")
                component.stop()
            except Exception as e:
                logger.error(f"Error stopping component {name}: {e}", exc_info=True)
        
        self.running = False
        logger.info("SIEM system stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the SIEM system and its components.
        
        Returns:
            Dictionary containing status information
        """
        status = {
            'running': self.running,
            'components': {}
        }
        
        for name, component in self.components.items():
            try:
                status['components'][name] = component.get_status()
            except Exception as e:
                status['components'][name] = {
                    'status': 'error',
                    'error': str(e)
                }
                
        return status
