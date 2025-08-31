"""
SIEM Agentless Collector

This module provides agentless log collection capabilities for the SIEM system,
supporting protocols like Syslog.
"""
import asyncio
import logging
import signal
import sys
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('agentless_collector.log')
    ]
)
logger = logging.getLogger('siem.agentless_collector')

# Import the collector after setting up logging
from siem.collectors.agentless import AgentlessCollector
from siem.config import load_config, validate_config

class AgentlessCollectorService:
    """Service wrapper for the agentless collector."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the service."""
        self.config = config
        self.collector = AgentlessCollector(config)
        self.running = False
        
    async def start(self):
        """Start the collector service."""
        if self.running:
            logger.warning("Collector service is already running")
            return
            
        logger.info("Starting agentless collector service...")
        
        # Set up signal handlers
        if sys.platform == 'win32':
            # On Windows, we can only set up signal handlers for SIGINT
            signal.signal(signal.SIGINT, lambda s, _: asyncio.create_task(self._handle_shutdown(s)))
        else:
            # On Unix-like systems, we can set up proper signal handlers
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(
                    sig,
                    lambda s=sig: asyncio.create_task(self._handle_shutdown(s))
                )
        
        # Start the collector
        try:
            await self.collector.start()
            self.running = True
            logger.info("Agentless collector service started successfully")
            
            # Keep the service running
            while self.running:
                await asyncio.sleep(1)
                
        except asyncio.CancelledError:
            logger.info("Shutdown signal received")
        except Exception as e:
            logger.error(f"Error in collector service: {e}", exc_info=True)
        finally:
            await self.stop()
    
    async def stop(self):
        """Stop the collector service."""
        if not self.running:
            return
            
        logger.info("Stopping agentless collector service...")
        await self.collector.stop()
        self.running = False
        logger.info("Agentless collector service stopped")
    
    async def _handle_shutdown(self, sig):
        """Handle shutdown signals."""
        logger.info(f"Received signal {sig.name}, shutting down...")
        await self.stop()
        asyncio.get_running_loop().stop()

def main():
    """Main entry point for the agentless collector."""
    try:
        # Load and validate configuration
        config = load_config()
        if not validate_config(config):
            logger.error("Invalid configuration")
            return 1
            
        # Set log level from config
        log_level = config.get('syslog', {}).get('log_level', 'INFO').upper()
        logging.getLogger('siem').setLevel(log_level)
        
        # Create and run the service
        service = AgentlessCollectorService(config)
        
        # Run the event loop
        asyncio.run(service.start())
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
        return 0
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
