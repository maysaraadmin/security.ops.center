"""
NDR Manager - Main module for Network Detection and Response.
Coordinates traffic collection, detection, and response.
"""
import logging
import signal
import sys
from typing import Optional, Dict, Any, List
import threading
import time
from datetime import datetime

from .traffic_collector import TrafficCollector
from .detection_engine import DetectionEngine
from .response_engine import ResponseEngine


class NDRManager:
    """Main class for Network Detection and Response functionality."""
    
    def __init__(self, interface: str = None, filter_exp: str = "ip"):
        """
        Initialize the NDR manager.
        
        Args:
            interface: Network interface to monitor (None for default)
            filter_exp: BPF filter expression for traffic filtering
        """
        self.interface = interface
        self.filter_exp = filter_exp
        self.running = False
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.traffic_collector = TrafficCollector(interface, filter_exp)
        self.detection_engine = DetectionEngine()
        self.response_engine = ResponseEngine()
        
        # Connect components
        self.traffic_collector.add_callback(self._process_packet)
        self.detection_engine.add_alert_callback(self._handle_alert)
        
        # Statistics
        self.stats = {
            'start_time': None,
            'packets_processed': 0,
            'alerts_triggered': 0,
            'last_alert': None
        }
    
    def start(self):
        """Start the NDR system."""
        if self.running:
            self.logger.warning("NDR system is already running")
            return
            
        self.logger.info("Starting NDR system...")
        self.running = True
        self.stats['start_time'] = datetime.utcnow()
        self.stats['packets_processed'] = 0
        self.stats['alerts_triggered'] = 0
        
        try:
            # Start the traffic collector in a separate thread
            self.traffic_collector.start()
            self.logger.info("NDR system started successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start NDR system: {e}")
            self.running = False
            return False
    
    def stop(self):
        """Stop the NDR system."""
        if not self.running:
            return
            
        self.logger.info("Stopping NDR system...")
        self.running = False
        self.traffic_collector.stop()
        self.logger.info("NDR system stopped")
    
    def _process_packet(self, packet_info: Dict[str, Any]):
        """Process a single network packet."""
        if not self.running:
            return
            
        try:
            self.stats['packets_processed'] += 1
            
            # Analyze the packet with the detection engine
            alerts = self.detection_engine.analyze_packet(packet_info)
            
            # Update stats
            if alerts:
                self.stats['alerts_triggered'] += len(alerts)
                self.stats['last_alert'] = datetime.utcnow()
                
                # Log the first alert at WARNING level, others at INFO
                for i, alert in enumerate(alerts):
                    log_level = logging.WARNING if i == 0 else logging.INFO
                    self.logger.log(
                        log_level,
                        f"Alert triggered: {alert.get('name')} "
                        f"(Severity: {alert.get('severity', 'unknown')})"
                    )
                    
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _handle_alert(self, alert: Dict[str, Any]):
        """Handle a detected alert."""
        if not self.running:
            return
            
        try:
            self.response_engine.handle_alert(alert)
        except Exception as e:
            self.logger.error(f"Error handling alert: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the NDR system."""
        uptime = 0
        if self.stats['start_time']:
            uptime = (datetime.utcnow() - self.stats['start_time']).total_seconds()
            
        return {
            'running': self.running,
            'interface': self.interface,
            'filter_expression': self.filter_exp,
            'uptime_seconds': uptime,
            'packets_processed': self.stats['packets_processed'],
            'alerts_triggered': self.stats['alerts_triggered'],
            'last_alert': self.stats['last_alert'].isoformat() if self.stats['last_alert'] else None,
            'detection_rules': len(self.detection_engine.rules),
            'response_actions': len(self.response_engine.actions)
        }


def run_ndr(interface: str = None, filter_exp: str = "ip"):
    """
    Run the NDR system with the specified interface and filter.
    
    Args:
        interface: Network interface to monitor (None for default)
        filter_exp: BPF filter expression for traffic filtering
    """
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    
    # Create and start the NDR manager
    ndr = NDRManager(interface, filter_exp)
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutting down NDR system...")
        ndr.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the NDR system
    if not ndr.start():
        sys.exit(1)
    
    # Main loop
    try:
        logger.info("NDR system running. Press Ctrl+C to stop.")
        while True:
            # Print status periodically
            status = ndr.get_status()
            logger.info(
                f"Status: {status['packets_processed']} packets processed, "
                f"{status['alerts_triggered']} alerts triggered"
            )
            time.sleep(60)
            
    except KeyboardInterrupt:
        logger.info("Shutting down NDR system...")
        ndr.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        ndr.stop()
        sys.exit(1)
