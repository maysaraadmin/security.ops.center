"""
NIPS Engine - Core Network Intrusion Prevention System

This module implements the main NIPS engine that coordinates detection and prevention
of network-based attacks in real-time.
"""

import logging
import threading
import time
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
import json
import os
from pathlib import Path

# Import internal components
from .signature_detector import SignatureDetector
from .anomaly_detector import AnomalyDetector
from .protocol_analyzer import ProtocolAnalyzer
from .traffic_inspector import TrafficInspector
from .threat_intel import ThreatIntelligence
from .response_engine import ResponseEngine

logger = logging.getLogger('nips.engine')

@dataclass
class NIPSConfig:
    """Configuration for the NIPS engine."""
    # General settings
    enabled: bool = True
    mode: str = 'inline'  # 'inline' or 'passive'
    interface: str = 'eth0'  # Default network interface
    
    # Component settings
    enable_signature_detection: bool = True
    enable_anomaly_detection: bool = True
    enable_protocol_analysis: bool = True
    enable_traffic_inspection: bool = True
    enable_threat_intel: bool = True
    
    # Performance settings
    max_packets_per_second: int = 10000
    max_concurrent_sessions: int = 10000
    
    # Logging settings
    log_level: str = 'INFO'
    log_file: Optional[str] = None
    
    # Update settings
    signature_update_url: str = "https://rules.emergingthreats.net/open/suricata/rules/"
    threat_intel_update_interval: int = 3600  # seconds
    
    # Response actions
    block_malicious_ips: bool = True
    block_anomalous_traffic: bool = True
    block_protocol_violations: bool = True
    
    # Paths
    rules_dir: str = "/etc/nips/rules"
    cache_dir: str = "/var/cache/nips"
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'NIPSConfig':
        """Create a NIPSConfig from a dictionary."""
        return cls(**{
            k: v for k, v in config_dict.items() 
            if k in cls.__annotations__
        })

class NIPSEngine:
    """Main NIPS engine class that coordinates all detection and prevention components."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the NIPS engine with the given configuration."""
        # Load and validate configuration
        self.config = NIPSConfig.from_dict(config or {})
        self._validate_config()
        
        # Initialize logging
        self._setup_logging()
        
        # Core components
        self.signature_detector = None
        self.anomaly_detector = None
        self.protocol_analyzer = None
        self.traffic_inspector = None
        self.threat_intel = None
        self.response_engine = None
        
        # State
        self.running = False
        self._stop_event = threading.Event()
        self._update_thread = None
        self._stats = {
            'packets_processed': 0,
            'attacks_blocked': 0,
            'alerts_generated': 0,
            'last_updated': time.time()
        }
        
        # Initialize components
        self._initialize_components()
        
        logger.info("NIPS Engine initialized")
    
    def _validate_config(self):
        """Validate the configuration settings."""
        if self.config.mode not in ('inline', 'passive'):
            logger.warning(f"Invalid mode '{self.config.mode}', defaulting to 'inline'")
            self.config.mode = 'inline'
        
        # Ensure directories exist
        for dir_path in (self.config.rules_dir, self.config.cache_dir):
            os.makedirs(dir_path, exist_ok=True, mode=0o750)
    
    def _setup_logging(self):
        """Configure logging for the NIPS engine."""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename=self.config.log_file
        )
    
    def _initialize_components(self):
        """Initialize all NIPS components."""
        logger.info("Initializing NIPS components...")
        
        # Initialize threat intelligence first as other components may depend on it
        self.threat_intel = ThreatIntelligence(
            update_interval=self.config.threat_intel_update_interval,
            cache_dir=os.path.join(self.config.cache_dir, 'threat_intel')
        )
        
        # Initialize response engine
        self.response_engine = ResponseEngine(
            block_malicious_ips=self.config.block_malicious_ips,
            block_anomalous_traffic=self.config.block_anomalous_traffic,
            block_protocol_violations=self.config.block_protocol_violations
        )
        
        # Initialize detection components
        if self.config.enable_signature_detection:
            self.signature_detector = SignatureDetector(
                rules_dir=self.config.rules_dir,
                update_url=self.config.signature_update_url
            )
        
        if self.config.enable_anomaly_detection:
            self.anomaly_detector = AnomalyDetector(
                max_packets_per_second=self.config.max_packets_per_second,
                max_concurrent_sessions=self.config.max_concurrent_sessions
            )
        
        if self.config.enable_protocol_analysis:
            self.protocol_analyzer = ProtocolAnalyzer()
        
        if self.config.enable_traffic_inspection:
            self.traffic_inspector = TrafficInspector(
                threat_intel=self.threat_intel,
                max_packets_per_second=self.config.max_packets_per_second
            )
        
        logger.info("NIPS components initialized")
    
    def start(self):
        """Start the NIPS engine."""
        if self.running:
            logger.warning("NIPS engine is already running")
            return
        
        logger.info("Starting NIPS engine...")
        self.running = True
        self._stop_event.clear()
        
        # Start component update thread
        self._update_thread = threading.Thread(
            target=self._update_components,
            name="NIPS-Updater",
            daemon=True
        )
        self._update_thread.start()
        
        # Start network capture
        if self.config.mode == 'inline':
            self._start_inline_capture()
        else:
            self._start_passive_capture()
        
        logger.info("NIPS engine started in %s mode", self.config.mode.upper())
    
    def stop(self):
        """Stop the NIPS engine."""
        if not self.running:
            return
        
        logger.info("Stopping NIPS engine...")
        self.running = False
        self._stop_event.set()
        
        # Stop network capture
        if hasattr(self, '_capture_thread') and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5.0)
        
        # Stop update thread
        if self._update_thread and self._update_thread.is_alive():
            self._update_thread.join(timeout=5.0)
        
        # Clean up components
        if self.traffic_inspector:
            self.traffic_inspector.cleanup()
        
        logger.info("NIPS engine stopped")
    
    def _start_inline_capture(self):
        """Start inline network traffic capture."""
        # In a real implementation, this would set up an inline network tap or use
        # a library like nfqueue or nftables for packet inspection and modification
        self._capture_thread = threading.Thread(
            target=self._inline_capture_loop,
            name="NIPS-Inline-Capture",
            daemon=True
        )
        self._capture_thread.start()
    
    def _start_passive_capture(self):
        """Start passive network traffic capture."""
        # In a real implementation, this would use libpcap or similar for packet capture
        self._capture_thread = threading.Thread(
            target=self._passive_capture_loop,
            name="NIPS-Passive-Capture",
            daemon=True
        )
        self._capture_thread.start()
    
    def _inline_capture_loop(self):
        """Main loop for inline packet processing."""
        logger.info("Starting inline packet capture on interface %s", self.config.interface)
        
        try:
            while not self._stop_event.is_set():
                # In a real implementation, this would:
                # 1. Capture packets from the network interface
                # 2. Process each packet through the inspection pipeline
                # 3. Forward or drop packets based on inspection results
                # 4. Update statistics
                
                # Simulate packet processing
                time.sleep(0.1)
                self._stats['packets_processed'] += 1
                
                # Periodically log statistics
                if self._stats['packets_processed'] % 1000 == 0:
                    logger.debug("Processed %d packets", self._stats['packets_processed'])
        
        except Exception as e:
            logger.error("Error in inline capture loop: %s", str(e), exc_info=True)
        finally:
            logger.info("Stopped inline packet capture")
    
    def _passive_capture_loop(self):
        """Main loop for passive packet processing."""
        logger.info("Starting passive packet capture on interface %s", self.config.interface)
        
        try:
            while not self._stop_event.is_set():
                # In a real implementation, this would:
                # 1. Capture packets from the network interface
                # 2. Process each packet through the inspection pipeline
                # 3. Generate alerts for detected threats
                # 4. Update statistics
                
                # Simulate packet processing
                time.sleep(0.1)
                self._stats['packets_processed'] += 1
                
                # Periodically log statistics
                if self._stats['packets_processed'] % 1000 == 0:
                    logger.debug("Processed %d packets", self._stats['packets_processed'])
        
        except Exception as e:
            logger.error("Error in passive capture loop: %s", str(e), exc_info=True)
        finally:
            logger.info("Stopped passive packet capture")
    
    def _update_components(self):
        """Periodically update NIPS components (signatures, threat intel, etc.)."""
        logger.info("Starting component update thread")
        
        while not self._stop_event.is_set():
            try:
                # Update threat intelligence
                if self.threat_intel:
                    self.threat_intel.update()
                
                # Update signature database
                if self.signature_detector:
                    self.signature_detector.update_signatures()
                
                # Update statistics
                self._stats['last_updated'] = time.time()
                
                # Sleep until next update
                self._stop_event.wait(3600)  # Check hourly
                
            except Exception as e:
                logger.error("Error updating components: %s", str(e), exc_info=True)
                self._stop_event.wait(300)  # Wait 5 minutes before retrying after error
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current NIPS statistics."""
        return {
            'status': 'running' if self.running else 'stopped',
            'mode': self.config.mode,
            'packets_processed': self._stats['packets_processed'],
            'attacks_blocked': self._stats['attacks_blocked'],
            'alerts_generated': self._stats['alerts_generated'],
            'last_updated': self._stats['last_updated'],
            'components': {
                'signature_detection': bool(self.signature_detector),
                'anomaly_detection': bool(self.anomaly_detector),
                'protocol_analysis': bool(self.protocol_analyzer),
                'traffic_inspection': bool(self.traffic_inspector),
                'threat_intelligence': bool(self.threat_intel)
            }
        }
    
    def reload_config(self, new_config: Dict):
        """Reload configuration and restart components if needed."""
        logger.info("Reloading NIPS configuration")
        
        # Stop the engine if it's running
        was_running = self.running
        if was_running:
            self.stop()
        
        # Update configuration
        self.config = NIPSConfig.from_dict(new_config)
        self._validate_config()
        
        # Reinitialize components
        self._initialize_components()
        
        # Restart if it was running
        if was_running:
            self.start()
        
        logger.info("Configuration reloaded")
        return True

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
