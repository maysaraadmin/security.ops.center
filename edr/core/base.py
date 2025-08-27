"""
Base classes and configuration for the EDR system.
"""
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Type, TypeVar
from enum import Enum
import logging
from pathlib import Path
import yaml
import platform
import os

class Platform(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "darwin"
    UNKNOWN = "unknown"

@dataclass
class EDRConfig:
    """Configuration for the EDR system."""
    # General settings
    agent_id: str = ""
    hostname: str = ""
    platform: Platform = Platform.UNKNOWN
    
    # Monitoring settings
    monitor_processes: bool = True
    monitor_files: bool = True
    monitor_network: bool = True
    monitor_registry: bool = os.name == 'nt'
    
    # Detection settings
    detection_rules_path: str = "config/detection_rules"
    enable_behavioral_detection: bool = True
    
    # Response settings
    enable_auto_containment: bool = False
    quarantine_path: str = "/var/quarantine"
    
    # Communication settings
    server_url: str = "https://edr-server:8080"
    heartbeat_interval: int = 300  # seconds
    
    # Logging settings
    log_level: str = "INFO"
    log_file: str = "/var/log/edr/agent.log"
    
    # Performance settings
    max_event_queue_size: int = 10000
    batch_size: int = 100
    
    def __post_init__(self):
        """Initialize configuration with system defaults."""
        if not self.agent_id:
            import uuid
            self.agent_id = str(uuid.uuid4())
            
        if not self.hostname:
            import socket
            self.hostname = socket.gethostname()
            
        # Set platform
        system = platform.system().lower()
        if system == 'windows':
            self.platform = Platform.WINDOWS
            if not self.quarantine_path:
                self.quarantine_path = r"C:\ProgramData\EDR\Quarantine"
            if not self.log_file:
                self.log_file = r"C:\ProgramData\EDR\Logs\agent.log"
        elif system == 'linux':
            self.platform = Platform.LINUX
            if not self.quarantine_path:
                self.quarantine_path = "/var/lib/edr/quarantine"
            if not self.log_file:
                self.log_file = "/var/log/edr/agent.log"
        elif system == 'darwin':
            self.platform = Platform.MACOS
            if not self.quarantine_path:
                self.quarantine_path = "/Library/Application Support/EDR/Quarantine"
            if not self.log_file:
                self.log_file = "/Library/Logs/EDR/agent.log"
    
    @classmethod
    def from_file(cls, config_path: str) -> 'EDRConfig':
        """Load configuration from a YAML file."""
        config_path = Path(config_path)
        if not config_path.exists():
            return cls()
            
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f) or {}
            
        return cls(**config_data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to a dictionary."""
        return {
            'agent_id': self.agent_id,
            'hostname': self.hostname,
            'platform': self.platform.value,
            'monitor_processes': self.monitor_processes,
            'monitor_files': self.monitor_files,
            'monitor_network': self.monitor_network,
            'monitor_registry': self.monitor_registry,
            'detection_rules_path': self.detection_rules_path,
            'enable_behavioral_detection': self.enable_behavioral_detection,
            'enable_auto_containment': self.enable_auto_containment,
            'quarantine_path': self.quarantine_path,
            'server_url': self.server_url,
            'heartbeat_interval': self.heartbeat_interval,
            'log_level': self.log_level,
            'log_file': self.log_file,
            'max_event_queue_size': self.max_event_queue_size,
            'batch_size': self.batch_size
        }
    
    def save(self, config_path: str):
        """Save configuration to a YAML file."""
        config_path = Path(config_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            yaml.safe_dump(self.to_dict(), f)

class EDRBase:
    """Base class for EDR components with common functionality."""
    
    def __init__(self, config: EDRConfig):
        """Initialize with configuration."""
        self.config = config
        self.logger = self._setup_logging()
        
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the component."""
        logger = logging.getLogger(self.__class__.__name__)
        logger.setLevel(self.config.log_level.upper())
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Create console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        # Create file handler if log file is specified
        if self.config.log_file:
            log_path = Path(self.config.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_path)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
            
        return logger
    
    def initialize(self) -> bool:
        """Initialize the component."""
        try:
            self.logger.info(f"Initializing {self.__class__.__name__}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize {self.__class__.__name__}: {e}")
            return False
    
    def shutdown(self):
        """Clean up resources."""
        self.logger.info(f"Shutting down {self.__class__.__name__}")
