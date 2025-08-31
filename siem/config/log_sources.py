"""
Log Source Management for SIEM

This module handles the configuration and management of log sources.
"""
import os
import yaml
import logging
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
from dataclasses import dataclass, asdict, field
from datetime import datetime

logger = logging.getLogger('siem.config.sources')

@dataclass
class LogSource:
    """Represents a log source configuration."""
    name: str
    type: str  # e.g., 'windows_event', 'syslog', 'firewall', 'ids', etc.
    ip_address: str
    description: str = ""
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    parser: str = ""  # Name of the parser to use
    parser_config: Dict[str, Any] = field(default_factory=dict)
    last_seen: Optional[datetime] = None
    first_seen: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the log source to a dictionary."""
        result = asdict(self)
        # Convert datetime objects to ISO format
        for field in ['last_seen', 'first_seen', 'created_at', 'updated_at']:
            if field in result and result[field] is not None:
                result[field] = result[field].isoformat() + 'Z'
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogSource':
        """Create a LogSource from a dictionary."""
        # Convert string timestamps back to datetime objects
        for field in ['last_seen', 'first_seen', 'created_at', 'updated_at']:
            if field in data and data[field] is not None and isinstance(data[field], str):
                # Remove 'Z' if present and parse
                dt_str = data[field].rstrip('Z')
                data[field] = datetime.fromisoformat(dt_str)
        return cls(**data)

class LogSourceManager:
    """Manages log sources for the SIEM."""
    
    def __init__(self, config_dir: str = None):
        """Initialize the log source manager.
        
        Args:
            config_dir: Directory containing log source configurations
        """
        self.config_dir = config_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'config',
            'sources'
        )
        self.sources: Dict[str, LogSource] = {}
        self._source_by_ip: Dict[str, LogSource] = {}
        
        # Create config directory if it doesn't exist
        os.makedirs(self.config_dir, exist_ok=True)
        
        # Load existing configurations
        self._load_sources()
    
    def _load_sources(self) -> None:
        """Load log sources from configuration files."""
        self.sources = {}
        self._source_by_ip = {}
        
        for config_file in Path(self.config_dir).glob('*.yaml'):
            try:
                with open(config_file, 'r') as f:
                    data = yaml.safe_load(f)
                    if not data:
                        continue
                        
                    if isinstance(data, list):
                        for source_data in data:
                            self._add_source(LogSource.from_dict(source_data))
                    else:
                        self._add_source(LogSource.from_dict(data))
                        
            except Exception as e:
                logger.error(f"Error loading log source from {config_file}: {e}", exc_info=True)
    
    def _add_source(self, source: LogSource) -> None:
        """Add a log source to the manager."""
        self.sources[source.name] = source
        self._source_by_ip[source.ip_address] = source
    
    def get_source(self, name: str) -> Optional[LogSource]:
        """Get a log source by name."""
        return self.sources.get(name)
    
    def get_source_by_ip(self, ip_address: str) -> Optional[LogSource]:
        """Get a log source by IP address."""
        return self._source_by_ip.get(ip_address)
    
    def list_sources(self, type_filter: str = None, enabled: bool = None) -> List[LogSource]:
        """List all log sources, optionally filtered by type and/or enabled status."""
        result = list(self.sources.values())
        
        if type_filter is not None:
            result = [s for s in result if s.type == type_filter]
            
        if enabled is not None:
            result = [s for s in result if s.enabled == enabled]
            
        return result
    
    def add_source(self, source: LogSource) -> bool:
        """Add a new log source."""
        if source.name in self.sources:
            logger.warning(f"Log source with name '{source.name}' already exists")
            return False
            
        if source.ip_address in self._source_by_ip:
            existing = self._source_by_ip[source.ip_address]
            logger.warning(
                f"IP address {source.ip_address} is already used by log source '{existing.name}'"
            )
            return False
            
        self._add_source(source)
        self._save_source(source)
        return True
    
    def update_source(self, name: str, **kwargs) -> bool:
        """Update an existing log source."""
        if name not in self.sources:
            logger.warning(f"Log source '{name}' not found")
            return False
            
        source = self.sources[name]
        
        # Don't allow changing the IP address if it's already in use
        if 'ip_address' in kwargs and kwargs['ip_address'] != source.ip_address:
            if kwargs['ip_address'] in self._source_by_ip:
                existing = self._source_by_ip[kwargs['ip_address']]
                if existing.name != name:  # Only error if it's a different source
                    logger.warning(
                        f"IP address {kwargs['ip_address']} is already used by log source '{existing.name}'"
                    )
                    return False
        
        # Update the source attributes
        for key, value in kwargs.items():
            if hasattr(source, key):
                setattr(source, key, value)
        
        source.updated_at = datetime.utcnow()
        
        # Update the source_by_ip mapping if the IP address changed
        if 'ip_address' in kwargs and kwargs['ip_address'] != source.ip_address:
            del self._source_by_ip[source.ip_address]
            source.ip_address = kwargs['ip_address']
            self._source_by_ip[source.ip_address] = source
        
        self._save_source(source)
        return True
    
    def delete_source(self, name: str) -> bool:
        """Delete a log source."""
        if name not in self.sources:
            return False
            
        source = self.sources[name]
        config_file = self._get_config_file(name)
        
        try:
            if config_file.exists():
                config_file.unlink()
        except Exception as e:
            logger.error(f"Error deleting config file {config_file}: {e}", exc_info=True)
            return False
            
        # Remove from our in-memory stores
        del self.sources[name]
        if source.ip_address in self._source_by_ip:
            del self._source_by_ip[source.ip_address]
            
        return True
    
    def _get_config_file(self, name: str) -> Path:
        """Get the path to a log source's configuration file."""
        safe_name = "".join(c if c.isalnum() or c in ' ._-' else '_' for c in name)
        return Path(self.config_dir) / f"{safe_name}.yaml"
    
    def _save_source(self, source: LogSource) -> None:
        """Save a log source's configuration to disk."""
        config_file = self._get_config_file(source.name)
        
        try:
            with open(config_file, 'w') as f:
                yaml.safe_dump(source.to_dict(), f, default_flow_style=False)
        except Exception as e:
            logger.error(f"Error saving log source {source.name} to {config_file}: {e}", exc_info=True)
            raise
    
    def update_last_seen(self, ip_address: str) -> bool:
        """Update the last seen timestamp for a log source."""
        source = self.get_source_by_ip(ip_address)
        if not source:
            # Auto-create a new source for unknown IPs
            source = LogSource(
                name=f"auto_{ip_address.replace('.', '_')}",
                type="unknown",
                ip_address=ip_address,
                description=f"Automatically created for {ip_address}",
                first_seen=datetime.utcnow()
            )
            self._add_source(source)
            
        source.last_seen = datetime.utcnow()
        if not source.first_seen:
            source.first_seen = source.last_seen
            
        self._save_source(source)
        return True

# Example usage
if __name__ == "__main__":
    # Create a log source manager
    manager = LogSourceManager()
    
    # Add a new log source
    source = LogSource(
        name="firewall-01",
        type="fortinet",
        ip_address="192.168.1.1",
        description="Main office FortiGate firewall",
        tags=["firewall", "fortinet", "production"],
        parser="fortinet_fortios"
    )
    
    if manager.add_source(source):
        print(f"Added log source: {source.name}")
    
    # List all log sources
    print("\nAll log sources:")
    for src in manager.list_sources():
        print(f"- {src.name} ({src.type}): {src.ip_address}")
    
    # Update a log source
    manager.update_source("firewall-01", description="Main office FortiGate 100F")
    
    # Get a specific log source
    src = manager.get_source("firewall-01")
    if src:
        print(f"\nUpdated description: {src.description}")
    
    # Update last seen
    manager.update_last_seen("192.168.1.1")
    print(f"Last seen updated: {manager.get_source('firewall-01').last_seen}")
