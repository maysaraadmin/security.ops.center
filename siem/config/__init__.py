"""
Configuration loading and validation for the SIEM system.
"""
import os
import yaml
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger('siem.config')

def load_config(config_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.
    
    Args:
        config_file: Path to the configuration file. If None, loads default config.
        
    Returns:
        dict: The loaded configuration
    """
    if config_file is None:
        # Default config path
        config_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config',
            'agentless_config.yaml'
        )
    
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        # Set default values if not specified
        config.setdefault('syslog', {})
        config['syslog'].setdefault('enabled', True)
        config['syslog'].setdefault('host', '0.0.0.0')
        config['syslog'].setdefault('port', 514)
        config['syslog'].setdefault('protocol', 'udp')
        config['syslog'].setdefault('max_message_size', 65535)
        config['syslog'].setdefault('timeout', 5.0)
        config['syslog'].setdefault('reuse_port', True)
        config['syslog'].setdefault('backlog', 100)
        config['syslog'].setdefault('log_level', 'INFO')
        config['syslog'].setdefault('filters', [])
        
        logger.info(f"Loaded configuration from {config_file}")
        return config
        
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_file}: {e}")
        # Return default config if loading fails
        return {
            'syslog': {
                'enabled': True,
                'host': '0.0.0.0',
                'port': 514,
                'protocol': 'udp',
                'max_message_size': 65535,
                'timeout': 5.0,
                'reuse_port': True,
                'backlog': 100,
                'log_level': 'INFO',
                'filters': []
            }
        }

def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate the configuration.
    
    Args:
        config: The configuration to validate
        
    Returns:
        bool: True if the configuration is valid, False otherwise
    """
    try:
        # Validate syslog configuration
        if config.get('syslog', {}).get('enabled', False):
            syslog = config['syslog']
            
            # Validate host
            if not isinstance(syslog.get('host'), str):
                logger.error("Invalid syslog host")
                return False
                
            # Validate port
            port = syslog.get('port', 514)
            if not isinstance(port, int) or not (0 < port <= 65535):
                logger.error(f"Invalid syslog port: {port}")
                return False
                
            # Validate protocol
            if syslog.get('protocol') not in ('udp', 'tcp'):
                logger.error(f"Unsupported protocol: {syslog.get('protocol')}")
                return False
                
            # Validate filters
            for filter_cfg in syslog.get('filters', []):
                if not isinstance(filter_cfg, dict) or 'type' not in filter_cfg:
                    logger.error("Invalid filter configuration")
                    return False
        
        return True
        
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        return False
