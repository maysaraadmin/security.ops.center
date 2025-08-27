""
Configuration for EDR monitoring.
"""
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

# Default configuration
DEFAULT_CONFIG = {
    'monitoring': {
        'enabled': True,
        'log_level': 'INFO',
        'log_file': 'edr_monitor.log',
    },
    'process_monitoring': {
        'enabled': True,
        'scan_interval': 1.0,  # seconds
        'monitor_new_processes': True,
        'monitor_process_termination': True,
        'collect_command_line': True,
        'collect_integrity_level': True,
        'calculate_hashes': True,
    },
    'file_monitoring': {
        'enabled': True,
        'monitor_directories': [
            '/bin',
            '/sbin',
            '/usr/bin',
            '/usr/sbin',
            '/usr/local/bin',
            '/usr/local/sbin',
            '/etc',
            '/tmp',
            '/var/tmp',
            '/dev/shm',
        ],
        'exclude_patterns': [
            '^/proc/.*',
            '^/sys/.*',
            '^/run/.*',
            '^/var/run/.*',
            '.*/\.cache/.*',
            '.*/\.git/.*',
            '.*/\.svn/.*',
        ],
        'calculate_hashes': True,
        'hash_algorithms': ['md5', 'sha1', 'sha256'],
        'max_file_size_mb': 50,  # Skip files larger than this
    },
    'network_monitoring': {
        'enabled': True,
        'scan_interval': 5.0,  # seconds
        'monitor_listening_ports': True,
        'monitor_established_connections': True,
        'monitor_dns_queries': True,
        'alert_on_suspicious_ports': True,
        'suspicious_ports': [
            22,    # SSH
            23,    # Telnet
            80,    # HTTP
            443,   # HTTPS
            445,   # SMB
            1433,  # MS SQL
            3306,  # MySQL
            3389,  # RDP
            5900,  # VNC
            8080,  # HTTP Proxy
            8443,  # HTTPS Alternative
        ],
    },
    'registry_monitoring': {
        'enabled': True,
        'monitor_autorun_keys': True,
        'monitor_sensitive_keys': True,
        'autorun_keys': [
            'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices',
            'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices',
        ],
        'sensitive_keys': [
            'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
            'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
            'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies',
            'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies',
        ],
    },
    'user_activity_monitoring': {
        'enabled': True,
        'monitor_logins': True,
        'monitor_logouts': True,
        'monitor_failed_logins': True,
        'monitor_privilege_changes': True,
        'monitor_sudo_usage': True,
    },
    'alerting': {
        'enabled': True,
        'alert_on_high_severity': True,
        'alert_on_medium_severity': True,
        'alert_on_low_severity': False,
        'alert_methods': ['console', 'syslog'],
        'email_alerts': {
            'enabled': False,
            'smtp_server': 'smtp.example.com',
            'smtp_port': 587,
            'smtp_username': 'user@example.com',
            'smtp_password': 'password',
            'from_address': 'edr@example.com',
            'to_addresses': ['security@example.com'],
            'use_tls': True,
        },
        'slack_alerts': {
            'enabled': False,
            'webhook_url': 'https://hooks.slack.com/services/...',
            'channel': '#security-alerts',
            'username': 'EDR Bot',
        },
    },
    'storage': {
        'enabled': True,
        'backend': 'sqlite',  # or 'postgresql', 'mysql', 'elasticsearch'
        'retention_days': 30,
        'sqlite': {
            'database': 'edr_events.db',
            'journal_mode': 'WAL',
            'synchronous': 'NORMAL',
        },
        'postgresql': {
            'host': 'localhost',
            'port': 5432,
            'database': 'edr',
            'username': 'edr_user',
            'password': 'password',
        },
        'elasticsearch': {
            'hosts': ['localhost:9200'],
            'index_prefix': 'edr-',
            'use_ssl': False,
            'verify_certs': False,
            'username': '',
            'password': '',
        },
    },
    'api': {
        'enabled': True,
        'host': '127.0.0.1',
        'port': 5000,
        'debug': False,
        'authentication': {
            'enabled': True,
            'api_keys': ['changeme'],
        },
    },
}

def load_config(config_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file or use defaults.
    
    Args:
        config_file: Path to configuration file (YAML format)
        
    Returns:
        Dictionary containing the configuration
    """
    config = DEFAULT_CONFIG.copy()
    
    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f) or {}
                # Deep merge with defaults
                _deep_update(config, user_config)
                
        except Exception as e:
            raise ValueError(f"Error loading config file {config_file}: {e}")
    
    return config

def save_config(config: Dict[str, Any], config_file: str) -> None:
    """
    Save configuration to file.
    
    Args:
        config: Configuration dictionary to save
        config_file: Path to save configuration file
    """
    try:
        # Create directory if it doesn't exist
        config_dir = os.path.dirname(os.path.abspath(config_file))
        os.makedirs(config_dir, exist_ok=True)
        
        with open(config_file, 'w') as f:
            yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)
            
    except Exception as e:
        raise ValueError(f"Error saving config to {config_file}: {e}")

def _deep_update(original: Dict[str, Any], update: Dict[str, Any]) -> None:
    """
    Recursively update a dictionary.
    
    Args:
        original: Dictionary to update
        update: Dictionary with updates to apply
    """
    for key, value in update.items():
        if key in original and isinstance(original[key], dict) and isinstance(value, dict):
            _deep_update(original[key], value)
        else:
            original[key] = value

def get_default_config_path() -> str:
    """
    Get the default configuration file path.
    
    Returns:
        Path to the default configuration file
    """
    # Try to use XDG config directory if available
    xdg_config_home = os.environ.get('XDG_CONFIG_HOME')
    if xdg_config_home:
        config_dir = os.path.join(xdg_config_home, 'edr')
    else:
        # Fall back to ~/.config/edr
        config_dir = os.path.expanduser('~/.config/edr')
    
    return os.path.join(config_dir, 'config.yaml')

def ensure_default_config() -> str:
    """
    Ensure the default configuration file exists.
    
    Returns:
        Path to the configuration file
    """
    config_path = get_default_config_path()
    config_dir = os.path.dirname(config_path)
    
    # Create config directory if it doesn't exist
    os.makedirs(config_dir, exist_ok=True)
    
    # Create default config if it doesn't exist
    if not os.path.exists(config_path):
        save_config(DEFAULT_CONFIG, config_path)
    
    return config_path
