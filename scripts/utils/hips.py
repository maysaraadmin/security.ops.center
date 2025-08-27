"""
HIPS (Host-based Intrusion Prevention System)

Main module that coordinates all HIPS components including process monitoring,
behavioral analysis, and system call monitoring.
"""

import logging
import threading
from typing import Dict, List, Optional, Callable, Any
from pathlib import Path
import signal
import sys
import platform

# Import core components
from .process_monitor import ProcessMonitor
from .behavior_analyzer import BehaviorAnalyzer
from .system_call_monitor import SystemCallMonitor
from .network_monitor import NetworkMonitor
from .policy_manager import PolicyManager
from .event_logger import EventLogger
from .response_engine import ResponseEngine

logger = logging.getLogger('hips')

class HIPS:
    """Main HIPS class that coordinates all monitoring and protection components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the HIPS system.
        
        Args:
            config: Configuration dictionary for HIPS components
        """
        self.config = config or {}
        self.running = False
        self._stop_event = threading.Event()
        
        # Initialize components
        self.policy_manager = PolicyManager(self.config.get('policies', {}))
        self.event_logger = EventLogger(self.config.get('logging', {}))
        self.response_engine = ResponseEngine(
            config=self.config.get('response', {}),
            event_logger=self.event_logger,
            policy_manager=self.policy_manager
        )
        
        # Initialize monitoring components
        self.process_monitor = ProcessMonitor(
            config=self.config.get('process_monitor', {}),
            event_logger=self.event_logger,
            response_engine=self.response_engine,
            policy_manager=self.policy_manager
        )
        
        self.behavior_analyzer = BehaviorAnalyzer(
            config=self.config.get('behavior_analyzer', {}),
            event_logger=self.event_logger,
            response_engine=self.response_engine
        )
        
        self.system_call_monitor = SystemCallMonitor(
            config=self.config.get('system_call_monitor', {}),
            event_logger=self.event_logger,
            response_engine=self.response_engine,
            policy_manager=self.policy_manager
        )
        
        self.network_monitor = NetworkMonitor(
            config=self.config.get('network_monitor', {}),
            event_logger=self.event_logger,
            response_engine=self.response_engine,
            policy_manager=self.policy_manager
        )
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        
        logger.info("HIPS system initialized")
    
    def start(self) -> None:
        """Start all HIPS monitoring components."""
        if self.running:
            logger.warning("HIPS is already running")
            return
            
        logger.info("Starting HIPS...")
        
        try:
            # Start monitoring components
            self.process_monitor.start()
            self.behavior_analyzer.start()
            self.system_call_monitor.start()
            self.network_monitor.start()
            
            self.running = True
            logger.info("HIPS started successfully")
            
            # Main monitoring loop
            while not self._stop_event.is_set():
                # Check for updates or perform periodic tasks
                self._periodic_tasks()
                self._stop_event.wait(1.0)
                
        except Exception as e:
            logger.error(f"Error in HIPS main loop: {e}", exc_info=True)
            self.stop()
    
    def stop(self) -> None:
        """Stop all HIPS monitoring components."""
        if not self.running:
            return
            
        logger.info("Stopping HIPS...")
        self._stop_event.set()
        
        # Stop monitoring components
        self.process_monitor.stop()
        self.behavior_analyzer.stop()
        self.system_call_monitor.stop()
        self.network_monitor.stop()
        
        # Ensure all events are logged
        self.event_logger.flush()
        
        self.running = False
        logger.info("HIPS stopped")
    
    def _periodic_tasks(self) -> None:
        """Perform periodic tasks like updating signatures or checking for updates."""
        # Example: Check for policy updates periodically
        if hasattr(self, '_last_policy_check'):
            import time
            if time.time() - self._last_policy_check > 3600:  # Check every hour
                self.policy_manager.check_for_updates()
                self._last_policy_check = time.time()
    
    def _handle_shutdown(self, signum, frame) -> None:
        """Handle shutdown signals gracefully."""
        logger.info(f"Received shutdown signal {signum}")
        self.stop()
        sys.exit(0)
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


def create_default_hips(config: Optional[Dict[str, Any]] = None) -> HIPS:
    """Create a HIPS instance with default configuration.
    
    Args:
        config: Optional configuration overrides
        
    Returns:
        Configured HIPS instance
    """
    default_config = {
        'process_monitor': {
            'enabled': True,
            'scan_interval': 5.0,
            'monitor_children': True,
            'critical_processes': [
                'lsass.exe', 'winlogon.exe', 'services.exe',
                'csrss.exe', 'smss.exe', 'system', 'init', 'systemd'
            ]
        },
        'behavior_analyzer': {
            'enabled': True,
            'suspicious_activities': {
                'process_hollowing': True,
                'code_injection': True,
                'dll_hijacking': True,
                'suspicious_cmdline': True
            }
        },
        'system_call_monitor': {
            'enabled': platform.system().lower() != 'windows',  # More effective on Unix-like
            'monitor_syscalls': [
                'execve', 'fork', 'clone', 'ptrace', 'open', 'openat',
                'execveat', 'mount', 'umount2', 'chmod', 'chown',
                'setuid', 'setgid', 'capset', 'prctl', 'seccomp'
            ]
        },
        'network_monitor': {
            'enabled': True,
            'block_malicious_ips': True,
            'block_suspicious_domains': True,
            'monitor_ports': {
                'tcp': [21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 8080],
                'udp': [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 4500]
            }
        },
        'policies': {
            'enforcement_mode': 'block',  # 'monitor' or 'block'
            'default_action': 'alert',    # 'alert', 'block', 'terminate', 'quarantine'
            'protected_paths': [
                '/etc/passwd', '/etc/shadow', '/etc/hosts',
                'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64',
                '/bin', '/sbin', '/usr/bin', '/usr/sbin',
                '/usr/local/bin', '/usr/local/sbin'
            ],
            'protected_registry_keys': [
                'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment',
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
            ]
        },
        'logging': {
            'level': 'INFO',
            'file': '/var/log/hips/hips.log',
            'max_size_mb': 10,
            'backup_count': 5,
            'syslog': {
                'enabled': True,
                'address': '/dev/log',
                'facility': 'local0'
            },
            'console': True
        },
        'response': {
            'quarantine_dir': '/var/lib/hips/quarantine',
            'backup_dir': '/var/lib/hips/backups',
            'max_quarantine_size_mb': 1024,
            'max_backup_age_days': 30
        }
    }
    
    # Apply user overrides
    if config:
        import json
        import copy
        
        def update_dict(d, u):
            for k, v in u.items():
                if isinstance(v, dict):
                    d[k] = update_dict(d.get(k, {}), v)
                else:
                    d[k] = v
            return d
            
        update_dict(default_config, config)
    
    return HIPS(default_config)
