"""
HIPS Service Implementation.

This module implements the Host-based Intrusion Prevention System (HIPS) service.
"""
import os
import sys
import time
import json
import signal
import logging
import threading
from typing import Dict, List, Optional, Any, Callable, Set
from pathlib import Path

from src.common.logging_utils import get_logger
from src.common.utils import RateLimiter, Timer, run_in_threadpool
from src.core.base_service import BaseService

from src.services.hips.models import (
    HIPSProcessRule, HIPSFileRule, HIPSRegistryRule,
    HIPSAlert, HIPSStats, HIPSAction, HIPSAlertLevel
)
from src.services.hips.rules import HIPSProcessMonitor, HIPSFileMonitor, HIPSRegistryMonitor

class HIPSService(BaseService):
    """
    Host-based Intrusion Prevention System (HIPS) service.
    
    Monitors system activities including processes, files, and registry changes
    to detect and prevent malicious activities on the host.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, **kwargs):
        """Initialize the HIPS service."""
        super().__init__(name='hips', **kwargs)
        
        # Configuration
        self.config = self._load_config(config or {})
        
        # Initialize monitors
        self.process_monitor = HIPSProcessMonitor(logger=self.logger.getChild('process'))
        self.file_monitor = HIPSFileMonitor(logger=self.logger.getChild('file'))
        self.registry_monitor = HIPSRegistryMonitor(logger=self.logger.getChild('registry'))
        
        # State
        self.running = False
        self._stop_event = threading.Event()
        self._monitor_thread = None
        self._alert_callbacks: List[Callable[[HIPSAlert], None]] = []
        
        # Statistics
        self.stats = HIPSStats(start_time=time.time())
        
        # Load default rules
        self._load_default_rules()
    
    def _load_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Load and validate configuration."""
        default_config = {
            'monitor_interval': 5.0,  # seconds
            'file_check_interval': 60.0,  # seconds
            'process_check_interval': 5.0,  # seconds
            'registry_check_interval': 30.0,  # seconds
            'max_alert_rate': 100,  # max alerts per minute
            'rules_file': 'config/hips_rules.json',
            'enable_process_monitoring': True,
            'enable_file_monitoring': True,
            'enable_registry_monitoring': platform.system() == 'Windows',
            'log_level': 'INFO'
        }
        
        # Merge with provided config
        config = {**default_config, **config}
        
        # Set log level
        self.logger.setLevel(getattr(logging, config['log_level'].upper(), logging.INFO))
        
        return config
    
    async def _start(self) -> bool:
        """Start the HIPS service."""
        if self.running:
            self.logger.warning("HIPS service is already running")
            return False
            
        try:
            self.logger.info("Starting HIPS service")
            self.running = True
            self._stop_event.clear()
            
            # Start monitoring threads
            if self.config['enable_process_monitoring']:
                self.process_monitor.start_monitoring(self.config['process_check_interval'])
                
            if self.config['enable_file_monitoring']:
                self.file_monitor.start_monitoring(self.config['file_check_interval'])
                
            if self.config['enable_registry_monitoring'] and platform.system() == 'Windows':
                self.registry_monitor.start_monitoring(self.config['registry_check_interval'])
            
            # Start the main monitoring loop
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True,
                name="HIPS-Monitor"
            )
            self._monitor_thread.start()
            
            self.logger.info("HIPS service started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start HIPS service: {e}", exc_info=True)
            self.running = False
            return False
    
    async def _stop(self) -> bool:
        """Stop the HIPS service."""
        if not self.running:
            return True
            
        self.logger.info("Stopping HIPS service")
        self.running = False
        self._stop_event.set()
        
        # Stop monitoring threads
        self.process_monitor.stop_monitoring()
        self.file_monitor.stop_monitoring()
        self.registry_monitor.stop_monitoring()
        
        # Wait for the monitor thread to finish
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)
            
        self.logger.info("HIPS service stopped")
        return True
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop for the HIPS service."""
        self.logger.info("Starting HIPS monitoring loop")
        
        while not self._stop_event.is_set():
            try:
                # Update statistics
                self._update_statistics()
                
                # Check for rule file changes
                self._check_rule_file()
                
                # Sleep until next check
                self._stop_event.wait(self.config['monitor_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in HIPS monitoring loop: {e}", exc_info=True)
                time.sleep(5)  # Prevent tight error loop
                
        self.logger.info("HIPS monitoring loop stopped")
    
    def _update_statistics(self) -> None:
        """Update service statistics."""
        # Update rule counts
        self.stats.process_rules = len([r for r in self.process_monitor.rules if r.enabled])
        self.stats.file_rules = len([r for r in self.file_monitor.rules if r.enabled])
        self.stats.registry_rules = len([r for r in self.registry_monitor.rules if r.enabled])
        
        # Update file monitoring stats
        self.stats.files_monitored = len(self.file_monitor.file_hashes)
        
        # Update memory usage
        try:
            import psutil
            process = psutil.Process(os.getpid())
            self.stats.memory_usage = process.memory_info().rss / (1024 * 1024)  # MB
            self.stats.cpu_usage = process.cpu_percent()
        except Exception as e:
            self.logger.debug(f"Failed to get process stats: {e}")
    
    def _check_rule_file(self) -> None:
        """Check for changes to the rule file and reload if needed."""
        rule_file = Path(self.config['rules_file'])
        
        if not rule_file.exists():
            return
            
        # Check if the file has been modified
        mtime = rule_file.stat().st_mtime
        if hasattr(self, '_last_rule_check') and mtime <= self._last_rule_check:
            return
            
        self._last_rule_check = mtime
        
        try:
            self.load_rules_from_file(rule_file)
            self.logger.info(f"Reloaded rules from {rule_file}")
        except Exception as e:
            self.logger.error(f"Failed to reload rules from {rule_file}: {e}", exc_info=True)
    
    def _load_default_rules(self) -> None:
        """Load default HIPS rules."""
        self.logger.info("Loading default HIPS rules")
        
        # Default process rules
        self.add_process_rule(HIPSProcessRule(
            rule_id="hips-proc-001",
            name="Suspicious Process Execution",
            description="Detects execution of potentially malicious processes",
            process_name=r"(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe)",
            action=HIPSAction.ALERT,
            alert_level=HIPSAlertLevel.HIGH
        ))
        
        # Default file rules
        if platform.system() == 'Windows':
            system_dirs = [
                r"C:\\Windows\\System32\\*",
                r"C:\\Windows\\SysWOW64\\*",
                r"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"
            ]
        else:
            system_dirs = [
                "/bin/*",
                "/sbin/*",
                "/usr/bin/*",
                "/usr/sbin/*",
                "/etc/init.d/*",
                "/etc/cron*/*"
            ]
            
        for i, path in enumerate(system_dirs, 1):
            self.add_file_rule(HIPSFileRule(
                rule_id=f"hips-file-{i:03d}",
                name=f"System Directory Protection: {path}",
                description=f"Monitors changes to system directory: {path}",
                path=path,
                action=HIPSAction.ALERT,
                alert_level=HIPSAlertLevel.HIGH,
                monitor_writes=True,
                monitor_executes=True,
                recursive=False
            ))
    
    def add_alert_callback(self, callback: Callable[[HIPSAlert], None]) -> None:
        """Add a callback function to be called when an alert is generated."""
        if callback not in self._alert_callbacks:
            self._alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: Callable[[HIPSAlert], None]) -> None:
        """Remove an alert callback function."""
        if callback in self._alert_callbacks:
            self._alert_callbacks.remove(callback)
    
    def _handle_alert(self, alert: HIPSAlert) -> None:
        """Handle a generated alert."""
        # Update statistics
        self.stats.alerts_triggered += 1
        
        # Log the alert
        log_msg = f"HIPS Alert: {alert.message} (Severity: {alert.severity.name}, Action: {alert.action_taken.name})"
        
        if alert.severity == HIPSAlertLevel.CRITICAL:
            self.logger.critical(log_msg)
        elif alert.severity == HIPSAlertLevel.HIGH:
            self.logger.error(log_msg)
        elif alert.severity == HIPSAlertLevel.MEDIUM:
            self.logger.warning(log_msg)
        else:
            self.logger.info(log_msg)
        
        # Call registered callbacks
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}", exc_info=True)
    
    # Process rule management
    def add_process_rule(self, rule: HIPSProcessRule) -> bool:
        """Add a process monitoring rule."""
        return self.process_monitor.add_rule(rule)
    
    def remove_process_rule(self, rule_id: str) -> bool:
        """Remove a process monitoring rule."""
        return self.process_monitor.remove_rule(rule_id)
    
    def enable_process_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """Enable or disable a process monitoring rule."""
        return self.process_monitor.enable_rule(rule_id, enabled)
    
    # File rule management
    def add_file_rule(self, rule: HIPSFileRule) -> bool:
        """Add a file monitoring rule."""
        return self.file_monitor.add_rule(rule)
    
    def remove_file_rule(self, rule_id: str) -> bool:
        """Remove a file monitoring rule."""
        return self.file_monitor.remove_rule(rule_id)
    
    def enable_file_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """Enable or disable a file monitoring rule."""
        return self.file_monitor.enable_rule(rule_id, enabled)
    
    # Registry rule management (Windows only)
    def add_registry_rule(self, rule: HIPSRegistryRule) -> bool:
        """Add a registry monitoring rule."""
        if platform.system() != 'Windows':
            self.logger.warning("Registry monitoring is only supported on Windows")
            return False
        return self.registry_monitor.add_rule(rule)
    
    def remove_registry_rule(self, rule_id: str) -> bool:
        """Remove a registry monitoring rule."""
        return self.registry_monitor.remove_rule(rule_id)
    
    def enable_registry_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """Enable or disable a registry monitoring rule."""
        return self.registry_monitor.enable_rule(rule_id, enabled)
    
    # Rule file operations
    def load_rules_from_file(self, file_path: str) -> bool:
        """Load rules from a JSON file."""
        try:
            with open(file_path, 'r') as f:
                rules_data = json.load(f)
                
            if not isinstance(rules_data, list):
                self.logger.error("Rules file should contain a list of rules")
                return False
                
            # Clear existing rules
            self.process_monitor.rules.clear()
            self.file_monitor.rules.clear()
            self.registry_monitor.rules.clear()
            
            # Add rules from file
            for rule_data in rules_data:
                try:
                    rule_type = rule_data.get('type')
                    
                    if rule_type == 'process':
                        rule = HIPSProcessRule.from_dict(rule_data)
                        self.add_process_rule(rule)
                    elif rule_type == 'file':
                        rule = HIPSFileRule.from_dict(rule_data)
                        self.add_file_rule(rule)
                    elif rule_type == 'registry' and platform.system() == 'Windows':
                        rule = HIPSRegistryRule.from_dict(rule_data)
                        self.add_registry_rule(rule)
                        
                except Exception as e:
                    self.logger.error(f"Failed to load rule: {e}", exc_info=True)
                    
            self.logger.info(f"Loaded {len(rules_data)} rules from {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load rules from {file_path}: {e}", exc_info=True)
            return False
    
    def save_rules_to_file(self, file_path: str) -> bool:
        """Save current rules to a JSON file."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            
            # Convert all rules to dictionaries
            rules = []
            rules.extend(r.to_dict() for r in self.process_monitor.rules)
            rules.extend(r.to_dict() for r in self.file_monitor.rules)
            
            if platform.system() == 'Windows':
                rules.extend(r.to_dict() for r in self.registry_monitor.rules)
            
            # Write to file
            with open(file_path, 'w') as f:
                json.dump(rules, f, indent=2)
                
            self.logger.info(f"Saved {len(rules)} rules to {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save rules to {file_path}: {e}", exc_info=True)
            return False
    
    # Status and statistics
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the HIPS service."""
        return {
            'status': 'running' if self.running else 'stopped',
            'process_rules': len([r for r in self.process_monitor.rules if r.enabled]),
            'file_rules': len([r for r in self.file_monitor.rules if r.enabled]),
            'registry_rules': len([r for r in self.registry_monitor.rules if r.enabled]),
            'files_monitored': len(self.file_monitor.file_hashes),
            'alerts_triggered': self.stats.alerts_triggered,
            'uptime': int(time.time() - self.stats.start_time)
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detailed statistics about the HIPS service."""
        return self.stats.to_dict()
    
    def __del__(self):
        """Clean up resources."""
        if hasattr(self, 'running') and self.running:
            self.stop()

# Factory function for service registration
def create_hips_service(config: Optional[Dict[str, Any]] = None, **kwargs) -> HIPSService:
    """Create and return a new HIPS service instance."""
    return HIPSService(config=config, **kwargs)
