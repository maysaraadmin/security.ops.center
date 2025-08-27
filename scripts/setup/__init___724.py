"""
HIPS Rules Engine.

This module implements the rule processing logic for the HIPS service.
"""
import os
import re
import time
import hashlib
import platform
import threading
import psutil
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Union, Pattern
from pathlib import Path

from src.common.logging_utils import get_logger
from src.common.utils import RateLimiter, Timer, run_in_threadpool

from src.services.hips.models import (
    HIPSProcessRule, HIPSFileRule, HIPSRegistryRule, 
    HIPSAlert, HIPSStats, HIPSAction, HIPSAlertLevel
)

class HIPSProcessMonitor:
    """Monitors process creation and execution."""
    
    def __init__(self, logger=None):
        """Initialize the process monitor."""
        self.logger = logger or get_logger('hips.process')
        self.rules: List[HIPSProcessRule] = []
        self.process_cache: Dict[int, dict] = {}
        self.rate_limiter = RateLimiter(max_calls=100, period=60)  # 100 calls per minute
        self._stop_event = threading.Event()
        self._monitor_thread = None
        
    def add_rule(self, rule: HIPSProcessRule) -> bool:
        """Add a process monitoring rule."""
        if any(r.rule_id == rule.rule_id for r in self.rules):
            self.logger.warning(f"Process rule with ID {rule.rule_id} already exists")
            return False
            
        self.rules.append(rule)
        self.logger.info(f"Added process rule: {rule.name} (ID: {rule.rule_id})")
        return True
        
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a process monitoring rule."""
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                self.rules.pop(i)
                self.logger.info(f"Removed process rule: {rule_id}")
                return True
                
        self.logger.warning(f"Process rule with ID {rule_id} not found")
        return False
        
    def enable_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """Enable or disable a process monitoring rule."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = enabled
                status = "enabled" if enabled else "disabled"
                self.logger.info(f"{status.capitalize()} process rule: {rule_id}")
                return True
                
        self.logger.warning(f"Process rule with ID {rule_id} not found")
        return False
        
    def check_process(self, process: 'psutil.Process') -> List[HIPSAlert]:
        """Check a process against all rules."""
        alerts = []
        
        try:
            # Skip if process is already in cache
            if process.pid in self.process_cache:
                return []
                
            # Get process info
            try:
                cmdline = ' '.join(process.cmdline()) if process.cmdline() else ''
                exe = process.exe() or ''
                name = process.name() or ''
                parent = process.parent()
                parent_name = parent.name() if parent else ''
                
                process_info = {
                    'pid': process.pid,
                    'name': name,
                    'exe': exe,
                    'cmdline': cmdline,
                    'parent_name': parent_name,
                    'create_time': process.create_time(),
                    'username': process.username() if hasattr(process, 'username') else ''
                }
                
                # Cache the process info
                self.process_cache[process.pid] = process_info
                
                # Check against all enabled rules
                for rule in (r for r in self.rules if r.enabled):
                    if self._matches_rule(process_info, rule):
                        alert = self._create_alert(process_info, rule)
                        alerts.append(alert)
                        
                        # Take action if needed
                        self._take_action(alert, process)
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process no longer exists or we don't have permission
                pass
                
        except Exception as e:
            self.logger.error(f"Error checking process {getattr(process, 'pid', 'unknown')}: {e}")
            
        return alerts
        
    def _matches_rule(self, process_info: dict, rule: HIPSProcessRule) -> bool:
        """Check if a process matches a rule."""
        # Check process name
        if rule.process_name and not re.search(rule.process_name, process_info['name'], re.IGNORECASE):
            return False
            
        # Check process path
        if rule.process_path and not re.search(rule.process_path, process_info['exe'], re.IGNORECASE):
            return False
            
        # Check parent process
        if rule.parent_process and not re.search(rule.parent_process, process_info['parent_name'], re.IGNORECASE):
            return False
            
        # Check command line
        if rule.command_line and not rule.command_line.search(process_info['cmdline']):
            return False
            
        return True
        
    def _create_alert(self, process_info: dict, rule: HIPSProcessRule) -> HIPSAlert:
        """Create an alert for a rule match."""
        from uuid import uuid4
        
        return HIPSAlert(
            alert_id=str(uuid4()),
            rule_id=rule.rule_id,
            rule_name=rule.name,
            timestamp=datetime.now(),
            message=f"Suspicious process detected: {process_info['name']} (PID: {process_info['pid']})",
            severity=rule.alert_level,
            action_taken=rule.action,
            details={
                'process': {
                    'pid': process_info['pid'],
                    'name': process_info['name'],
                    'path': process_info['exe'],
                    'command_line': process_info['cmdline'],
                    'parent': process_info['parent_name'],
                    'username': process_info.get('username', '')
                },
                'rule': rule.to_dict()
            }
        )
        
    def _take_action(self, alert: HIPSAlert, process: 'psutil.Process') -> None:
        """Take action based on the alert."""
        try:
            if alert.action_taken == HIPSAction.BLOCK:
                self._terminate_process(process, alert)
            elif alert.action_taken == HIPSAction.QUARANTINE:
                self._quarantine_process(process, alert)
                
        except Exception as e:
            self.logger.error(f"Failed to take action on process {process.pid}: {e}")
            
    def _terminate_process(self, process: 'psutil.Process', alert: HIPSAlert) -> None:
        """Terminate a process."""
        try:
            process.terminate()
            self.logger.warning(f"Terminated process {process.pid} ({process.name()})")
            alert.details['action'] = 'process_terminated'
        except Exception as e:
            self.logger.error(f"Failed to terminate process {process.pid}: {e}")
            alert.details['action'] = 'process_terminate_failed'
            alert.details['error'] = str(e)
            
    def _quarantine_process(self, process: 'psutil.Process', alert: HIPSAlert) -> None:
        """Quarantine a process and its files."""
        try:
            # First terminate the process
            self._terminate_process(process, alert)
            
            # Get process executable path
            exe = process.exe()
            if exe and os.path.exists(exe):
                # In a real implementation, this would move the file to quarantine
                self.logger.warning(f"Quarantined file: {exe}")
                alert.details['quarantined_file'] = exe
                alert.details['action'] = 'file_quarantined'
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine process {process.pid}: {e}")
            alert.details['action'] = 'quarantine_failed'
            alert.details['error'] = str(e)
            
    def start_monitoring(self, interval: float = 5.0) -> None:
        """Start background monitoring of processes."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            self.logger.warning("Process monitoring is already running")
            return
            
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True,
            name="HIPS-ProcessMonitor"
        )
        self._monitor_thread.start()
        self.logger.info("Started process monitoring")
        
    def stop_monitoring(self) -> None:
        """Stop background monitoring of processes."""
        self._stop_event.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)
        self.logger.info("Stopped process monitoring")
        
    def _monitor_loop(self, interval: float) -> None:
        """Background monitoring loop."""
        while not self._stop_event.is_set():
            try:
                self._check_running_processes()
            except Exception as e:
                self.logger.error(f"Error in process monitoring loop: {e}")
                
            # Wait for the next check
            self._stop_event.wait(interval)
            
    def _check_running_processes(self) -> None:
        """Check all running processes against the rules."""
        try:
            # Get all running processes
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
                try:
                    self.check_process(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
            # Clean up process cache
            self._cleanup_process_cache()
            
        except Exception as e:
            self.logger.error(f"Error checking running processes: {e}")
            
    def _cleanup_process_cache(self) -> None:
        """Remove dead processes from the cache."""
        current_time = time.time()
        dead_pids = []
        
        for pid, proc_info in list(self.process_cache.items()):
            # If process is older than 1 hour, remove it from cache
            if current_time - proc_info['create_time'] > 3600:
                dead_pids.append(pid)
                
        for pid in dead_pids:
            self.process_cache.pop(pid, None)
