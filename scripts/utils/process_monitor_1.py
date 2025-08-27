"""
Process Monitoring Module

This module provides process monitoring capabilities for the HIPS system,
including process creation/termination tracking, suspicious behavior detection,
and process tree analysis.
"""

import os
import sys
import time
import signal
import logging
import platform
import threading
import subprocess
from typing import Dict, List, Optional, Set, Tuple, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
import hashlib

# Platform-specific imports
try:
    import psutil
    import win32api
    import win32process
    import win32con
    import wmi
    WINDOWS = True
except ImportError:
    try:
        import psutil
        WINDOWS = False
    except ImportError:
        psutil = None

from ..utils.helpers import is_suspicious_process_name, calculate_file_hash

logger = logging.getLogger('hips.process_monitor')

@dataclass
class ProcessInfo:
    """Container for process information."""
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: List[str]
    username: str
    create_time: float
    hash: Optional[str] = None
    parent_name: Optional[str] = None
    children: List[int] = field(default_factory=list)
    suspicious: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class ProcessMonitor:
    """Monitors system processes for suspicious activities."""
    
    def __init__(
        self,
        config: Dict[str, Any],
        event_logger: 'EventLogger',
        response_engine: 'ResponseEngine',
        policy_manager: 'PolicyManager'
    ):
        """Initialize the process monitor.
        
        Args:
            config: Configuration dictionary
            event_logger: Event logger instance
            response_engine: Response engine for taking actions
            policy_manager: Policy manager for access control
        """
        self.config = config
        self.enabled = config.get('enabled', True)
        self.scan_interval = config.get('scan_interval', 5.0)
        self.monitor_children = config.get('monitor_children', True)
        self.critical_processes = set(
            p.lower() for p in config.get('critical_processes', [])
        )
        
        self.event_logger = event_logger
        self.response_engine = response_engine
        self.policy_manager = policy_manager
        
        self.running = False
        self._stop_event = threading.Event()
        self._monitor_thread = None
        self._process_cache: Dict[int, ProcessInfo] = {}
        self._process_tree: Dict[int, Set[int]] = {}  # parent_pid -> set of child pids
        self._process_lock = threading.RLock()
        self._suspicious_processes: Dict[int, Tuple[ProcessInfo, float]] = {}
        
        # Initialize platform-specific components
        self._init_platform()
        
        logger.info("Process monitor initialized")
    
    def _init_platform(self) -> None:
        """Initialize platform-specific components."""
        if WINDOWS:
            try:
                self.wmi = wmi.WMI()
                self._get_process_info = self._get_process_info_windows
            except Exception as e:
                logger.error(f"Failed to initialize WMI: {e}")
                self._get_process_info = self._get_process_info_psutil
        else:
            self._get_process_info = self._get_process_info_psutil
    
    def start(self) -> None:
        """Start the process monitor."""
        if not self.enabled:
            logger.info("Process monitor is disabled in configuration")
            return
            
        if self.running:
            logger.warning("Process monitor is already running")
            return
            
        logger.info("Starting process monitor...")
        self.running = True
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="ProcessMonitor",
            daemon=True
        )
        self._monitor_thread.start()
        logger.info("Process monitor started")
    
    def stop(self) -> None:
        """Stop the process monitor."""
        if not self.running:
            return
            
        logger.info("Stopping process monitor...")
        self.running = False
        self._stop_event.set()
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
            if self._monitor_thread.is_alive():
                logger.warning("Process monitor thread did not stop gracefully")
            self._monitor_thread = None
        
        logger.info("Process monitor stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        logger.debug("Process monitor loop started")
        
        # Initial scan
        self._scan_processes()
        
        # Main monitoring loop
        while not self._stop_event.is_set():
            try:
                start_time = time.monotonic()
                
                # Scan for new/terminated processes
                self._scan_processes()
                
                # Check for suspicious processes
                self._check_suspicious_processes()
                
                # Sleep for the remaining interval
                elapsed = time.monotonic() - start_time
                sleep_time = max(0, self.scan_interval - elapsed)
                self._stop_event.wait(timeout=sleep_time)
                
            except Exception as e:
                logger.error(f"Error in process monitor loop: {e}", exc_info=True)
                time.sleep(1)  # Prevent tight loop on errors
    
    def _scan_processes(self) -> None:
        """Scan running processes and detect changes."""
        try:
            current_pids = set()
            
            # Get all running processes
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
                try:
                    pid = proc.info['pid']
                    current_pids.add(pid)
                    
                    # Check if this is a new process
                    if pid not in self._process_cache:
                        self._handle_new_process(proc)
                    else:
                        # Update process info if needed
                        self._update_process(proc)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    logger.error(f"Error processing process {proc.pid}: {e}", exc_info=True)
            
            # Check for terminated processes
            dead_pids = set(self._process_cache.keys()) - current_pids
            for pid in dead_pids:
                self._handle_terminated_process(pid)
                
        except Exception as e:
            logger.error(f"Error scanning processes: {e}", exc_info=True)
    
    def _handle_new_process(self, proc: psutil.Process) -> None:
        """Handle a newly detected process."""
        try:
            # Get detailed process info
            proc_info = self._get_process_info(proc)
            if not proc_info:
                return
                
            # Check for suspicious attributes
            self._analyze_process(proc_info)
            
            # Cache the process
            with self._process_lock:
                self._process_cache[proc_info.pid] = proc_info
                
                # Update process tree
                if proc_info.ppid not in self._process_tree:
                    self._process_tree[proc_info.ppid] = set()
                self._process_tree[proc_info.ppid].add(proc_info.pid)
            
            # Log the new process
            self._log_process_event('process_start', proc_info)
            
            # Take action if process is suspicious
            if proc_info.suspicious:
                self._handle_suspicious_process(proc_info)
                
        except Exception as e:
            logger.error(f"Error handling new process {proc.pid}: {e}", exc_info=True)
    
    def _handle_terminated_process(self, pid: int) -> None:
        """Handle a terminated process."""
        try:
            with self._process_lock:
                if pid not in self._process_cache:
                    return
                    
                proc_info = self._process_cache[pid]
                
                # Log process termination
                self._log_process_event('process_end', proc_info)
                
                # Clean up process tree
                if pid in self._process_tree:
                    for child_pid in list(self._process_tree[pid]):
                        if child_pid in self._process_cache:
                            self._handle_terminated_process(child_pid)
                    del self._process_tree[pid]
                
                # Remove from parent's children
                for parent_pid, children in self._process_tree.items():
                    if pid in children:
                        children.remove(pid)
                
                # Remove from cache
                del self._process_cache[pid]
                
        except Exception as e:
            logger.error(f"Error handling terminated process {pid}: {e}", exc_info=True)
    
    def _update_process(self, proc: psutil.Process) -> None:
        """Update information for an existing process."""
        try:
            with self._process_lock:
                if proc.pid not in self._process_cache:
                    return
                    
                old_info = self._process_cache[proc.pid]
                new_info = self._get_process_info(proc)
                
                if not new_info:
                    return
                
                # Check for suspicious changes
                self._detect_process_changes(old_info, new_info)
                
                # Update cache
                self._process_cache[proc.pid] = new_info
                
        except Exception as e:
            logger.error(f"Error updating process {proc.pid}: {e}", exc_info=True)
    
    def _analyze_process(self, proc_info: ProcessInfo) -> None:
        """Analyze a process for suspicious characteristics."""
        # Check process name
        if is_suspicious_process_name(proc_info.name):
            proc_info.suspicious = True
            proc_info.suspicious_reasons.append(f"Suspicious process name: {proc_info.name}")
        
        # Check executable path
        if proc_info.exe and any(p in proc_info.exe.lower() for p in ['/tmp/', '/dev/shm/', '/var/tmp/']):
            proc_info.suspicious = True
            proc_info.suspicious_reasons.append(f"Suspicious executable path: {proc_info.exe}")
        
        # Check command line
        if proc_info.cmdline:
            cmdline = ' '.join(proc_info.cmdline).lower()
            suspicious_terms = ['-enc', '-e ', 'iex ', 'invoke-', 'nishang', 'mimikatz', 'meterpreter']
            if any(term in cmdline for term in suspicious_terms):
                proc_info.suspicious = True
                proc_info.suspicious_reasons.append("Suspicious command line arguments")
        
        # Check parent process
        if (proc_info.ppid in self._process_cache and 
            self._process_cache[proc_info.ppid].suspicious):
            proc_info.suspicious = True
            proc_info.suspicious_reasons.append(
                f"Parent process is suspicious: {self._process_cache[proc_info.ppid].name}"
            )
        
        # Check for critical system processes
        if proc_info.name.lower() in self.critical_processes:
            # Check if the process is running from an unusual location
            expected_paths = [
                '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/',
                'C:\\Windows\\System32\\', 'C:\\Windows\\SysWOW64\\'
            ]
            if proc_info.exe and not any(proc_info.exe.lower().startswith(p.lower()) for p in expected_paths):
                proc_info.suspicious = True
                proc_info.suspicious_reasons.append(
                    f"Critical system process running from unusual location: {proc_info.exe}"
                )
    
    def _detect_process_changes(self, old_info: ProcessInfo, new_info: ProcessInfo) -> None:
        """Detect and handle changes in process attributes."""
        # Check for code injection (process hollowing)
        if old_info.hash and new_info.hash and old_info.hash != new_info.hash:
            new_info.suspicious = True
            new_info.suspicious_reasons.append(
                f"Process image modified in memory (possible code injection). "
                f"Old hash: {old_info.hash[:8]}..., New hash: {new_info.hash[:8]}..."
            )
        
        # Check for suspicious module loading
        if WINDOWS and hasattr(self, 'wmi'):
            try:
                for module in self.wmi.Win32_ModuleLoadTrace(ProcessId=new_info.pid):
                    if any(s in module.FileName.lower() for s in ['temp', 'appdata', 'local\\temp']):
                        new_info.suspicious = True
                        new_info.suspicious_reasons.append(
                            f"Suspicious module loaded: {module.FileName}"
                        )
            except Exception as e:
                logger.debug(f"Error checking module load for {new_info.pid}: {e}")
    
    def _handle_suspicious_process(self, proc_info: ProcessInfo) -> None:
        """Handle a process that has been flagged as suspicious."""
        # Add to suspicious processes with timestamp
        self._suspicious_processes[proc_info.pid] = (proc_info, time.time())
        
        # Take action based on policy
        action = self.policy_manager.get_action_for_event(
            'suspicious_process',
            process=proc_info.name,
            pid=proc_info.pid,
            reasons=proc_info.suspicious_reasons
        )
        
        if action == 'terminate':
            self._terminate_process(proc_info.pid)
        elif action == 'quarantine' and proc_info.exe:
            self.response_engine.quarantine_file(proc_info.exe)
            self._terminate_process(proc_info.pid)
    
    def _check_suspicious_processes(self) -> None:
        """Check for suspicious processes that need further monitoring."""
        current_time = time.time()
        to_remove = []
        
        for pid, (proc_info, timestamp) in list(self._suspicious_processes.items()):
            # Remove if process no longer exists or timeout reached
            if (pid not in self._process_cache or 
                current_time - timestamp > 300):  # 5 minute timeout
                to_remove.append(pid)
                continue
                
            # Additional checks for suspicious behavior over time
            # (e.g., process making network connections, accessing sensitive files, etc.)
            
        # Clean up old entries
        for pid in to_remove:
            if pid in self._suspicious_processes:
                del self._suspicious_processes[pid]
    
    def _terminate_process(self, pid: int) -> bool:
        """Terminate a process."""
        try:
            if WINDOWS:
                handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, 0, pid)
                win32api.TerminateProcess(handle, 1)
                win32api.CloseHandle(handle)
            else:
                os.kill(pid, signal.SIGKILL)
                
            logger.warning(f"Terminated suspicious process {pid}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to terminate process {pid}: {e}")
            return False
    
    def _log_process_event(self, event_type: str, proc_info: ProcessInfo) -> None:
        """Log a process-related event."""
        event_data = {
            'event_type': event_type,
            'pid': proc_info.pid,
            'ppid': proc_info.ppid,
            'process_name': proc_info.name,
            'exe': proc_info.exe,
            'cmdline': proc_info.cmdline,
            'username': proc_info.username,
            'create_time': proc_info.create_time,
            'suspicious': proc_info.suspicious,
            'suspicious_reasons': proc_info.suspicious_reasons,
            'hash': proc_info.hash,
            'parent_name': proc_info.parent_name
        }
        
        self.event_logger.log('process', event_data)
    
    # Platform-specific process info retrieval methods
    
    def _get_process_info_windows(self, proc: psutil.Process) -> Optional[ProcessInfo]:
        """Get detailed process information on Windows."""
        try:
            # Get basic info
            proc_info = ProcessInfo(
                pid=proc.info['pid'],
                ppid=proc.info['ppid'],
                name=proc.info['name'],
                exe=proc.info['exe'],
                cmdline=proc.info['cmdline'] or [],
                username=proc.info['username'],
                create_time=proc.info['create_time'],
                parent_name=None
            )
            
            # Get parent process name if available
            if proc_info.ppid in self._process_cache:
                proc_info.parent_name = self._process_cache[proc_info.ppid].name
            
            # Calculate file hash if possible
            if proc_info.exe and os.path.exists(proc_info.exe):
                try:
                    proc_info.hash = calculate_file_hash(proc_info.exe)
                except Exception as e:
                    logger.debug(f"Error calculating hash for {proc_info.exe}: {e}")
            
            return proc_info
            
        except Exception as e:
            logger.error(f"Error getting Windows process info for {proc.pid}: {e}")
            return None
    
    def _get_process_info_psutil(self, proc: psutil.Process) -> Optional[ProcessInfo]:
        """Get process information using psutil (cross-platform)."""
        try:
            # Get basic info
            with proc.oneshot():
                proc_info = ProcessInfo(
                    pid=proc.pid,
                    ppid=proc.ppid(),
                    name=proc.name(),
                    exe=proc.exe() if proc.exe() else "",
                    cmdline=proc.cmdline(),
                    username=proc.username(),
                    create_time=proc.create_time(),
                    parent_name=None
                )
            
            # Get parent process name if available
            if proc_info.ppid in self._process_cache:
                proc_info.parent_name = self._process_cache[proc_info.ppid].name
            
            # Calculate file hash if possible
            if proc_info.exe and os.path.exists(proc_info.exe):
                try:
                    proc_info.hash = calculate_file_hash(proc_info.exe)
                except Exception as e:
                    logger.debug(f"Error calculating hash for {proc_info.exe}: {e}")
            
            return proc_info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            logger.error(f"Error getting process info for {proc.pid}: {e}", exc_info=True)
            return None

    def get_process_tree(self, pid: int, max_depth: int = 3) -> Dict:
        """Get the process tree starting from the specified PID.
        
        Args:
            pid: Root process ID
            max_depth: Maximum depth to traverse
            
        Returns:
            Nested dictionary representing the process tree
        """
        def build_tree(p: int, depth: int = 0) -> Optional[Dict]:
            if p not in self._process_cache or depth > max_depth:
                return None
                
            proc = self._process_cache[p]
            children = {}
            
            for child_pid in self._process_tree.get(p, []):
                child_tree = build_tree(child_pid, depth + 1)
                if child_tree:
                    children[child_pid] = child_tree
            
            return {
                'name': proc.name,
                'pid': proc.pid,
                'exe': proc.exe,
                'suspicious': proc.suspicious,
                'children': children
            }
        
        return build_tree(pid)
    
    def get_suspicious_processes(self) -> List[Dict]:
        """Get a list of currently suspicious processes."""
        with self._process_lock:
            return [
                {
                    'pid': p.pid,
                    'name': p.name,
                    'exe': p.exe,
                    'reasons': p.suspicious_reasons,
                    'first_seen': p.create_time
                }
                for p in self._process_cache.values()
                if p.suspicious
            ]

# Helper functions for process monitoring

def is_process_running(name: str) -> bool:
    """Check if a process with the given name is running."""
    try:
        return any(p.info['name'].lower() == name.lower() for p in psutil.process_iter(['name']))
    except Exception:
        return False

def find_processes_by_name(name: str) -> List[Dict]:
    """Find processes by name."""
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                if name.lower() in proc.info['name'].lower():
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': proc.info['cmdline'],
                        'username': proc.info['username']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        logger.error(f"Error finding processes by name: {e}")
    
    return processes
