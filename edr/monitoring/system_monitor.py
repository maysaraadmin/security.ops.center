"""
System Monitor for EDR Agent
---------------------------
Monitors system events including processes, files, and network activity.
"""
import os
import time
import logging
import threading
import psutil
import win32con
import win32file
import win32event
import win32api
import pywintypes
from typing import Dict, List, Callable, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger('edr.monitor')

@dataclass
class SystemEvent:
    """Represents a system event detected by the monitor."""
    event_type: str
    timestamp: float
    data: dict
    severity: str = 'INFO'

class SystemMonitor:
    """Monitors system events and notifies callbacks when events occur."""
    
    def __init__(self, config: Optional[dict] = None):
        """Initialize the system monitor."""
        self.config = config or {}
        self.running = False
        self.callbacks = []
        self.watch_paths = self.config.get('watch_paths', ['C:\\Windows\\System32'])
        self.process_monitor_thread = None
        self.file_monitor_thread = None
        self.network_monitor_thread = None
        
    def start(self):
        """Start monitoring system events."""
        if self.running:
            logger.warning("System monitor is already running")
            return
            
        self.running = True
        logger.info("Starting system monitor...")
        
        # Start monitoring threads
        self.process_monitor_thread = threading.Thread(target=self._monitor_processes)
        self.process_monitor_thread.daemon = True
        self.process_monitor_thread.start()
        
        self.file_monitor_thread = threading.Thread(target=self._monitor_files)
        self.file_monitor_thread.daemon = True
        self.file_monitor_thread.start()
        
        self.network_monitor_thread = threading.Thread(target=self._monitor_network)
        self.network_monitor_thread.daemon = True
        self.network_monitor_thread.start()
        
        logger.info("System monitor started")
    
    def stop(self):
        """Stop monitoring system events."""
        if not self.running:
            return
            
        self.running = False
        logger.info("Stopping system monitor...")
        
        # Wait for threads to finish
        if self.process_monitor_thread and self.process_monitor_thread.is_alive():
            self.process_monitor_thread.join(timeout=2)
            
        if self.file_monitor_thread and self.file_monitor_thread.is_alive():
            self.file_monitor_thread.join(timeout=2)
            
        if self.network_monitor_thread and self.network_monitor_thread.is_alive():
            self.network_monitor_thread.join(timeout=2)
            
        logger.info("System monitor stopped")
    
    def register_callback(self, callback: Callable):
        """Register a callback function to receive system events."""
        if callback not in self.callbacks:
            self.callbacks.append(callback)
    
    def _notify_callbacks(self, event: SystemEvent):
        """Notify all registered callbacks of a system event."""
        for callback in self.callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in system event callback: {e}")
    
    def _monitor_processes(self):
        """Monitor process creation and termination."""
        logger.info("Starting process monitor")
        
        # Get initial process list
        known_pids = set(p.pid for p in psutil.process_iter(['pid']))
        
        while self.running:
            try:
                current_pids = set(p.pid for p in psutil.process_iter(['pid']))
                
                # Check for new processes
                new_pids = current_pids - known_pids
                for pid in new_pids:
                    try:
                        p = psutil.Process(pid)
                        with p.oneshot():
                            event = SystemEvent(
                                event_type='PROCESS_CREATE',
                                timestamp=time.time(),
                                data={
                                    'pid': p.pid,
                                    'name': p.name(),
                                    'exe': p.exe(),
                                    'cmdline': p.cmdline(),
                                    'username': p.username(),
                                    'create_time': p.create_time(),
                                    'status': p.status(),
                                    'cpu_percent': p.cpu_percent(),
                                    'memory_percent': p.memory_percent()
                                },
                                severity='LOW'
                            )
                            self._notify_callbacks(event)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                known_pids = current_pids
                
            except Exception as e:
                logger.error(f"Error in process monitor: {e}")
            
            time.sleep(1)  # Check every second
    
    def _monitor_files(self):
        """Monitor file system changes."""
        logger.info("Starting file system monitor")
        
        # Set up change notification for each watch path
        change_handles = []
        for path in self.watch_paths:
            try:
                if os.path.isdir(path):
                    handle = win32file.CreateFile(
                        path,
                        win32con.GENERIC_READ,
                        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                        None,
                        win32con.OPEN_EXISTING,
                        win32con.FILE_FLAG_BACKUP_SEMANTICS,
                        None
                    )
                    change_handles.append(handle)
            except Exception as e:
                logger.error(f"Failed to monitor path {path}: {e}")
        
        if not change_handles:
            logger.warning("No valid paths to monitor")
            return
            
        while self.running and change_handles:
            try:
                # Wait for change notification
                handles = [h for h in change_handles if h]
                if not handles:
                    break
                    
                rc = win32event.WaitForMultipleObjects(
                    handles,
                    False,  # Wait for any
                    win32event.INFINITE
                )
                
                if rc == win32event.WAIT_FAILED:
                    logger.error("WaitForMultipleObjects failed")
                    break
                    
                idx = rc - win32event.WAIT_OBJECT_0
                if idx < 0 or idx >= len(handles):
                    logger.error("Invalid handle index")
                    continue
                    
                handle = handles[idx]
                
                # Get the change information
                try:
                    results = win32file.ReadDirectoryChangesW(
                        handle,
                        1024,
                        True,  # Watch subdirectories
                        win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                        win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                        win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                        win32con.FILE_NOTIFY_CHANGE_SIZE |
                        win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                        win32con.FILE_NOTIFY_CHANGE_SECURITY,
                        None,
                        None
                    )
                    
                    for action, filename in results:
                        if not self.running:
                            break
                            
                        full_path = os.path.join(path, filename)
                        
                        # Map action to event type
                        if action == win32con.FILE_ACTION_ADDED:
                            event_type = 'FILE_CREATE'
                            severity = 'MEDIUM'
                        elif action == win32con.FILE_ACTION_REMOVED:
                            event_type = 'FILE_DELETE'
                            severity = 'HIGH'
                        elif action == win32con.FILE_ACTION_MODIFIED:
                            event_type = 'FILE_MODIFY'
                            severity = 'LOW'
                        elif action == win32con.FILE_ACTION_RENAMED_OLD_NAME:
                            event_type = 'FILE_RENAME_OLD'
                            severity = 'MEDIUM'
                        elif action == win32con.FILE_ACTION_RENAMED_NEW_NAME:
                            event_type = 'FILE_RENAME_NEW'
                            severity = 'MEDIUM'
                        else:
                            event_type = 'FILE_OTHER'
                            severity = 'INFO'
                        
                        event = SystemEvent(
                            event_type=event_type,
                            timestamp=time.time(),
                            data={
                                'path': full_path,
                                'filename': filename,
                                'action': action
                            },
                            severity=severity
                        )
                        self._notify_callbacks(event)
                        
                except pywintypes.error as e:
                    if e.winerror != 995:  # ERROR_OPERATION_ABORTED
                        logger.error(f"Error reading directory changes: {e}")
                    continue
                
            except Exception as e:
                logger.error(f"Error in file monitor: {e}")
                time.sleep(1)  # Prevent tight loop on error
        
        # Clean up handles
        for handle in change_handles:
            try:
                if handle:
                    win32api.CloseHandle(handle)
            except:
                pass
    
    def _monitor_network(self):
        """Monitor network connections."""
        logger.info("Starting network monitor")
        
        # Get initial connections
        known_connections = set()
        
        while self.running:
            try:
                current_connections = set()
                
                for conn in psutil.net_connections(kind='inet'):
                    if not all([conn.laddr, hasattr(conn, 'raddr') and conn.raddr]):
                        continue
                        
                    # Skip localhost connections
                    if hasattr(conn, 'raddr') and conn.raddr and conn.raddr.ip in ('127.0.0.1', '::1'):
                        continue
                        
                    conn_id = (
                        conn.fd,
                        conn.family,
                        conn.type,
                        conn.laddr,
                        conn.raddr if hasattr(conn, 'raddr') else None,
                        conn.status,
                        conn.pid
                    )
                    current_connections.add(conn_id)
                    
                    # Check if this is a new connection
                    if conn_id not in known_connections:
                        try:
                            p = psutil.Process(conn.pid) if conn.pid else None
                            
                            event = SystemEvent(
                                event_type='NETWORK_CONNECTION',
                                timestamp=time.time(),
                                data={
                                    'pid': conn.pid,
                                    'process_name': p.name() if p else 'unknown',
                                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if hasattr(conn, 'raddr') and conn.raddr else None,
                                    'status': conn.status,
                                    'family': 'IPv4' if conn.family == 2 else 'IPv6',
                                    'type': 'TCP' if conn.type == 1 else 'UDP' if conn.type == 2 else 'UNIX' if conn.type == 1 else 'UNKNOWN'
                                },
                                severity='MEDIUM' if hasattr(conn, 'raddr') and conn.raddr else 'LOW'
                            )
                            self._notify_callbacks(event)
                            
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            continue
                
                known_connections = current_connections
                
            except Exception as e:
                logger.error(f"Error in network monitor: {e}")
            
            time.sleep(5)  # Check every 5 seconds

    def __del__(self):
        """Ensure cleanup on object deletion."""
        self.stop()
