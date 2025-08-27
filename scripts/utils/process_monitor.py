""
Process monitoring and analysis for the EDR system.
"""

import os
import re
import sys
import time
import signal
import logging
import hashlib
import platform
import subprocess
from typing import Dict, List, Optional, Set, Callable, Any
from datetime import datetime

logger = logging.getLogger('edr.process_monitor')

class ProcessMonitor:
    """Monitor and analyze system processes."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the process monitor."""
        self.config = config or {}
        self._stop_event = False
        self._monitor_thread = None
        self._known_processes = set()
        self._load_config()
    
    def _load_config(self) -> None:
        """Load monitoring configuration."""
        self.scan_interval = self.config.get('scan_interval', 5)
        self.suspicious_names = set(self.config.get('suspicious_names', []))
        self.suspicious_cmdlines = set(self.config.get('suspicious_cmdlines', []))
        self.whitelisted_paths = set(self.config.get('whitelisted_paths', [
            '/bin', '/sbin', '/usr/bin', '/usr/sbin',
            'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64'
        ]))
    
    def start(self, callback: Callable[[Dict], None]) -> None:
        """Start process monitoring."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.warning("Monitoring already running")
            return
        
        self._stop_event = False
        self._monitor_thread = threading.Thread(
            target=self._monitor_processes,
            args=(callback,),
            daemon=True
        )
        self._monitor_thread.start()
    
    def stop(self) -> None:
        """Stop process monitoring."""
        self._stop_event = True
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
    
    def _monitor_processes(self, callback: Callable[[Dict], None]) -> None:
        """Monitor processes for suspicious activity."""
        while not self._stop_event:
            try:
                current_processes = self._get_processes()
                new_processes = current_processes - self._known_processes
                
                # Check new processes
                for pid in new_processes:
                    process_info = self._get_process_info(pid)
                    if not process_info:
                        continue
                        
                    # Check for suspicious indicators
                    if self._is_suspicious(process_info):
                        event = {
                            'type': 'suspicious_process',
                            'timestamp': datetime.utcnow().isoformat(),
                            'data': process_info
                        }
                        callback(event)
                
                # Update known processes
                self._known_processes = current_processes
                
                # Sleep before next scan
                time.sleep(self.scan_interval)
                
            except Exception as e:
                logger.error(f"Process monitoring error: {e}")
                time.sleep(5)  # Wait before retry
    
    def _get_processes(self) -> Set[int]:
        """Get set of running process PIDs."""
        try:
            import psutil
            return {p.pid for p in psutil.process_iter(['pid'])}
        except ImportError:
            # Fallback to platform-specific methods
            if sys.platform == 'win32':
                return self._get_windows_processes()
            else:
                return self._get_unix_processes()
    
    def _get_windows_processes(self) -> Set[int]:
        """Get running processes on Windows."""
        try:
            output = subprocess.check_output(
                ['wmic', 'process', 'get', 'ProcessId'],
                stderr=subprocess.DEVNULL,
                text=True
            )
            return {
                int(pid) for pid in output.split() 
                if pid.isdigit()
            }
        except (subprocess.SubprocessError, ValueError):
            return set()
    
    def _get_unix_processes(self) -> Set[int]:
        """Get running processes on Unix-like systems."""
        try:
            return {
                int(pid) for pid in os.listdir('/proc')
                if pid.isdigit()
            }
        except (OSError, ValueError):
            return set()
    
    def _get_process_info(self, pid: int) -> Optional[Dict]:
        """Get detailed information about a process."""
        try:
            import psutil
            p = psutil.Process(pid)
            
            # Get process attributes
            with p.oneshot():
                cmdline = p.cmdline()
                exe = p.exe()
                cwd = p.cwd()
                username = p.username()
                create_time = datetime.fromtimestamp(p.create_time())
                
                # Get hashes if possible
                file_hash = self._get_file_hash(exe) if exe and os.path.exists(exe) else None
                
                return {
                    'pid': pid,
                    'ppid': p.ppid(),
                    'name': p.name(),
                    'exe': exe,
                    'cmdline': cmdline,
                    'cwd': cwd,
                    'username': username,
                    'create_time': create_time.isoformat(),
                    'status': p.status(),
                    'cpu_percent': p.cpu_percent(),
                    'memory_percent': p.memory_percent(),
                    'open_files': [f.path for f in p.open_files()],
                    'connections': [{
                        'family': conn.family.name,
                        'type': conn.type.name,
                        'local_address': conn.laddr[0] if conn.laddr else None,
                        'local_port': conn.laddr[1] if conn.laddr and len(conn.laddr) > 1 else None,
                        'remote_address': conn.raddr[0] if conn.raddr else None,
                        'remote_port': conn.raddr[1] if conn.raddr and len(conn.raddr) > 1 else None,
                        'status': conn.status
                    } for conn in p.connections()],
                    'environ': dict(p.environ()),
                    'file_hash': file_hash,
                    'threads': p.num_threads(),
                    'is_running': p.is_running(),
                    'terminal': p.terminal()
                }
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            logger.error(f"Error getting process info for {pid}: {e}")
            return None
    
    def _get_file_hash(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes."""
        hashes = {}
        
        try:
            # Read file in chunks for large files
            chunk_size = 65536  # 64KB chunks
            
            # Initialize hash algorithms
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            
            hashes['md5'] = md5.hexdigest()
            hashes['sha1'] = sha1.hexdigest()
            hashes['sha256'] = sha256.hexdigest()
            
        except Exception as e:
            logger.warning(f"Error hashing file {file_path}: {e}")
        
        return hashes
    
    def _is_suspicious(self, process_info: Dict) -> bool:
        """Check if a process is suspicious."""
        # Check suspicious names
        if any(
            re.search(pattern, process_info['name'], re.IGNORECASE)
            for pattern in self.suspicious_names
        ):
            return True
        
        # Check command line arguments
        cmdline = ' '.join(process_info['cmdline']).lower()
        if any(
            re.search(pattern, cmdline, re.IGNORECASE)
            for pattern in self.suspicious_cmdlines
        ):
            return True
        
        # Check executable path
        exe_path = process_info.get('exe', '').lower()
        if exe_path and not any(
            exe_path.startswith(whitelisted.lower())
            for whitelisted in self.whitelisted_paths
        ):
            return True
        
        # Check for hidden processes (Linux/Unix)
        if sys.platform != 'win32' and not process_info.get('terminal') and not process_info['name'].startswith('systemd'):
            return True
        
        return False

def monitor_processes(callback: Callable[[Dict], None], 
                    config: Optional[Dict] = None) -> ProcessMonitor:
    """
    Start process monitoring with a callback.
    
    Args:
        callback: Function to call with suspicious processes
        config: Optional configuration
        
    Returns:
        ProcessMonitor instance
    """
    monitor = ProcessMonitor(config or {})
    monitor.start(callback)
    return monitor
