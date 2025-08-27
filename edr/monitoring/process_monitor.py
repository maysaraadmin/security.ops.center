"""
Process monitoring for EDR.
Tracks process creation, termination, and modifications.
"""
import psutil
import time
import hashlib
import os
from typing import Dict, Any, List, Optional, Set
from datetime import datetime

from .base_monitor import BaseMonitor

class ProcessMonitor(BaseMonitor):
    """Monitors process creation, termination, and modifications."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the process monitor."""
        super().__init__(config)
        self.known_pids: Set[int] = set()
        self.scan_interval = float(self.config.get('scan_interval', 1.0))
        self.collect_hashes = self.config.get('collect_hashes', True)
        self.hash_algorithms = self.config.get('hash_algorithms', ['md5', 'sha1', 'sha256'])
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop for process events."""
        self._initialize_known_processes()
        
        while self.running:
            try:
                current_pids = set()
                
                # Check all running processes
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        current_pids.add(pid)
                        
                        # New process detected
                        if pid not in self.known_pids:
                            self._handle_new_process(proc)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                # Check for terminated processes
                for pid in self.known_pids - current_pids:
                    self._handle_terminated_process(pid)
                
                # Update known PIDs
                self.known_pids = current_pids
                
                # Sleep before next scan
                time.sleep(self.scan_interval)
                
            except Exception as e:
                self.logger.error(f"Error in process monitor: {e}", exc_info=True)
                time.sleep(5)  # Avoid tight loop on error
    
    def _initialize_known_processes(self) -> None:
        """Initialize the set of known running processes."""
        self.known_pids = {p.info['pid'] for p in psutil.process_iter(['pid'])}
        self.logger.info(f"Initialized with {len(self.known_pids)} running processes")
    
    def _handle_new_process(self, proc: psutil.Process) -> None:
        """Handle a newly created process."""
        try:
            with proc.oneshot():
                info = proc.as_dict(attrs=['pid', 'name', 'cmdline', 'username', 'create_time', 'exe'])
                
                # Get process hashes if enabled
                hashes = {}
                if self.collect_hashes and info.get('exe') and os.path.exists(info['exe']):
                    hashes = self._calculate_hashes(info['exe'])
                
                # Create process event
                event = self._create_event(
                    event_type='process_start',
                    data={
                        'pid': info['pid'],
                        'name': info['name'],
                        'command_line': ' '.join(info['cmdline']) if info['cmdline'] else '',
                        'executable_path': info.get('exe', ''),
                        'username': info.get('username', ''),
                        'create_time': datetime.fromtimestamp(info['create_time']).isoformat(),
                        'hashes': hashes,
                        'parent_pid': proc.ppid(),
                        'integrity_level': self._get_process_integrity(proc)
                    }
                )
                
                self._notify_handlers(event)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            self.logger.error(f"Error handling new process: {e}", exc_info=True)
    
    def _handle_terminated_process(self, pid: int) -> None:
        """Handle a terminated process."""
        try:
            event = self._create_event(
                event_type='process_stop',
                data={'pid': pid}
            )
            self._notify_handlers(event)
        except Exception as e:
            self.logger.error(f"Error handling terminated process: {e}", exc_info=True)
    
    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes using specified algorithms."""
        hashes = {}
        
        try:
            # Read file in chunks to handle large files
            chunk_size = 65536  # 64KB chunks
            
            # Initialize hash objects
            hash_objects = {algo: getattr(hashlib, algo)() for algo in self.hash_algorithms 
                          if hasattr(hashlib, algo)}
            
            # Read file and update hashes
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
            
            # Get hex digests
            hashes = {algo: hash_obj.hexdigest() 
                     for algo, hash_obj in hash_objects.items()}
            
        except Exception as e:
            self.logger.warning(f"Error calculating hashes for {file_path}: {e}")
        
        return hashes
    
    def _get_process_integrity(self, proc: psutil.Process) -> str:
        """Get process integrity level (Windows only)."""
        try:
            if hasattr(proc, 'uac_realtime'):
                return proc.uac_realtime()
            return 'N/A'
        except Exception:
            return 'N/A'
