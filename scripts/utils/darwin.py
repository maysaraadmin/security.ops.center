"""
macOS-specific monitoring implementation.
"""

import os
import re
import stat
import pwd
import grp
import glob
import time
import fcntl
import signal
import struct
import socket
import subprocess
import plistlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable, Tuple

from . import SystemMonitor, PlatformNotSupportedError

class DarwinMonitor(SystemMonitor):
    """macOS-specific system monitoring implementation."""
    
    def __init__(self):
        self._watchers = {}
        self._proc_path = "/proc"
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get detailed system information."""
        try:
            # Get macOS version info
            sw_vers = subprocess.check_output(["sw_vers"]).decode('utf-8')
            sw_vers = dict(
                line.split(':', 1)
                for line in sw_vers.splitlines()
                if ':' in line
            )
            
            # Get hardware info
            hw_model = subprocess.check_output(["sysctl", "-n", "hw.model"]).decode('utf-8').strip()
            hw_memsize = subprocess.check_output(["sysctl", "-n", "hw.memsize"]).decode('utf-8').strip()
            hw_ncpu = subprocess.check_output(["sysctl", "-n", "hw.ncpu"]).decode('utf-8').strip()
            
            return {
                'os': {
                    'name': 'macOS',
                    'product_name': sw_vers.get('ProductName', '').strip(),
                    'version': sw_vers.get('ProductVersion', '').strip(),
                    'build_version': sw_vers.get('BuildVersion', '').strip(),
                },
                'hardware': {
                    'model': hw_model,
                    'memory_bytes': int(hw_memsize),
                    'cpu_count': int(hw_ncpu),
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to get system info: {e}")
    
    def get_running_processes(self) -> List[Dict[str, Any]]:
        """Get detailed information about running processes."""
        processes = []
        
        try:
            # Use ps command to get process list
            ps_output = subprocess.check_output([
                "ps", "-A", "-o", "pid,ppid,user,group,pcpu,pmem,vsz,rss,tt,state,time,command"
            ]).decode('utf-8')
            
            # Parse ps output
            lines = ps_output.strip().split('\n')
            if len(lines) < 2:  # Header + at least one process
                return []
                
            headers = [h.lower() for h in lines[0].split()]
            
            for line in lines[1:]:
                try:
                    # Split the line, handling quoted command with arguments
                    parts = []
                    current = ""
                    in_quotes = False
                    
                    for char in line:
                        if char == '"':
                            in_quotes = not in_quotes
                        elif char == ' ' and not in_quotes:
                            if current:
                                parts.append(current)
                                current = ""
                            continue
                        else:
                            current += char
                    
                    if current:
                        parts.append(current)
                    
                    # The command may be split into multiple parts
                    if len(parts) > len(headers):
                        command_parts = parts[len(headers)-1:]
                        parts = parts[:len(headers)-1] + [' '.join(command_parts)]
                    
                    if len(parts) != len(headers):
                        continue
                    
                    process = dict(zip(headers, parts))
                    
                    processes.append({
                        'pid': int(process.get('pid', 0)),
                        'ppid': int(process.get('ppid', 0)),
                        'user': process.get('user', ''),
                        'group': process.get('group', ''),
                        'cpu_percent': float(process.get('pcpu', 0)),
                        'memory_percent': float(process.get('pmem', 0)),
                        'vsz': int(process.get('vsz', 0)) * 1024,  # Convert KB to bytes
                        'rss': int(process.get('rss', 0)) * 1024,   # Convert KB to bytes
                        'tty': process.get('tt', ''),
                        'state': process.get('state', ''),
                        'cpu_time': process.get('time', ''),
                        'command': process.get('command', '')
                    })
                    
                except (ValueError, KeyError):
                    continue
            
            return processes
            
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to get process list: {e}")
    
    def get_network_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections."""
        connections = []
        
        try:
            # Use netstat to get network connections
            netstat_output = subprocess.check_output([
                "netstat", "-anv", "-p", "tcp"
            ]).decode('utf-8')
            
            # Parse netstat output
            for line in netstat_output.split('\n'):
                if not line.strip() or 'Proto ' in line:
                    continue
                    
                # Parse the line
                parts = line.split()
                if len(parts) < 5:
                    continue
                
                proto = parts[0]
                
                # Skip header lines
                if proto == 'Proto' or 'Active' in proto or 'Internet' in proto:
                    continue
                
                # Parse local and remote addresses
                local_addr, local_port = self._parse_netstat_addr(parts[3])
                remote_addr, remote_port = self._parse_netstat_addr(parts[4])
                
                # Get process info if available (macOS netstat doesn't show PIDs)
                pid = None
                
                connections.append({
                    'protocol': proto.lower(),
                    'local_address': local_addr,
                    'local_port': local_port,
                    'remote_address': remote_addr,
                    'remote_port': remote_port,
                    'state': parts[5] if len(parts) > 5 else 'N/A',
                    'pid': pid
                })
            
            return connections
            
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to get network connections: {e}")
    
    def get_file_metadata(self, path: str) -> Optional[Dict[str, Any]]:
        """Get detailed metadata for a file."""
        try:
            stat_info = os.stat(path)
            
            # Get file type
            if stat.S_ISDIR(stat_info.st_mode):
                file_type = 'directory'
            elif stat.S_ISREG(stat_info.st_mode):
                file_type = 'file'
            elif stat.S_ISLNK(stat_info.st_mode):
                file_type = 'symlink'
            elif stat.S_ISBLK(stat_info.st_mode):
                file_type = 'block_device'
            elif stat.S_ISCHR(stat_info.st_mode):
                file_type = 'character_device'
            elif stat.S_ISFIFO(stat_info.st_mode):
                file_type = 'fifo'
            elif stat.S_ISSOCK(stat_info.st_mode):
                file_type = 'socket'
            else:
                file_type = 'unknown'
            
            # Get user and group names
            try:
                user = pwd.getpwuid(stat_info.st_uid).pw_name
            except KeyError:
                user = str(stat_info.st_uid)
                
            try:
                group = grp.getgrgid(stat_info.st_gid).gr_name
            except KeyError:
                group = str(stat_info.st_gid)
            
            # Get file permissions
            perms = {
                'user_read': bool(stat_info.st_mode & 0o400),
                'user_write': bool(stat_info.st_mode & 0o200),
                'user_execute': bool(stat_info.st_mode & 0o100),
                'group_read': bool(stat_info.st_mode & 0o040),
                'group_write': bool(stat_info.st_mode & 0o020),
                'group_execute': bool(stat_info.st_mode & 0o010),
                'other_read': bool(stat_info.st_mode & 0o004),
                'other_write': bool(stat_info.st_mode & 0o002),
                'other_execute': bool(stat_info.st_mode & 0o001),
                'setuid': bool(stat_info.st_mode & 0o4000),
                'setgid': bool(stat_info.st_mode & 0o2000),
                'sticky': bool(stat_info.st_mode & 0o1000),
            }
            
            # Get extended attributes
            xattrs = {}
            try:
                xattr_list = subprocess.check_output(["xattr", "-l", path], 
                                                  stderr=subprocess.DEVNULL).decode('utf-8')
                for line in xattr_list.split('\n'):
                    if ': ' in line:
                        k, v = line.split(': ', 1)
                        xattrs[k] = v
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
            
            # Get file hashes
            hashes = self._calculate_file_hashes(path) if os.path.isfile(path) else {}
            
            return {
                'path': os.path.abspath(path),
                'type': file_type,
                'size': stat_info.st_size,
                'created': stat_info.st_birthtime,
                'modified': stat_info.st_mtime,
                'accessed': stat_info.st_atime,
                'inode': stat_info.st_ino,
                'device': stat_info.st_dev,
                'hard_links': stat_info.st_nlink,
                'user': user,
                'group': group,
                'permissions': perms,
                'permissions_octal': oct(stat_info.st_mode & 0o7777),
                'extended_attributes': xattrs if xattrs else None,
                'hashes': hashes if hashes else None
            }
            
        except Exception as e:
            return None
    
    def monitor_file_changes(self, path: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Monitor a file or directory for changes using fsevents."""
        try:
            import fsevents
            
            # Resolve symlinks
            path = os.path.abspath(path)
            
            # Create observer
            observer = fsevents.Observer()
            
            def handle_event(event):
                callback({
                    'path': event.name,
                    'timestamp': datetime.utcnow().isoformat(),
                    'event_types': [event.flags],
                    'is_directory': os.path.isdir(event.name)
                })
            
            # Schedule the handler
            observer.schedule(handle_event, path, recursive=True)
            
            # Start the observer in a separate thread
            import threading
            thread = threading.Thread(target=observer.start, daemon=True)
            thread.start()
            
            # Store the watcher
            self._watchers[path] = {
                'thread': thread,
                'observer': observer
            }
            
        except ImportError:
            # Fallback to polling if fsevents is not available
            self._monitor_file_changes_polling(path, callback)
    
    def _monitor_file_changes_polling(self, path: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Fallback file monitoring using polling."""
        import threading
        
        class MonitorThread(threading.Thread):
            def __init__(self, path, callback):
                super().__init__(daemon=True)
                self.path = path
                self.callback = callback
                self._stop_event = threading.Event()
                self._file_stats = {}
                
                # Initial scan
                self._scan()
                
            def stop(self):
                self._stop_event.set()
                
            def _scan(self):
                if os.path.isfile(self.path):
                    try:
                        stat_info = os.stat(self.path)
                        self._file_stats[self.path] = stat_info
                    except OSError:
                        pass
                else:
                    for root, _, files in os.walk(self.path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                stat_info = os.stat(file_path)
                                self._file_stats[file_path] = stat_info
                            except OSError:
                                continue
            
            def run(self):
                while not self._stop_event.is_set():
                    try:
                        # Check for new or modified files
                        if os.path.isfile(self.path):
                            try:
                                stat_info = os.stat(self.path)
                                if self.path not in self._file_stats:
                                    # New file
                                    self.callback({
                                        'path': self.path,
                                        'timestamp': datetime.utcnow().isoformat(),
                                        'event_types': ['IN_CREATE'],
                                        'is_directory': False
                                    })
                                elif stat_info.st_mtime > self._file_stats[self.path].st_mtime:
                                    # Modified file
                                    self.callback({
                                        'path': self.path,
                                        'timestamp': datetime.utcnow().isoformat(),
                                        'event_types': ['IN_MODIFY'],
                                        'is_directory': False
                                    })
                                self._file_stats[self.path] = stat_info
                            except OSError:
                                pass
                        else:
                            # Check for deleted files
                            for file_path in list(self._file_stats.keys()):
                                if not os.path.exists(file_path):
                                    self.callback({
                                        'path': file_path,
                                        'timestamp': datetime.utcnow().isoformat(),
                                        'event_types': ['IN_DELETE'],
                                        'is_directory': False
                                    })
                                    del self._file_stats[file_path]
                            
                            # Check for new or modified files
                            for root, _, files in os.walk(self.path):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    try:
                                        stat_info = os.stat(file_path)
                                        if file_path not in self._file_stats:
                                            # New file
                                            self.callback({
                                                'path': file_path,
                                                'timestamp': datetime.utcnow().isoformat(),
                                                'event_types': ['IN_CREATE'],
                                                'is_directory': False
                                            })
                                        elif stat_info.st_mtime > self._file_stats[file_path].st_mtime:
                                            # Modified file
                                            self.callback({
                                                'path': file_path,
                                                'timestamp': datetime.utcnow().isoformat(),
                                                'event_types': ['IN_MODIFY'],
                                                'is_directory': False
                                            })
                                        self._file_stats[file_path] = stat_info
                                    except OSError:
                                        continue
                    
                    except Exception as e:
                        self.callback({
                            'path': self.path,
                            'timestamp': datetime.utcnow().isoformat(),
                            'error': str(e),
                            'type': 'monitor_error'
                        })
                    
                    # Wait before next scan
                    time.sleep(1)
        
        # Start the monitoring thread
        thread = MonitorThread(path, callback)
        thread.start()
        
        # Store the watcher
        self._watchers[path] = {
            'thread': thread
        }
    
    def get_system_logs(self, log_type: str = 'system', limit: int = 100) -> List[Dict[str, Any]]:
        """Get system logs using the log command."""
        logs = []
        
        try:
            # Map log type to log command predicates
            log_predicates = {
                'system': 'process == "system"',
                'auth': 'subsystem == "com.apple.Authorization"',
                'kernel': 'senderImagePath contains "/System/Library/Kernels/"',
                'application': 'process == "UserEventAgent"',
                'install': 'process == "installd"',
                'backup': 'process == "backupd"',
            }
            
            predicate = log_predicates.get(log_type.lower(), '')
            
            # Build the log command
            cmd = ["log", "show", "--style", "json", "--last", f"{limit}"]
            if predicate:
                cmd.extend(["--predicate", predicate])
            
            # Run the log command
            log_output = subprocess.check_output(cmd, timeout=10).decode('utf-8')
            
            # Parse the JSON output
            try:
                log_entries = []
                for line in log_output.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = plistlib.loads(line.encode('utf-8'))
                        log_entries.append(entry)
                    except (plistlib.InvalidFileException, ValueError):
                        continue
                
                # Convert to our format
                for entry in log_entries:
                    log_entry = {
                        'timestamp': entry.get('timestamp', datetime.utcnow().isoformat()),
                        'message': entry.get('message', ''),
                        'process': entry.get('process', ''),
                        'subsystem': entry.get('subsystem', ''),
                        'category': entry.get('category', ''),
                        'level': entry.get('level', '').lower(),
                        'source': 'system' if entry.get('process') == 'system' else 'application'
                    }
                    
                    # Add any additional fields
                    for k, v in entry.items():
                        if k not in log_entry and k not in ['timestamp', 'message']:
                            log_entry[k] = v
                    
                    logs.append(log_entry)
                
            except Exception as e:
                # Fallback to raw output if JSON parsing fails
                logs = [{'message': line} for line in log_output.split('\n') if line.strip()]
            
            return logs
            
        except subprocess.CalledProcessError as e:
            # Fallback to reading log files directly
            log_files = {
                'system': ['/var/log/system.log'],
                'auth': ['/var/log/secure.log'],
                'install': ['/var/log/install.log']
            }
            
            log_paths = log_files.get(log_type.lower(), [])
            
            for log_path in log_paths:
                if os.path.exists(log_path):
                    try:
                        with open(log_path, 'r') as f:
                            for line in f:
                                logs.append({'message': line.strip()})
                        
                        # Keep only the last 'limit' entries
                        logs = logs[-limit:]
                        break
                        
                    except Exception:
                        continue
            
            return logs
            
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to read {log_type} logs: {e}")
    
    def _parse_netstat_addr(self, addr_str: str) -> Tuple[str, int]:
        """Parse address string from netstat output."""
        if '.' in addr_str:  # IPv4
            if ':' in addr_str:
                ip_part, port_part = addr_str.rsplit(':', 1)
                return ip_part, int(port_part)
            return addr_str, 0
        elif ':' in addr_str:  # IPv6
            if '.' in addr_str:  # IPv4-mapped IPv6
                return addr_str, 0
            
            # Handle IPv6 with port: [::1].12345
            if '].' in addr_str:
                ip_part, port_part = addr_str.rsplit('.', 1)
                return ip_part.strip('[]'), int(port_part)
            elif ']:' in addr_str:
                ip_part, port_part = addr_str.rsplit(':', 1)
                return ip_part.strip('[]'), int(port_part)
            
            return addr_str, 0
        
        return addr_str, 0
    
    def _calculate_file_hashes(self, path: str) -> Dict[str, str]:
        """Calculate file hashes using different algorithms."""
        import hashlib
        
        hashes = {}
        
        try:
            # Define hash algorithms to use
            hash_algorithms = {
                'md5': hashlib.md5(),
                'sha1': hashlib.sha1(),
                'sha256': hashlib.sha256(),
                'sha512': hashlib.sha512()
            }
            
            # Calculate hashes in a single pass
            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(65536)  # 64KB chunks
                    if not chunk:
                        break
                    for alg in hash_algorithms.values():
                        alg.update(chunk)
            
            # Get hex digests
            for name, alg in hash_algorithms.items():
                hashes[name] = alg.hexdigest()
                
        except Exception as e:
            hashes['error'] = str(e)
            
        return hashes
