"""
Linux-specific monitoring implementation.
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
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable, Tuple

from . import SystemMonitor, PlatformNotSupportedError

class LinuxMonitor(SystemMonitor):
    """Linux-specific system monitoring implementation."""
    
    def __init__(self):
        self._watchers = {}
        self._proc_path = "/proc"
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get detailed system information."""
        try:
            # Get OS info from /etc/os-release
            os_info = {}
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", 'r') as f:
                    for line in f:
                        if '=' in line:
                            k, v = line.strip().split('=', 1)
                            os_info[k] = v.strip('"\'')
            
            # Get kernel version
            with open("/proc/version", 'r') as f:
                kernel_version = f.read().strip()
            
            # Get CPU info
            cpu_info = {}
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", 'r') as f:
                    for line in f:
                        if ':' in line:
                            k, v = line.split(':', 1)
                            cpu_info[k.strip()] = v.strip()
            
            # Get memory info
            mem_info = {}
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo", 'r') as f:
                    for line in f:
                        if ':' in line:
                            k, v = line.split(':', 1)
                            mem_info[k.strip()] = v.strip()
            
            return {
                'os': {
                    'name': os_info.get('NAME', 'Linux'),
                    'version': os_info.get('VERSION', ''),
                    'id': os_info.get('ID', ''),
                    'id_like': os_info.get('ID_LIKE', ''),
                    'version_codename': os_info.get('VERSION_CODENAME', ''),
                    'kernel_version': kernel_version,
                },
                'cpu': cpu_info,
                'memory': mem_info,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to get system info: {e}")
    
    def get_running_processes(self) -> List[Dict[str, Any]]:
        """Get detailed information about running processes."""
        processes = []
        
        try:
            # Iterate through /proc/[pid] directories
            for pid in [d for d in os.listdir(self._proc_path) if d.isdigit()]:
                try:
                    # Read process status
                    status = {}
                    if os.path.exists(f"{self._proc_path}/{pid}/status"):
                        with open(f"{self._proc_path}/{pid}/status") as f:
                            for line in f:
                                if ':' in line:
                                    k, v = line.split(':', 1)
                                    status[k.strip()] = v.strip()
                    
                    # Read command line
                    cmdline = []
                    if os.path.exists(f"{self._proc_path}/{pid}/cmdline"):
                        with open(f"{self._proc_path}/{pid}/cmdline", 'rb') as f:
                            cmdline = [arg.decode('utf-8', 'ignore') for arg in f.read().split(b'\x00') if arg]
                    
                    # Get executable path
                    exe_path = ''
                    if os.path.exists(f"{self._proc_path}/{pid}/exe"):
                        exe_path = os.path.realpath(f"{self._proc_path}/{pid}/exe")
                    
                    processes.append({
                        'pid': int(pid),
                        'name': status.get('Name', ''),
                        'ppid': int(status.get('PPid', 0)),
                        'state': status.get('State', ''),
                        'command_line': ' '.join(cmdline) if cmdline else '',
                        'executable_path': exe_path,
                        'user': status.get('Uid', '').split('\t')[0],
                        'group': status.get('Gid', '').split('\t')[0],
                        'threads': int(status.get('Threads', 0)),
                        'vm_size': int(status.get('VmSize', '0').split()[0]) * 1024 if 'VmSize' in status else 0,
                        'rss': int(status.get('VmRSS', '0').split()[0]) * 1024 if 'VmRSS' in status else 0,
                    })
                    
                except (PermissionError, FileNotFoundError, ProcessLookupError):
                    continue
                except Exception as e:
                    continue
            
            return processes
            
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to get process list: {e}")
    
    def get_network_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections."""
        connections = []
        
        try:
            # Read /proc/net/tcp and /proc/net/udp
            for proto, proto_name in [('tcp', 'tcp'), ('tcp6', 'tcp6'), ('udp', 'udp'), ('udp6', 'udp6')]:
                try:
                    with open(f"/proc/net/{proto}", 'r') as f:
                        # Skip header line
                        next(f)
                        
                        for line in f:
                            try:
                                fields = line.strip().split()
                                if len(fields) < 10:
                                    continue
                                
                                # Parse local and remote addresses
                                local_ip, local_port = self._parse_proc_net_addr(fields[1])
                                remote_ip, remote_port = self._parse_proc_net_addr(fields[2])
                                
                                # Get process info if available (Linux 2.6+)
                                inode = int(fields[9]) if len(fields) > 9 else 0
                                pid = self._find_pid_by_inode(proto_name, inode)
                                
                                connections.append({
                                    'protocol': proto_name,
                                    'local_address': local_ip,
                                    'local_port': local_port,
                                    'remote_address': remote_ip,
                                    'remote_port': remote_port,
                                    'state': self._get_tcp_state(int(fields[3], 16)) if proto_name.startswith('tcp') else 'N/A',
                                    'pid': pid,
                                    'inode': inode
                                })
                                
                            except (ValueError, IndexError):
                                continue
                                
                except FileNotFoundError:
                    continue
            
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
            
            # Get extended attributes if available
            xattrs = {}
            try:
                if hasattr(os, 'listxattr'):
                    for attr in os.listxattr(path):
                        try:
                            xattrs[attr] = os.getxattr(path, attr)
                        except (PermissionError, OSError):
                            xattrs[attr] = "[unreadable]"
            except (NotImplementedError, OSError):
                pass
            
            # Get file hashes
            hashes = self._calculate_file_hashes(path) if os.path.isfile(path) else {}
            
            return {
                'path': os.path.abspath(path),
                'type': file_type,
                'size': stat_info.st_size,
                'created': stat_info.st_ctime,
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
        """Monitor a file or directory for changes using inotify."""
        try:
            import inotify.adapters
            import inotify.constants as inotify_const
            
            # Resolve symlinks
            path = os.path.abspath(path)
            
            # Create inotify instance
            inotify = inotify.adapters.InotifyTree(
                path,
                mask=(
                    inotify_const.IN_CREATE |
                    inotify_const.IN_DELETE |
                    inotify_const.IN_MODIFY |
                    inotify_const.IN_MOVED_FROM |
                    inotify_const.IN_MOVED_TO |
                    inotify_const.IN_ATTRIB
                )
            )
            
            def monitor_thread():
                try:
                    for event in inotify.event_gen():
                        if event is not None:
                            (header, type_names, watch_path, filename) = event
                            
                            # Skip directory events if we're watching a file
                            if os.path.isfile(path) and filename:
                                continue
                                
                            callback({
                                'path': os.path.join(watch_path, filename) if filename else watch_path,
                                'timestamp': datetime.utcnow().isoformat(),
                                'event_types': type_names,
                                'is_directory': bool(inotify_const.IN_ISDIR in header.mask)
                            })
                except Exception as e:
                    callback({
                        'path': path,
                        'timestamp': datetime.utcnow().isoformat(),
                        'error': str(e),
                        'type': 'monitor_error'
                    })
            
            # Start monitoring thread
            import threading
            thread = threading.Thread(target=monitor_thread, daemon=True)
            thread.start()
            
            # Store the watcher
            self._watchers[path] = {
                'thread': thread,
                'inotify': inotify
            }
            
        except ImportError:
            # Fallback to polling if inotify is not available
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
    
    def get_system_logs(self, log_type: str = 'syslog', limit: int = 100) -> List[Dict[str, Any]]:
        """Get system logs."""
        logs = []
        
        try:
            # Determine log file based on log_type
            log_files = {
                'syslog': ['/var/log/syslog', '/var/log/messages'],
                'auth': ['/var/log/auth.log', '/var/log/secure'],
                'kernel': ['/var/log/kern.log'],
                'daemon': ['/var/log/daemon.log']
            }
            
            log_paths = log_files.get(log_type.lower(), [])
            log_path = None
            
            # Find the first existing log file
            for path in log_paths:
                if os.path.exists(path):
                    log_path = path
                    break
            
            if not log_path:
                return []
            
            # Read the last 'limit' lines from the log file
            try:
                # Use 'tail' command to efficiently get last N lines
                result = subprocess.run(
                    ['tail', f'-n{limit}', log_path],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if not line.strip():
                            continue
                            
                        # Basic log parsing (can be extended based on log format)
                        log_entry = {
                            'message': line,
                            'timestamp': datetime.utcnow().isoformat(),  # Default to now
                            'source': log_path
                        }
                        
                        # Try to extract timestamp if in standard format
                        try:
                            # Common log format: "MMM DD HH:MM:SS hostname process[pid]: message"
                            parts = line.split(maxsplit=4)
                            if len(parts) >= 5:
                                month, day, time_str, hostname, rest = parts
                                
                                # Parse the timestamp (assuming current year)
                                year = datetime.utcnow().year
                                month_num = time.strptime(month, '%b').tm_mon
                                day_num = int(day)
                                hour, minute, second = map(int, time_str.split(':'))
                                
                                log_entry['timestamp'] = datetime(
                                    year, month_num, day_num,
                                    hour, minute, second
                                ).isoformat()
                                
                                # Extract process and PID if available
                                if '[' in rest and ']' in rest:
                                    process_part = rest.split(']', 1)[0] + ']'
                                    process_name = process_part.split('[')[0].strip()
                                    pid = process_part.split('[')[1].split(']')[0]
                                    
                                    log_entry['process'] = process_name
                                    if pid.isdigit():
                                        log_entry['pid'] = int(pid)
                                
                                # The rest is the message
                                message_start = rest.find(']: ')
                                if message_start > 0:
                                    log_entry['message'] = rest[message_start + 3:].strip()
                                
                        except (ValueError, IndexError):
                            pass
                            
                        logs.append(log_entry)
                
            except subprocess.SubprocessError:
                # Fallback to reading file directly if 'tail' fails
                try:
                    with open(log_path, 'r', errors='ignore') as f:
                        for line in f:
                            if line.strip():
                                logs.append({'message': line.strip()})
                    
                    # Keep only the last 'limit' entries
                    logs = logs[-limit:]
                except Exception:
                    pass
            
            return logs
            
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to read {log_type} logs: {e}")
    
    def _parse_proc_net_addr(self, addr_str: str) -> Tuple[str, int]:
        """Parse address string from /proc/net/* files."""
        if ':' in addr_str:  # IPv6
            ip_part, port_part = addr_str.rsplit(':', 1)
            
            # Remove the leading '0000000000000000FFFF0000' prefix for IPv4-mapped IPv6 addresses
            if ip_part.startswith('0000000000000000FFFF0000'):
                ip_part = ip_part[24:]
                
            # Convert hex to IP address
            ip_bytes = bytes.fromhex(ip_part)
            ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
            
        else:  # IPv4
            ip_part, port_part = addr_str.split(':', 1)
            
            # Convert hex to IP address
            ip_int = int(ip_part, 16)
            ip = socket.inet_ntoa(struct.pack("<I", ip_int))
        
        # Convert hex port to integer
        port = int(port_part, 16)
        
        return ip, port
    
    def _get_tcp_state(self, state_hex: int) -> str:
        """Convert TCP state from hex to string."""
        tcp_states = {
            1: 'ESTABLISHED',
            2: 'SYN_SENT',
            3: 'SYN_RECV',
            4: 'FIN_WAIT1',
            5: 'FIN_WAIT2',
            6: 'TIME_WAIT',
            7: 'CLOSE',
            8: 'CLOSE_WAIT',
            9: 'LAST_ACK',
            10: 'LISTEN',
            11: 'CLOSING',
            12: 'NEW_SYN_RECV'
        }
        
        return tcp_states.get(state_hex, f'UNKNOWN ({state_hex})')
    
    def _find_pid_by_inode(self, proto: str, inode: int) -> Optional[int]:
        """Find the PID of a process using a network socket with the given inode."""
        if not inode:
            return None
            
        # Look for the inode in /proc/[pid]/fd/*
        for pid_dir in glob.glob('/proc/[0-9]*'):
            try:
                pid = int(os.path.basename(pid_dir))
                
                # Check if this process has a socket with our inode
                fd_path = f"/proc/{pid}/fd"
                if os.path.exists(fd_path):
                    for fd in os.listdir(fd_path):
                        try:
                            link = os.readlink(f"{fd_path}/{fd}")
                            # Format: "socket:[inode]"
                            if link.startswith(f'socket:[{inode}]'):
                                return pid
                        except (OSError, ValueError):
                            continue
            except (ValueError, PermissionError):
                continue
                
        return None
    
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
