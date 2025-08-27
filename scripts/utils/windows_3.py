"""
Windows-specific monitoring implementation.
"""

import os
import win32api
import win32security
import win32con
import win32process
import win32file
import win32event
import win32evtlog
import win32evtlogutil
import wmi
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime

from . import SystemMonitor, PlatformNotSupportedError

class WindowsMonitor(SystemMonitor):
    """Windows-specific system monitoring implementation."""
    
    def __init__(self):
        self._wmi = wmi.WMI()
        self._watchers = {}
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get detailed system information."""
        try:
            os_info = win32api.GetVersionEx(1)
            computer_system = self._wmi.Win32_ComputerSystem()[0]
            os_info_wmi = self._wmi.Win32_OperatingSystem()[0]
            
            return {
                'os': {
                    'name': 'Windows',
                    'version': f"{os_info[0]}.{os_info[1]}.{os_info[2]}",
                    'build': os_info_wmi.BuildNumber,
                    'install_date': os_info_wmi.InstallDate,
                },
                'hardware': {
                    'manufacturer': computer_system.Manufacturer,
                    'model': computer_system.Model,
                    'total_physical_memory': int(computer_system.TotalPhysicalMemory),
                },
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to get system info: {e}")
    
    def get_running_processes(self) -> List[Dict[str, Any]]:
        """Get detailed information about running processes."""
        processes = []
        try:
            for process in self._wmi.Win32_Process():
                processes.append({
                    'pid': process.ProcessId,
                    'name': process.Name,
                    'command_line': process.CommandLine or '',
                    'executable_path': process.ExecutablePath or '',
                    'parent_pid': process.ParentProcessId,
                })
            return processes
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to get process list: {e}")
    
    def get_network_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections."""
        connections = []
        try:
            for conn in self._wmi.Win32_PerfRawData_Tcpip_TCPv4():
                connections.append({
                    'local_address': conn.LocalAddress,
                    'local_port': conn.LocalPort,
                    'remote_address': conn.RemoteAddress,
                    'remote_port': conn.RemotePort,
                    'state': conn.State,
                    'pid': conn.OwningProcess,
                })
            return connections
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to get network connections: {e}")
    
    def get_file_metadata(self, path: str) -> Optional[Dict[str, Any]]:
        """Get detailed metadata for a file."""
        try:
            file_stat = os.stat(path)
            return {
                'path': os.path.abspath(path),
                'size': file_stat.st_size,
                'created': datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(file_stat.st_atime).isoformat(),
                'attributes': file_stat.st_file_attributes,
            }
        except Exception:
            return None
    
    def monitor_file_changes(self, path: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Monitor a file or directory for changes."""
        try:
            path = os.path.abspath(path)
            change_event = win32event.CreateEvent(None, 0, 0, None)
            
            dir_handle = win32file.CreateFile(
                os.path.dirname(path) if os.path.isfile(path) else path,
                win32con.FILE_LIST_DIRECTORY,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS | win32con.FILE_FLAG_OVERLAPPED,
                None
            )
            
            def monitor_thread():
                while True:
                    try:
                        win32file.ReadDirectoryChangesW(
                            dir_handle,
                            1024,
                            True,
                            win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                            win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                            win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                            win32con.FILE_NOTIFY_CHANGE_SIZE |
                            win32con.FILE_NOTIFY_CHANGE_LAST_WRITE,
                            None,
                            None
                        )
                        callback({
                            'path': path,
                            'timestamp': datetime.utcnow().isoformat(),
                            'type': 'file_change'
                        })
                    except Exception:
                        break
            
            import threading
            thread = threading.Thread(target=monitor_thread, daemon=True)
            thread.start()
            
            self._watchers[path] = {
                'thread': thread,
                'event': change_event,
                'handle': dir_handle
            }
            
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to set up file monitoring: {e}")
    
    def get_system_logs(self, log_type: str = 'system', limit: int = 100) -> List[Dict[str, Any]]:
        """Get system event logs."""
        logs = []
        try:
            log_map = {
                'system': 'System',
                'application': 'Application',
                'security': 'Security'
            }
            
            log_name = log_map.get(log_type.lower(), 'System')
            hand = win32evtlog.OpenEventLog(None, log_name)
            
            try:
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0, limit)
                
                for event in events:
                    try:
                        msg = win32evtlogutil.SafeFormatMessage(event, log_name)
                        logs.append({
                            'timestamp': event.TimeGenerated.isoformat(),
                            'source': event.SourceName,
                            'event_id': event.EventID & 0xFFFF,
                            'level': self._get_event_level(event.EventType),
                            'message': msg.strip() if msg else ''
                        })
                    except:
                        continue
                        
            finally:
                win32evtlog.CloseEventLog(hand)
                
        except Exception as e:
            raise PlatformNotSupportedError(f"Failed to read {log_type} logs: {e}")
        
        return logs
    
    @staticmethod
    def _get_event_level(event_type: int) -> str:
        """Convert Windows event type to severity level."""
        if event_type == win32evtlog.EVENTLOG_ERROR_TYPE:
            return 'error'
        elif event_type == win32evtlog.EVENTLOG_WARNING_TYPE:
            return 'warning'
        elif event_type == win32evtlog.EVENTLOG_INFORMATION_TYPE:
            return 'info'
        elif event_type == win32evtlog.EVENTLOG_AUDIT_SUCCESS:
            return 'audit_success'
        elif event_type == win32evtlog.EVENTLOG_AUDIT_FAILURE:
            return 'audit_failure'
        return 'unknown'
