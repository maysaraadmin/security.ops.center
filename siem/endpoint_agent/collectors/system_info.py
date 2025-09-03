"""
System Information Collector
---------------------------
Collects system information from the endpoint.
"""
import os
import sys
import time
import socket
import platform
import json
import logging
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from .base import BaseCollector

logger = logging.getLogger('siem_agent.collector.system_info')

class SystemInfoCollector(BaseCollector):
    """Collects system information from the endpoint."""
    
    def __init__(self, interval: int = 3600, **kwargs):
        """Initialize the system information collector.
        
        Args:
            interval: How often to collect system information (in seconds)
            **kwargs: Additional arguments passed to the base class
        """
        super().__init__(name="SystemInfo", **kwargs)
        self.interval = interval
        self.last_collection = 0
        self._system_info = {}
        self._network_info = {}
        self._user_info = {}
        self._installed_software = []
        self._initialized = False
        
        # Platform-specific initialization
        self._init_platform()
    
    def _init_platform(self):
        """Initialize platform-specific attributes and methods."""
        self.platform = sys.platform.lower()
        
        if self.platform.startswith('win'):
            self._get_system_info = self._get_windows_system_info
            self._get_network_info = self._get_windows_network_info
            self._get_user_info = self._get_windows_user_info
            self._get_installed_software = self._get_windows_installed_software
        elif self.platform.startswith('linux'):
            self._get_system_info = self._get_linux_system_info
            self._get_network_info = self._get_linux_network_info
            self._get_user_info = self._get_linux_user_info
            self._get_installed_software = self._get_linux_installed_software
        elif self.platform == 'darwin':
            self._get_system_info = self._get_macos_system_info
            self._get_network_info = self._get_macos_network_info
            self._get_user_info = self._get_macos_user_info
            self._get_installed_software = self._get_macos_installed_software
        else:
            logger.warning(f"Unsupported platform: {self.platform}")
            return
        
        self._initialized = True
    
    def _collect(self):
        """Collect system information if enough time has passed since the last collection."""
        if not self._initialized or not self.running:
            return
        
        current_time = time.time()
        if current_time - self.last_collection < self.interval:
            return
        
        try:
            logger.info("Collecting system information...")
            
            # Collect system information
            self._system_info = self._get_system_info()
            
            # Collect network information
            self._network_info = self._get_network_info()
            
            # Collect user information
            self._user_info = self._get_user_info()
            
            # Collect installed software (less frequently)
            if current_time - getattr(self, '_last_software_collection', 0) > 86400:  # Once per day
                self._installed_software = self._get_installed_software()
                self._last_software_collection = current_time
            
            # Import LogEntry and LogSeverity here to avoid circular imports
            from ..agent import LogEntry, LogSeverity
            
            # Create the log entry as a LogEntry object
            log_entry = LogEntry(
                timestamp=datetime.utcnow().isoformat() + 'Z',
                source='system_info',
                hostname=socket.gethostname(),
                log_type='inventory',
                severity=LogSeverity.INFO,
                message='System information collected',
                data={
                    'system': self._system_info,
                    'network': self._network_info,
                    'users': self._user_info,
                    'installed_software': self._installed_software
                }
            )
            
            self._add_log(log_entry)
            self.last_collection = current_time
            
        except Exception as e:
            logger.error(f"Error collecting system information: {e}", exc_info=True)
    
    # Platform-specific methods
    
    def _get_windows_system_info(self) -> Dict[str, Any]:
        """Get system information on Windows."""
        try:
            import wmi
            
            c = wmi.WMI()
            system_info = c.Win32_ComputerSystem()[0]
            os_info = c.Win32_OperatingSystem()[0]
            processor = c.Win32_Processor()[0]
            
            return {
                'os': {
                    'name': os_info.Caption,
                    'version': os_info.Version,
                    'build': os_info.BuildNumber,
                    'install_date': os_info.InstallDate,
                    'last_boot': os_info.LastBootUpTime
                },
                'hardware': {
                    'manufacturer': system_info.Manufacturer,
                    'model': system_info.Model,
                    'system_type': system_info.SystemType,
                    'total_physical_memory': system_info.TotalPhysicalMemory,
                    'processor': {
                        'name': processor.Name,
                        'manufacturer': processor.Manufacturer,
                        'architecture': processor.Architecture,
                        'cores': processor.NumberOfCores,
                        'logical_processors': processor.NumberOfLogicalProcessors
                    }
                },
                'bios': {
                    'version': c.Win32_BIOS()[0].Version,
                    'manufacturer': c.Win32_BIOS()[0].Manufacturer,
                    'release_date': c.Win32_BIOS()[0].ReleaseDate
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting Windows system info: {e}")
            return {'error': str(e)}
    
    def _get_windows_network_info(self) -> Dict[str, Any]:
        """Get network information on Windows."""
        try:
            import wmi
            import psutil
            
            c = wmi.WMI()
            
            # Get network interfaces
            interfaces = []
            for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                interfaces.append({
                    'description': interface.Description,
                    'mac_address': interface.MACAddress,
                    'ip_addresses': interface.IPAddress,
                    'subnet_masks': interface.IPSubnet,
                    'default_gateway': interface.DefaultIPGateway[0] if interface.DefaultIPGateway else None,
                    'dhcp_enabled': interface.DHCPEnabled,
                    'dhcp_server': interface.DHCPServer if interface.DHCPServer else None,
                    'dns_servers': interface.DNSServerSearchOrder if interface.DNSServerSearchOrder else []
                })
            
            # Get active connections
            connections = []
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
            
            return {
                'hostname': socket.gethostname(),
                'fqdn': socket.getfqdn(),
                'interfaces': interfaces,
                'active_connections': connections
            }
            
        except Exception as e:
            logger.error(f"Error getting Windows network info: {e}")
            return {'error': str(e)}
    
    def _get_windows_user_info(self) -> Dict[str, Any]:
        """Get user information on Windows."""
        try:
            import wmi
            import psutil
            
            c = wmi.WMI()
            logged_in_users = []
            local_users = []
            
            try:
                # Get logged in users
                for user in c.Win32_LoggedOnUser():
                    try:
                        logged_in_users.append({
                            'username': getattr(user.Antecedent, 'Name', 'Unknown'),
                            'domain': getattr(user.Antecedent, 'Domain', 'Unknown'),
                            'logon_type': 'Unknown',
                            'logon_time': None
                        })
                    except Exception as e:
                        logger.debug(f"Error processing logged in user: {e}")
                        continue
                
                # Get local users
                for user in c.Win32_UserAccount():
                    try:
                        local_users.append({
                            'username': getattr(user, 'Name', 'Unknown'),
                            'full_name': getattr(user, 'FullName', ''),
                            'description': getattr(user, 'Description', ''),
                            'disabled': not getattr(user, 'Disabled', False),
                            'account_type': getattr(user, 'AccountType', ''),
                            'sid': getattr(user, 'SID', '')
                        })
                    except Exception as e:
                        logger.debug(f"Error processing local user: {e}")
                        continue
                        
            except Exception as e:
                logger.warning(f"WMI query failed: {e}")
                # Fall back to basic user info using psutil
                try:
                    import getpass
                    local_users = [{
                        'username': getpass.getuser(),
                        'full_name': '',
                        'description': 'Current user',
                        'disabled': False,
                        'account_type': 'User',
                        'sid': ''
                    }]
                except Exception as e:
                    logger.error(f"Failed to get basic user info: {e}")
            
            # Get running processes with usernames
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time']):
                try:
                    pinfo = proc.info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'username': pinfo['username'],
                        'start_time': datetime.fromtimestamp(pinfo['create_time']).isoformat() if pinfo.get('create_time') else None
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            return {
                'logged_in_users': logged_in_users,
                'local_users': local_users,
                'processes': processes
            }
            
        except Exception as e:
            logger.error(f"Error getting Windows user info: {e}")
            return {'error': str(e)}
    
    def _get_windows_installed_software(self) -> List[Dict[str, Any]]:
        """Get installed software on Windows."""
        try:
            import winreg
            
            def get_reg_value(key, value_name, default=None):
                """Safely get a registry value with error handling."""
                try:
                    value, _ = winreg.QueryValueEx(key, value_name)
                    if isinstance(value, str):
                        value = value.strip(' \t\n\r\0')
                        if not value or value.lower() in ('(value not set)', 'n/a', 'none'):
                            return default
                    return value
                except WindowsError:
                    return default
            
            software_list = []
            seen_software = set()
            
            # Check both 64-bit and 32-bit software locations
            uninstall_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
            ]
            
            for hkey, uninstall_path in uninstall_paths:
                try:
                    with winreg.OpenKey(hkey, uninstall_path) as uninstall_key:
                        for i in range(0, winreg.QueryInfoKey(uninstall_key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(uninstall_key, i)
                                with winreg.OpenKey(uninstall_key, subkey_name) as subkey:
                                    try:
                                        name = get_reg_value(subkey, 'DisplayName')
                                        if not name:  # Skip if no display name
                                            continue
                                            
                                        # Skip if we've already seen this software (from another registry location)
                                        if name.lower() in seen_software:
                                            continue
                                            
                                        # Get all relevant software info with safe defaults
                                        version = get_reg_value(subkey, 'DisplayVersion')
                                        publisher = get_reg_value(subkey, 'Publisher')
                                        install_date = get_reg_value(subkey, 'InstallDate')
                                        install_location = get_reg_value(subkey, 'InstallLocation')
                                        uninstall_string = get_reg_value(subkey, 'UninstallString')
                                        
                                        # Create software entry
                                        software_entry = {
                                            'name': name,
                                            'version': version,
                                            'publisher': publisher,
                                            'install_date': install_date,
                                            'install_location': install_location,
                                            'uninstall_string': uninstall_string,
                                            'source': 'registry',
                                            'architecture': '64-bit' if 'WOW6432Node' in uninstall_path else '32-bit'
                                        }
                                        
                                        # Add to our list and mark as seen
                                        software_list.append(software_entry)
                                        seen_software.add(name.lower())
                                    except (WindowsError, OSError):
                                        continue
                            except (WindowsError, OSError):
                                continue
                except (WindowsError, OSError):
                    continue
            
            # Get from WMI as a fallback
            try:
                import wmi
                c = wmi.WMI()
                
                for product in c.Win32_Product():
                    software_list.append({
                        'name': product.Name,
                        'version': product.Version,
                        'vendor': product.Vendor,
                        'install_date': product.InstallDate,
                        'source': 'wmi',
                        'architecture': 'unknown'
                    })
            except Exception:
                pass
            
            return software_list
            
        except Exception as e:
            logger.error(f"Error getting Windows installed software: {e}")
            return []
    
    def _get_linux_system_info(self) -> Dict[str, Any]:
        """Get system information on Linux."""
        try:
            import distro
            import psutil
            
            # Get OS info
            os_info = {
                'name': ' '.join(distro.linux_distribution()),
                'version': platform.release(),
                'kernel': platform.version()
            }
            
            # Get CPU info
            with open('/proc/cpuinfo', 'r') as f:
                cpu_info = f.read()
            
            processor_info = {}
            for line in cpu_info.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    processor_info[key.strip()] = value.strip()
            
            # Get memory info
            mem = psutil.virtual_memory()
            
            return {
                'os': os_info,
                'hardware': {
                    'machine': platform.machine(),
                    'processor': platform.processor(),
                    'cpu_model': processor_info.get('model name', 'Unknown'),
                    'cpu_cores': psutil.cpu_count(logical=False),
                    'cpu_threads': psutil.cpu_count(logical=True),
                    'total_physical_memory': mem.total
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting Linux system info: {e}")
            return {'error': str(e)}
    
    def _get_linux_network_info(self) -> Dict[str, Any]:
        """Get network information on Linux."""
        try:
            import psutil
            import netifaces
            
            # Get network interfaces
            interfaces = []
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                
                # Skip loopback and non-IP interfaces
                if netifaces.AF_INET not in addrs:
                    continue
                
                # Get IPv4 addresses
                ipv4_addrs = []
                for addr in addrs[netifaces.AF_INET]:
                    ipv4_addrs.append({
                        'address': addr['addr'],
                        'netmask': addr.get('netmask', ''),
                        'broadcast': addr.get('broadcast', '')
                    })
                
                # Get MAC address
                mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', '')
                
                interfaces.append({
                    'name': iface,
                    'mac_address': mac,
                    'ipv4_addresses': ipv4_addrs
                })
            
            # Get active connections
            connections = []
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED' and conn.laddr:
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
            
            return {
                'hostname': socket.gethostname(),
                'fqdn': socket.getfqdn(),
                'interfaces': interfaces,
                'active_connections': connections
            }
            
        except Exception as e:
            logger.error(f"Error getting Linux network info: {e}")
            return {'error': str(e)}
    
    def _get_linux_user_info(self) -> Dict[str, Any]:
        """Get user information on Linux."""
        try:
            import pwd
            import psutil
            
            # Get logged in users
            logged_in_users = []
            for user in psutil.users():
                logged_in_users.append({
                    'username': user.name,
                    'terminal': user.terminal,
                    'host': user.host,
                    'started': datetime.fromtimestamp(user.started).isoformat()
                })
            
            # Get local users
            local_users = []
            for user in pwd.getpwall():
                if user.pw_uid >= 1000 or user.pw_uid == 0:  # Skip system users
                    local_users.append({
                        'username': user.pw_name,
                        'uid': user.pw_uid,
                        'gid': user.pw_gid,
                        'home': user.pw_dir,
                        'shell': user.pw_shell
                    })
            
            # Get running processes with usernames
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time']):
                try:
                    pinfo = proc.info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'username': pinfo['username'],
                        'start_time': datetime.fromtimestamp(pinfo['create_time']).isoformat() if pinfo.get('create_time') else None
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            return {
                'logged_in_users': logged_in_users,
                'local_users': local_users,
                'processes': processes
            }
            
        except Exception as e:
            logger.error(f"Error getting Linux user info: {e}")
            return {'error': str(e)}
    
    def _get_linux_installed_software(self) -> List[Dict[str, Any]]:
        """Get installed software on Linux."""
        try:
            import subprocess
            
            software_list = []
            
            # Try to get software from package managers
            package_managers = [
                ('dpkg', ['dpkg', '-l']),
                ('rpm', ['rpm', '-qa', '--queryformat', '%{NAME} %{VERSION} %{VENDOR}\n']),
                ('pacman', ['pacman', '-Q']),
                ('apk', ['apk', 'info'])
            ]
            
            for pkg_mgr, cmd in package_managers:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                    
                    if pkg_mgr == 'dpkg':
                        # Parse dpkg output
                        for line in result.stdout.split('\n')[5:]:  # Skip header
                            if not line.strip():
                                continue
                            parts = line.split()
                            if len(parts) >= 3:
                                software_list.append({
                                    'name': parts[1],
                                    'version': parts[2],
                                    'source': 'dpkg',
                                    'architecture': parts[3] if len(parts) > 3 else None
                                })
                    
                    elif pkg_mgr == 'rpm':
                        # Parse rpm output
                        for line in result.stdout.split('\n'):
                            if not line.strip():
                                continue
                            parts = line.split()
                            if parts:
                                software_list.append({
                                    'name': parts[0],
                                    'version': parts[1] if len(parts) > 1 else None,
                                    'vendor': ' '.join(parts[2:]) if len(parts) > 2 else None,
                                    'source': 'rpm'
                                })
                    
                    elif pkg_mgr == 'pacman':
                        # Parse pacman output
                        for line in result.stdout.split('\n'):
                            if ' ' in line:
                                name, version = line.split(' ', 1)
                                software_list.append({
                                    'name': name,
                                    'version': version,
                                    'source': 'pacman'
                                })
                    
                    elif pkg_mgr == 'apk':
                        # Parse apk output
                        for name in result.stdout.split('\n'):
                            if name.strip():
                                software_list.append({
                                    'name': name.strip(),
                                    'source': 'apk'
                                })
                    
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
            
            return software_list
            
        except Exception as e:
            logger.error(f"Error getting Linux installed software: {e}")
            return []
    
    def _get_macos_system_info(self) -> Dict[str, Any]:
        """Get system information on macOS."""
        try:
            import subprocess
            import plistlib
            
            # Get system profiler data
            result = subprocess.run(
                ['system_profiler', 'SPHardwareDataType', '-xml'],
                capture_output=True, text=True, check=True
            )
            
            # Parse the plist
            plist_data = plistlib.loads(result.stdout.encode('utf-8'))
            hardware = plist_data[0]['_items'][0]
            
            # Get memory info
            mem = psutil.virtual_memory()
            
            return {
                'os': {
                    'name': platform.mac_ver()[0],
                    'version': platform.mac_ver()[0],
                    'build': platform.mac_ver()[2],
                    'system': platform.system(),
                    'release': platform.release()
                },
                'hardware': {
                    'model': hardware.get('machine_name', hardware.get('model_name', 'Unknown')),
                    'model_identifier': hardware.get('machine_model', 'Unknown'),
                    'processor': hardware.get('cpu_type', 'Unknown'),
                    'cpu_cores': hardware.get('number_processors', 1) * hardware.get('packages', 1),
                    'total_physical_memory': mem.total,
                    'serial_number': hardware.get('serial_number', 'Unknown')
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting macOS system info: {e}")
            return {'error': str(e)}
    
    def _get_macos_network_info(self) -> Dict[str, Any]:
        """Get network information on macOS."""
        try:
            import psutil
            import netifaces
            
            # Get network interfaces
            interfaces = []
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                
                # Skip loopback and non-IP interfaces
                if netifaces.AF_INET not in addrs:
                    continue
                
                # Get IPv4 addresses
                ipv4_addrs = []
                for addr in addrs[netifaces.AF_INET]:
                    ipv4_addrs.append({
                        'address': addr['addr'],
                        'netmask': addr.get('netmask', ''),
                        'broadcast': addr.get('broadcast', '')
                    })
                
                # Get MAC address
                mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', '')
                
                interfaces.append({
                    'name': iface,
                    'mac_address': mac,
                    'ipv4_addresses': ipv4_addrs
                })
            
            # Get active connections
            connections = []
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED' and conn.laddr:
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
            
            return {
                'hostname': socket.gethostname(),
                'fqdn': socket.getfqdn(),
                'interfaces': interfaces,
                'active_connections': connections
            }
            
        except Exception as e:
            logger.error(f"Error getting macOS network info: {e}")
            return {'error': str(e)}
    
    def _get_macos_user_info(self) -> Dict[str, Any]:
        """Get user information on macOS."""
        try:
            import pwd
            import psutil
            
            # Get logged in users
            logged_in_users = []
            for user in psutil.users():
                logged_in_users.append({
                    'username': user.name,
                    'terminal': user.terminal,
                    'host': user.host,
                    'started': datetime.fromtimestamp(user.started).isoformat()
                })
            
            # Get local users
            local_users = []
            for user in pwd.getpwall():
                if user.pw_uid >= 500 or user.pw_uid == 0:  # Skip system users
                    local_users.append({
                        'username': user.pw_name,
                        'uid': user.pw_uid,
                        'gid': user.pw_gid,
                        'full_name': user.pw_gecos.split(',')[0] if user.pw_gecos else '',
                        'home': user.pw_dir,
                        'shell': user.pw_shell
                    })
            
            # Get running processes with usernames
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time']):
                try:
                    pinfo = proc.info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'username': pinfo['username'],
                        'start_time': datetime.fromtimestamp(pinfo['create_time']).isoformat() if pinfo.get('create_time') else None
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            return {
                'logged_in_users': logged_in_users,
                'local_users': local_users,
                'processes': processes
            }
            
        except Exception as e:
            logger.error(f"Error getting macOS user info: {e}")
            return {'error': str(e)}
    
    def _get_macos_installed_software(self) -> List[Dict[str, Any]]:
        """Get installed software on macOS."""
        try:
            import subprocess
            import plistlib
            
            software_list = []
            
            # Get applications from /Applications
            app_dirs = ['/Applications', os.path.expanduser('~/Applications')]
            
            for app_dir in app_dirs:
                if not os.path.exists(app_dir):
                    continue
                    
                for app in os.listdir(app_dir):
                    if app.endswith('.app'):
                        app_path = os.path.join(app_dir, app)
                        info_plist = os.path.join(app_path, 'Contents', 'Info.plist')
                        
                        if os.path.exists(info_plist):
                            try:
                                with open(info_plist, 'rb') as f:
                                    plist = plistlib.load(f)
                                    
                                    software_list.append({
                                        'name': plist.get('CFBundleName', app),
                                        'version': plist.get('CFBundleShortVersionString', 'Unknown'),
                                        'bundle_identifier': plist.get('CFBundleIdentifier', ''),
                                        'path': app_path,
                                        'source': 'app_bundle'
                                    })
                            except Exception:
                                software_list.append({
                                    'name': app,
                                    'path': app_path,
                                    'source': 'app_bundle'
                                })
            
            # Get software from Homebrew
            try:
                result = subprocess.run(
                    ['brew', 'list', '--versions'],
                    capture_output=True, text=True, check=True
                )
                
                for line in result.stdout.split('\n'):
                    if not line.strip():
                        continue
                    parts = line.split()
                    if parts:
                        software_list.append({
                            'name': parts[0],
                            'version': ' '.join(parts[1:]) if len(parts) > 1 else None,
                            'source': 'homebrew'
                        })
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
            
            # Get software from MacPorts
            try:
                result = subprocess.run(
                    ['port', 'installed'],
                    capture_output=True, text=True, check=True
                )
                
                for line in result.stdout.split('\n'):
                    if not line.strip() or line.startswith('  '):
                        continue
                    
                    parts = line.split()
                    if parts and parts[0] not in ('The', '--->'):
                        software_list.append({
                            'name': parts[0],
                            'version': parts[1] if len(parts) > 1 else None,
                            'source': 'macports'
                        })
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
            
            return software_list
            
        except Exception as e:
            logger.error(f"Error getting macOS installed software: {e}")
            return []
