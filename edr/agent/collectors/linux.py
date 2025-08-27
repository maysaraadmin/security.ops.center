"""
Linux-specific collectors for the EDR agent.
"""
import os
import re
import pwd
import grp
import json
import socket
import logging
import subprocess
import datetime
import platform
from typing import Dict, List, Any, Optional, Tuple

import psutil
from .base import BaseCollector


logger = logging.getLogger('edr.agent.collector.linux')


class LinuxCollector(BaseCollector):
    """Linux-specific collector implementation."""
    
    def _collect(self) -> Dict[str, Any]:
        """Collect system information specific to Linux."""
        data = {}
        
        try:
            if 'process' in self.config.get('collectors', []):
                data['processes'] = self._collect_processes()
            
            if 'network' in self.config.get('collectors', []):
                data['network'] = self._collect_network_info()
            
            if 'system' in self.config.get('collectors', []):
                data['system'] = self._collect_system_info()
            
            if 'packages' in self.config.get('collectors', []):
                data['packages'] = self._collect_installed_packages()
            
            if 'users' in self.config.get('collectors', []):
                data['users'] = self._collect_user_info()
            
            if 'services' in self.config.get('collectors', []):
                data['services'] = self._collect_services()
            
            if 'cron' in self.config.get('collectors', []):
                data['cron'] = self._collect_cron_jobs()
            
        except Exception as e:
            logger.error(f"Error in Linux collector: {e}", exc_info=True)
        
        return data
    
    def _collect_processes(self) -> List[Dict[str, Any]]:
        """Collect information about running processes."""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'status',
                                           'create_time', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'cmdline': proc_info['cmdline'],
                        'username': proc_info['username'],
                        'status': proc_info['status'],
                        'create_time': proc_info['create_time'],
                        'cpu_percent': proc_info['cpu_percent'],
                        'memory_percent': proc_info['memory_percent']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"Error collecting processes: {e}")
            
        return processes
    
    def _collect_network_info(self) -> Dict[str, Any]:
        """Collect network information."""
        network_info = {
            'connections': [],
            'interfaces': []
        }
        
        try:
            # Collect active connections
            for conn in psutil.net_connections(kind='inet'):
                network_info['connections'].append({
                    'family': conn.family.name,
                    'type': conn.type.name,
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if hasattr(conn, 'raddr') and conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
                
            # Collect interface information
            for name, addrs in psutil.net_if_addrs().items():
                iface = {
                    'name': name,
                    'addresses': []
                }
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        iface['addresses'].append({
                            'family': 'IPv4',
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        })
                    elif addr.family == socket.AF_INET6:
                        iface['addresses'].append({
                            'family': 'IPv6',
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
                    elif addr.family == psutil.AF_LINK:
                        iface['mac'] = addr.address
                
                network_info['interfaces'].append(iface)
                
            # Get routing table
            with open('/proc/net/route') as f:
                network_info['routing_table'] = f.readlines()
                
            # Get ARP table
            with open('/proc/net/arp') as f:
                network_info['arp_table'] = f.readlines()
                
        except Exception as e:
            logger.error(f"Error collecting network info: {e}")
            
        return network_info
    
    def _collect_system_info(self) -> Dict[str, Any]:
        """Collect system information."""
        sys_info = {
            'hostname': socket.gethostname(),
            'os': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine()
            },
            'cpu': {
                'cores': os.cpu_count(),
                'usage': psutil.cpu_percent(interval=1, percpu=True)
            },
            'memory': dict(psutil.virtual_memory()._asdict()),
            'disks': []
        }
        
        # Get disk information
        try:
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    sys_info['disks'].append({
                        'device': part.device,
                        'mountpoint': part.mountpoint,
                        'fstype': part.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free
                    })
                except Exception as e:
                    logger.debug(f"Error getting disk info for {part.mountpoint}: {e}")
        except Exception as e:
            logger.debug(f"Error getting disk partitions: {e}")
            
        return sys_info
    
    def _collect_installed_packages(self) -> Dict[str, List[Dict[str, str]]]:
        """Collect information about installed packages."""
        packages = {
            'dpkg': [],
            'rpm': []
        }
        
        # Debian/Ubuntu packages (dpkg)
        try:
            dpkg_cmd = ['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n']
            result = subprocess.run(dpkg_cmd, capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if '\t' in line:
                    pkg, version, arch = line.strip().split('\t')
                    packages['dpkg'].append({
                        'name': pkg,
                        'version': version,
                        'architecture': arch
                    })
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
            
        # RHEL/CentOS packages (rpm)
        try:
            rpm_cmd = ['rpm', '-qa', '--queryformat=%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n']
            result = subprocess.run(rpm_cmd, capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if '\t' in line:
                    pkg, version, arch = line.strip().split('\t')
                    packages['rpm'].append({
                        'name': pkg,
                        'version': version,
                        'architecture': arch
                    })
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
            
        return packages
    
    def _collect_user_info(self) -> Dict[str, Any]:
        """Collect user and login information."""
        users = {
            'logged_in': [],
            'all_users': []
        }
        
        # Get logged in users
        try:
            who_cmd = ['who']
            result = subprocess.run(who_cmd, capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                parts = line.split()
                if parts:
                    users['logged_in'].append({
                        'user': parts[0],
                        'tty': parts[1],
                        'login_time': ' '.join(parts[2:4])
                    })
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
            
        # Get all users
        try:
            for user in pwd.getpwall():
                users['all_users'].append({
                    'name': user.pw_name,
                    'uid': user.pw_uid,
                    'gid': user.pw_gid,
                    'home': user.pw_dir,
                    'shell': user.pw_shell
                })
        except Exception as e:
            logger.error(f"Error getting user list: {e}")
            
        return users
    
    def _collect_services(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect information about system services."""
        services = {
            'systemd': [],
            'initd': []
        }
        
        # Systemd services
        try:
            systemctl_cmd = ['systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--no-legend']
            result = subprocess.run(systemctl_cmd, capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4:
                    services['systemd'].append({
                        'name': parts[0],
                        'load': parts[1],
                        'active': parts[2],
                        'sub': parts[3],
                        'description': ' '.join(parts[4:]) if len(parts) > 4 else ''
                    })
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
            
        # Traditional init.d services
        try:
            if os.path.isdir('/etc/init.d'):
                for service in os.listdir('/etc/init.d'):
                    service_path = os.path.join('/etc/init.d', service)
                    if os.path.isfile(service_path) and os.access(service_path, os.X_OK):
                        services['initd'].append({
                            'name': service,
                            'path': service_path
                        })
        except Exception as e:
            logger.debug(f"Error getting init.d services: {e}")
            
        return services
    
    def _collect_cron_jobs(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect scheduled cron jobs."""
        cron_jobs = {
            'system': [],
            'user': {}
        }
        
        # System crontab
        try:
            if os.path.isfile('/etc/crontab'):
                with open('/etc/crontab', 'r') as f:
                    cron_jobs['system'] = self._parse_crontab(f.read())
        except Exception as e:
            logger.debug(f"Error reading system crontab: {e}")
            
        # User crontabs
        try:
            for user in pwd.getpwall():
                try:
                    user_cron = subprocess.check_output(
                        ['crontab', '-l', '-u', user.pw_name],
                        stderr=subprocess.PIPE
                    ).decode('utf-8')
                    cron_jobs['user'][user.pw_name] = self._parse_crontab(user_cron)
                except subprocess.CalledProcessError:
                    continue
        except Exception as e:
            logger.debug(f"Error reading user crontabs: {e}")
            
        return cron_jobs
    
    def _parse_crontab(self, crontab: str) -> List[Dict[str, Any]]:
        """Parse a crontab file into a list of job entries."""
        jobs = []
        for line in crontab.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Handle special cases like @reboot, @daily, etc.
            if line.startswith('@'):
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    jobs.append({
                        'special': parts[0],
                        'command': parts[1]
                    })
                continue
                
            # Parse standard crontab line
            parts = line.split()
            if len(parts) >= 6:
                jobs.append({
                    'minute': parts[0],
                    'hour': parts[1],
                    'day_of_month': parts[2],
                    'month': parts[3],
                    'day_of_week': parts[4],
                    'command': ' '.join(parts[5:])
                })
                
        return jobs
