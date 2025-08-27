"""
macOS-specific collectors for the EDR agent.
"""
import os
import re
import sys
import json
import time
import plistlib
import subprocess
import logging
import platform
import datetime
import pwd
import grp
from typing import Dict, List, Any, Optional, Tuple

import psutil
from .base import BaseCollector

logger = logging.getLogger('edr.agent.collector.darwin')

class DarwinCollector(BaseCollector):
    """macOS-specific collector implementation."""

    def _collect(self) -> Dict[str, Any]:
        """Collect system information specific to macOS."""
        data = {}

        try:
            if 'process' in self.config.get('collectors', []):
                data['processes'] = self._collect_processes()

            if 'network' in self.config.get('collectors', []):
                data['network'] = self._collect_network_info()

            if 'system' in self.config.get('collectors', []):
                data['system'] = self._collect_system_info()

            if 'applications' in self.config.get('collectors', []):
                data['applications'] = self._collect_installed_apps()

            if 'users' in self.config.get('collectors', []):
                data['users'] = self._collect_user_info()

            if 'launch_agents' in self.config.get('collectors', []):
                data['launch_agents'] = self._collect_launch_agents()

            if 'browser_extensions' in self.config.get('collectors', []):
                data['browser_extensions'] = self._collect_browser_extensions()

        except Exception as e:
            logger.error(f"Error in macOS collector: {e}", exc_info=True)

        return data

    def _run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
        """Run a shell command and return the result."""
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            return (result.returncode, result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            return (-1, '', 'Command timed out')
        except Exception as e:
            return (-1, '', str(e))

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

            # Collect interface information using ifconfig
            rc, out, _ = self._run_command(['ifconfig'])
            if rc == 0:
                current_interface = None
                for line in out.splitlines():
                    if not line.startswith('\t') and ':' in line:
                        current_interface = line.split(':')[0]
                        network_info['interfaces'].append({
                            'name': current_interface,
                            'addresses': []
                        })
                    elif current_interface and 'inet ' in line:
                        # Parse IP address and netmask
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            ip = parts[1]
                            netmask = parts[3] if len(parts) > 3 and 'netmask' in line else None
                            network_info['interfaces'][-1]['addresses'].append({
                                'family': 'AF_INET',
                                'address': ip,
                                'netmask': netmask
                            })
                    elif current_interface and 'inet6 ' in line:
                        # Parse IPv6 address
                        parts = line.strip().split()
                        if len(parts) >= 2 and '%' in parts[1]:
                            ip = parts[1].split('%')[0]
                            network_info['interfaces'][-1]['addresses'].append({
                                'family': 'AF_INET6',
                                'address': ip
                            })

            # Get routing table
            rc, out, _ = self._run_command(['netstat', '-nr'])
            if rc == 0:
                network_info['routing_table'] = out.splitlines()

            # Get ARP table
            rc, out, _ = self._run_command(['arp', '-an'])
            if rc == 0:
                network_info['arp_table'] = out.splitlines()

        except Exception as e:
            logger.error(f"Error collecting network info: {e}")

        return network_info

    def _collect_system_info(self) -> Dict[str, Any]:
        """Collect system information."""
        sys_info = {
            'hostname': platform.node(),
            'os': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.mac_ver()[0],
                'machine': platform.machine()
            },
            'cpu': {
                'cores': os.cpu_count(),
                'usage': psutil.cpu_percent(interval=1, percpu=True)
            },
            'memory': dict(psutil.virtual_memory()._asdict())
        }

        # Get system profiler data
        try:
            rc, out, _ = self._run_command(['system_profiler', 'SPHardwareDataType', '-json'])
            if rc == 0:
                hardware_info = json.loads(out)
                if 'SPHardwareDataType' in hardware_info and hardware_info['SPHardwareDataType']:
                    hw_data = hardware_info['SPHardwareDataType'][0]
                    sys_info['hardware'] = {
                        'model': hw_data.get('machine_name', 'Unknown'),
                        'model_identifier': hw_data.get('machine_model', 'Unknown'),
                        'processor': hw_data.get('cpu_type', 'Unknown'),
                        'processor_speed': hw_data.get('current_processor_speed', 'Unknown'),
                        'number_processors': hw_data.get('number_processors', 1),
                        'total_cores': hw_data.get('total_number_cores', 1),
                        'memory': hw_data.get('physical_memory', 'Unknown'),
                        'serial_number': hw_data.get('serial_number', 'Unknown')
                    }

        except Exception as e:
            logger.debug(f"Error getting system profiler data: {e}")

        # Get disk information
        sys_info['disks'] = []
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

        # Get battery information if available
        try:
            if hasattr(psutil, 'sensors_battery'):
                battery = psutil.sensors_battery()
                if battery:
                    sys_info['battery'] = {
                        'percent': battery.percent,
                        'power_plugged': battery.power_plugged,
                        'secsleft': battery.secsleft
                    }

        except Exception as e:
            logger.debug(f"Error getting battery info: {e}")

        return sys_info

    def _collect_installed_apps(self) -> List[Dict[str, Any]]:
        """Collect information about installed applications."""
        apps = []
        app_dirs = [
            '/Applications',
            os.path.expanduser('~/Applications'),
            '/System/Applications'
        ]

        for app_dir in app_dirs:
            if not os.path.isdir(app_dir):
                continue

            try:
                for app in os.listdir(app_dir):
                    if app.endswith('.app'):
                        app_path = os.path.join(app_dir, app)
                        info_plist = os.path.join(app_path, 'Contents', 'Info.plist')

                        if os.path.exists(info_plist):
                            try:
                                with open(info_plist, 'rb') as f:
                                    plist_data = plistlib.load(f)

                                    app_info = {
                                        'name': plist_data.get('CFBundleName', app),
                                        'bundle_identifier': plist_data.get('CFBundleIdentifier'),
                                        'version': plist_data.get('CFBundleShortVersionString'),
                                        'build': plist_data.get('CFBundleVersion'),
                                        'path': app_path,
                                        'executable': os.path.join(
                                            app_path, 'Contents', 'MacOS',
                                            plist_data.get('CFBundleExecutable', '')
                                        ) if 'CFBundleExecutable' in plist_data else None,
                                        'signing_info': self._get_code_signature(app_path)
                                    }

                                    # Get additional metadata
                                    app_info['file_info'] = {
                                        'size': self._get_folder_size(app_path),
                                        'created': os.path.getctime(app_path),
                                        'modified': os.path.getmtime(app_path),
                                        'permissions': oct(os.stat(app_path).st_mode)[-3:]
                                    }

                                    apps.append(app_info)

                            except Exception as e:
                                logger.debug(f"Error reading plist for {app}: {e}")

            except Exception as e:
                logger.debug(f"Error reading applications from {app_dir}: {e}")

        return apps

    def _get_code_signature(self, app_path: str) -> Dict[str, Any]:
        """Get code signature information for an application."""
        try:
            rc, out, _ = self._run_command(['codesign', '-dv', '--verbose=4', app_path])
            if rc == 0:
                signature = {}
                for line in out.splitlines():
                    if '=' in line:
                        key, value = line.split('=', 1)
                        signature[key.strip()] = value.strip()
                return signature

        except Exception as e:
            logger.debug(f"Error getting code signature for {app_path}: {e}")

        return {}

    def _get_folder_size(self, path: str) -> int:
        """Calculate the total size of a folder in bytes."""
        total = 0
        for dirpath, _, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total += os.path.getsize(fp)
                except (OSError, PermissionError):
                    continue
        return total

    def _collect_user_info(self) -> Dict[str, Any]:
        """Collect user and login information."""
        users = {
            'logged_in': [],
            'all_users': []
        }

        # Get logged in users
        try:
            rc, out, _ = self._run_command(['who'])
            if rc == 0:
                for line in out.splitlines():
                    parts = line.split()
                    if parts:
                        users['logged_in'].append({
                            'user': parts[0],
                            'tty': parts[1],
                            'login_time': ' '.join(parts[2:4])
                        })

        except Exception as e:
            logger.debug(f"Error getting logged in users: {e}")

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
            logger.debug(f"Error getting user list: {e}")

        return users

    def _collect_launch_agents(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect launch agents and daemons."""
        launch_items = {
            'user_agents': [],
            'system_agents': [],
            'user_daemons': [],
            'system_daemons': []
        }

        # Common launch agent/daemon directories
        launch_paths = [
            (os.path.expanduser('~/Library/LaunchAgents'), 'user_agents'),
            ('/Library/LaunchAgents', 'system_agents'),
            ('/System/Library/LaunchAgents', 'system_agents'),
            (os.path.expanduser('~/Library/LaunchDaemons'), 'user_daemons'),
            ('/Library/LaunchDaemons', 'system_daemons'),
            ('/System/Library/LaunchDaemons', 'system_daemons')
        ]

        for path, item_type in launch_paths:
            if not os.path.isdir(path):
                continue

            try:
                for plist_file in os.listdir(path):
                    if not plist_file.endswith('.plist'):
                        continue

                    plist_path = os.path.join(path, plist_file)
                    try:
                        with open(plist_path, 'rb') as f:
                            plist_data = plistlib.load(f)

                            # Get the program/script being executed
                            program = None
                            program_args = []

                            if 'ProgramArguments' in plist_data:
                                program_args = plist_data['ProgramArguments']
                                if program_args:
                                    program = program_args[0]

                            item_info = {
                                'file': plist_path,
                                'label': plist_data.get('Label', 'Unknown'),
                                'program': program,
                                'program_arguments': program_args[1:] if program_args and len(program_args) > 1 else [],
                                'run_at_load': plist_data.get('RunAtLoad', False),
                                'keep_alive': plist_data.get('KeepAlive', False),
                                'start_interval': plist_data.get('StartInterval'),
                                'start_calendar_interval': plist_data.get('StartCalendarInterval'),
                                'disabled': plist_data.get('Disabled', False),
                                'file_info': {
                                    'size': os.path.getsize(plist_path),
                                    'created': os.path.getctime(plist_path),
                                    'modified': os.path.getmtime(plist_path),
                                    'permissions': oct(os.stat(plist_path).st_mode)[-3:],
                                    'owner': pwd.getpwuid(os.stat(plist_path).st_uid).pw_name,
                                    'group': grp.getgrgid(os.stat(plist_path).st_gid).gr_name
                                }
                            }

                            launch_items[item_type].append(item_info)

                    except Exception as e:
                        logger.debug(f"Error reading plist {plist_file}: {e}")

            except Exception as e:
                logger.debug(f"Error reading launch items from {path}: {e}")

        return launch_items

    def _collect_browser_extensions(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect browser extensions from common browsers."""
        extensions = {
            'safari': [],
            'chrome': [],
            'firefox': [],
            'edge': [],
            'brave': []
        }

        # Safari extensions
        try:
            safari_ext_dir = os.path.expanduser('~/Library/Safari/Extensions/')
            if os.path.isdir(safari_ext_dir):
                for ext_file in os.listdir(safari_ext_dir):
                    if ext_file.endswith('.safariextz'):
                        ext_path = os.path.join(safari_ext_dir, ext_file)
                        extensions['safari'].append({
                            'name': os.path.splitext(ext_file)[0],
                            'path': ext_path,
                            'size': os.path.getsize(ext_path),
                            'modified': os.path.getmtime(ext_path)
                        })

        except Exception as e:
            logger.debug(f"Error collecting Safari extensions: {e}")

        # Chrome extensions
        try:
            chrome_ext_dir = os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Extensions/')
            if os.path.isdir(chrome_ext_dir):
                for ext_id in os.listdir(chrome_ext_dir):
                    ext_versions = os.path.join(chrome_ext_dir, ext_id)
                    if os.path.isdir(ext_versions):
                        for version in os.listdir(ext_versions):
                            manifest_path = os.path.join(ext_versions, version, 'manifest.json')
                            if os.path.isfile(manifest_path):
                                try:
                                    with open(manifest_path, 'r') as f:
                                        manifest = json.load(f)
                                        extensions['chrome'].append({
                                            'id': ext_id,
                                            'version': version,
                                            'name': manifest.get('name'),
                                            'description': manifest.get('description'),
                                            'permissions': manifest.get('permissions', []),
                                            'path': os.path.dirname(manifest_path)
                                        })

                                except Exception as e:
                                    logger.debug(f"Error reading Chrome extension manifest: {e}")

        except Exception as e:
            logger.debug(f"Error collecting Chrome extensions: {e}")

        # Firefox extensions
        try:
            firefox_profiles = os.path.expanduser('~/Library/Application Support/Firefox/Profiles/')
            if os.path.isdir(firefox_profiles):
                for profile in os.listdir(firefox_profiles):
                    ext_dir = os.path.join(firefox_profiles, profile, 'extensions')
                    if os.path.isdir(ext_dir):
                        for ext_file in os.listdir(ext_dir):
                            ext_path = os.path.join(ext_dir, ext_file)
                            if ext_file.endswith('.xpi'):
                                extensions['firefox'].append({
                                    'id': os.path.splitext(ext_file)[0],
                                    'path': ext_path,
                                    'size': os.path.getsize(ext_path)
                                })
                            elif os.path.isdir(ext_path):  # Unpacked extension
                                manifest_path = os.path.join(ext_path, 'manifest.json')
                                if os.path.isfile(manifest_path):
                                    try:
                                        with open(manifest_path, 'r') as f:
                                            manifest = json.load(f)
                                            extensions['firefox'].append({
                                                'id': ext_file,
                                                'name': manifest.get('name'),
                                                'description': manifest.get('description'),
                                                'version': manifest.get('version'),
                                                'path': ext_path
                                            })

                                    except Exception as e:
                                        logger.debug(f"Error reading Firefox extension manifest: {e}")

        except Exception as e:
            logger.debug(f"Error collecting Firefox extensions: {e}")

        return extensions
