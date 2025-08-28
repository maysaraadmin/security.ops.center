"""
Forensic Data Collection for Incident Response.

This module handles the collection of forensic data from systems during incident response.
"""
import os
import sys
import json
import logging
import hashlib
import platform
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Callable, Union
from pathlib import Path
import shutil
import tempfile
import zipfile
import psutil
import socket
import time

logger = logging.getLogger(__name__)

class ForensicsError(Exception):
    """Base exception for forensics operations."""
    pass

class CollectorBase:
    """Base class for forensic data collectors."""
    
    def __init__(self, output_dir: str, compress: bool = True):
        """Initialize the collector.
        
        Args:
            output_dir: Directory to store collected data
            compress: Whether to compress the output
        """
        self.output_dir = Path(output_dir)
        self.compress = compress
        self.start_time = datetime.utcnow()
        self.collection_id = f"forensic_{self.start_time.strftime('%Y%m%d_%H%M%S')}"
        self.collection_dir = self.output_dir / self.collection_id
        self.temp_dir = Path(tempfile.mkdtemp(prefix=f"{self.collection_id}_"))
        
        # Create output directories
        self.collection_dir.mkdir(parents=True, exist_ok=True)
        
        # Collection metadata
        self.metadata = {
            'collection_id': self.collection_id,
            'start_time': self.start_time.isoformat(),
            'system': {
                'hostname': socket.gethostname(),
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'executable': sys.executable
            },
            'collectors': [],
            'files': [],
            'artifacts': []
        }
    
    def collect(self) -> Dict[str, Any]:
        """Perform the forensic collection."""
        try:
            logger.info(f"Starting forensic collection: {self.collection_id}")
            
            # Run all collection methods (methods starting with 'collect_')
            for method_name in dir(self):
                if method_name.startswith('collect_') and callable(getattr(self, method_name)):
                    try:
                        collector_name = method_name[8:]  # Remove 'collect_' prefix
                        logger.info(f"Running collector: {collector_name}")
                        
                        start_time = time.time()
                        result = getattr(self, method_name)()
                        duration = time.time() - start_time
                        
                        self.metadata['collectors'].append({
                            'name': collector_name,
                            'status': 'completed',
                            'duration_seconds': round(duration, 2),
                            'result': result or {}
                        })
                        
                    except Exception as e:
                        logger.error(f"Error in collector {method_name}: {e}", exc_info=True)
                        self.metadata['collectors'].append({
                            'name': method_name[8:],
                            'status': 'failed',
                            'error': str(e)
                        })
            
            # Save metadata
            self._save_metadata()
            
            # Package the collection if requested
            output_path = self._package_collection()
            
            # Clean up temporary files
            self._cleanup()
            
            return {
                'status': 'completed',
                'collection_id': self.collection_id,
                'output_path': str(output_path),
                'metadata': self.metadata
            }
            
        except Exception as e:
            logger.error(f"Forensic collection failed: {e}", exc_info=True)
            self.metadata['status'] = 'failed'
            self.metadata['error'] = str(e)
            self._save_metadata()
            
            return {
                'status': 'failed',
                'collection_id': self.collection_id,
                'error': str(e),
                'metadata': self.metadata
            }
    
    def _save_metadata(self) -> None:
        """Save the collection metadata to a file."""
        self.metadata['end_time'] = datetime.utcnow().isoformat()
        metadata_path = self.collection_dir / 'metadata.json'
        
        with open(metadata_path, 'w') as f:
            json.dump(self.metadata, f, indent=2)
    
    def _package_collection(self) -> Path:
        """Package the collected data into a single archive."""
        if not self.compress:
            return self.collection_dir
        
        output_file = self.output_dir / f"{self.collection_id}.zip"
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(self.collection_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(self.output_dir)
                    zipf.write(file_path, arcname)
        
        # Calculate hash of the archive
        file_hash = self._calculate_file_hash(output_file)
        self.metadata['package'] = {
            'filename': output_file.name,
            'size_bytes': os.path.getsize(output_file),
            'sha256': file_hash
        }
        self._save_metadata()
        
        return output_file
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate the SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def _save_command_output(self, command: str, output_file: str) -> Dict[str, Any]:
        """Run a command and save its output to a file."""
        output_path = self.temp_dir / output_file
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            with open(output_path, 'w') as f:
                f.write(f"$ {command}\n")
                f.write(f"Exit code: {result.returncode}\n")
                f.write("=" * 80 + "\n")
                f.write(result.stdout)
                f.write("\n" + "=" * 80 + "\n")
                f.write("STDERR:\n")
                f.write(result.stderr)
            
            file_info = self._add_artifact(output_path, 'command_output')
            file_info.update({
                'command': command,
                'exit_code': result.returncode
            })
            
            return file_info
            
        except subprocess.TimeoutExpired:
            with open(output_path, 'w') as f:
                f.write(f"$ {command}\n")
                f.write("ERROR: Command timed out after 5 minutes\n")
            
            file_info = self._add_artifact(output_path, 'command_output')
            file_info.update({
                'command': command,
                'error': 'Command timed out'
            })
            
            return file_info
            
        except Exception as e:
            with open(output_path, 'w') as f:
                f.write(f"$ {command}\n")
                f.write(f"ERROR: {str(e)}\n")
            
            file_info = self._add_artifact(output_path, 'command_output')
            file_info.update({
                'command': command,
                'error': str(e)
            })
            
            return file_info
    
    def _copy_file(self, src_path: str, dest_path: Optional[str] = None) -> Dict[str, Any]:
        """Copy a file to the collection directory."""
        src = Path(src_path)
        
        if not src.exists():
            raise FileNotFoundError(f"Source file not found: {src_path}")
        
        if dest_path is None:
            # Create a relative path in the collection directory
            rel_path = str(src).lstrip('/\\')
            rel_path = rel_path.replace(':', '_')  # Handle Windows drive letters
            dest = self.collection_dir / 'files' / rel_path
        else:
            dest = self.collection_dir / dest_path
        
        # Create parent directories if they don't exist
        dest.parent.mkdir(parents=True, exist_ok=True)
        
        # Copy the file
        if src.is_file():
            shutil.copy2(src, dest)
        elif src.is_dir():
            shutil.copytree(src, dest, dirs_exist_ok=True)
        else:
            raise ValueError(f"Unsupported file type: {src_path}")
        
        return self._add_artifact(dest, 'file_copy')
    
    def _add_artifact(self, path: Path, artifact_type: str) -> Dict[str, Any]:
        """Add an artifact to the collection metadata."""
        if not path.exists():
            raise FileNotFoundError(f"Artifact not found: {path}")
        
        # Calculate file hash
        file_hash = self._calculate_file_hash(path)
        
        # Get file info
        stat = path.stat()
        
        artifact = {
            'path': str(path.relative_to(self.collection_dir)),
            'type': artifact_type,
            'size_bytes': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'sha256': file_hash
        }
        
        self.metadata['artifacts'].append(artifact)
        return artifact
    
    def _cleanup(self) -> None:
        """Clean up temporary files."""
        try:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            logger.warning(f"Error cleaning up temporary files: {e}")


class WindowsForensicCollector(CollectorBase):
    """Forensic data collector for Windows systems."""
    
    def collect_system_info(self) -> Dict[str, Any]:
        """Collect system information."""
        info = {
            'system_info': {}
        }
        
        try:
            # System information
            self._save_command_output('systeminfo', 'system_info.txt')
            
            # Network configuration
            self._save_command_output('ipconfig /all', 'network_ipconfig.txt')
            self._save_command_output('netstat -ano', 'network_connections.txt')
            self._save_command_output('arp -a', 'network_arp.txt')
            
            # Running processes
            self._save_command_output('tasklist /v', 'processes.txt')
            
            # Services
            self._save_command_output('net start', 'services_running.txt')
            self._save_command_output('sc query state= all', 'services_detailed.txt')
            
            # Scheduled tasks
            self._save_command_output('schtasks /query /fo LIST /v', 'scheduled_tasks.txt')
            
            # User accounts
            self._save_command_output('net user', 'users.txt')
            self._save_command_output('net localgroup administrators', 'local_administrators.txt')
            
            # Security logs (requires admin)
            try:
                self._save_command_output(
                    'wevtutil qe Security /f:text /rd:true /c:1000', 
                    'logs_security.txt'
                )
            except Exception as e:
                logger.warning(f"Could not collect security logs: {e}")
            
            # Collect important files
            try:
                self._copy_file(r'C:\Windows\System32\drivers\etc\hosts')
            except Exception as e:
                logger.warning(f"Could not copy hosts file: {e}")
            
            return info
            
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            raise
    
    def collect_memory_dump(self) -> Dict[str, Any]:
        """Create a memory dump (requires admin privileges)."""
        try:
            # This is a placeholder - in a real implementation, you would use a tool like WinPmem
            output_file = self.collection_dir / 'memory.dmp'
            
            # Check if we have admin privileges
            try:
                import ctypes
                if os.name == 'nt':
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                else:
                    is_admin = os.getuid() == 0
                    
                if not is_admin:
                    return {'status': 'skipped', 'reason': 'Administrator privileges required'}
                    
            except (AttributeError, OSError) as e:
                logger.warning(f"Error checking admin status: {e}")
                return {'status': 'error', 'reason': f'Failed to check admin status: {str(e)}'}
            
            # In a real implementation, you would call the memory acquisition tool here
            # For example: os.system(f'dumpit.exe -o {output_file} -t raw')
            
            return {
                'status': 'not_implemented',
                'message': 'Memory dump collection is not implemented in this version'
            }
            
        except Exception as e:
            logger.error(f"Error collecting memory dump: {e}")
            raise


class LinuxForensicCollector(CollectorBase):
    """Forensic data collector for Linux systems."""
    
    def collect_system_info(self) -> Dict[str, Any]:
        """Collect system information."""
        info = {}
        
        try:
            # System information
            self._save_command_output('uname -a', 'system_uname.txt')
            self._save_command_output('cat /etc/*-release', 'system_os.txt')
            self._save_command_output('uptime', 'system_uptime.txt')
            
            # CPU and memory info
            self._save_command_output('cat /proc/cpuinfo', 'system_cpuinfo.txt')
            self._save_command_output('cat /proc/meminfo', 'system_meminfo.txt')
            self._save_command_output('free -m', 'system_memory.txt')
            
            # Mounted filesystems
            self._save_command_output('mount', 'system_mounts.txt')
            self._save_command_output('df -h', 'system_disk_usage.txt')
            
            # Network configuration
            self._save_command_output('ifconfig -a', 'network_ifconfig.txt')
            self._save_command_output('ip addr', 'network_ip_addr.txt')
            self._save_command_output('netstat -tulnpe', 'network_connections.txt')
            self._save_command_output('arp -an', 'network_arp.txt')
            self._save_command_output('route -n', 'network_routes.txt')
            
            # Running processes
            self._save_command_output('ps aux', 'processes.txt')
            self._save_command_output('lsof -i', 'network_lsof.txt')
            
            # Services
            if os.path.exists('/etc/init.d'):
                self._save_command_output('ls -la /etc/init.d/', 'services_initd.txt')
            
            # User accounts
            self._save_command_output('cat /etc/passwd', 'users_passwd.txt')
            self._save_command_output('cat /etc/group', 'users_groups.txt')
            self._save_command_output('last', 'users_last_logins.txt')
            self._save_command_output('who -a', 'users_currently_logged_in.txt')
            
            # Scheduled tasks
            self._save_command_output('crontab -l', 'cron_root.txt')
            self._save_command_output('ls -la /etc/cron*', 'cron_directories.txt')
            
            # System logs
            for log_file in ['/var/log/syslog', '/var/log/messages', '/var/log/auth.log']:
                if os.path.exists(log_file):
                    try:
                        self._copy_file(log_file, f"logs/{os.path.basename(log_file)}")
                    except Exception as e:
                        logger.warning(f"Could not copy log file {log_file}: {e}")
            
            # Important files
            try:
                self._copy_file('/etc/hosts')
                self._copy_file('/etc/resolv.conf')
                self._copy_file('/etc/ssh/sshd_config')
            except Exception as e:
                logger.warning(f"Could not copy important files: {e}")
            
            return info
            
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            raise
    
    def collect_memory_dump(self) -> Dict[str, Any]:
        """Create a memory dump (requires root privileges)."""
        try:
            # Check if we're root
            if os.geteuid() != 0:
                return {'status': 'skipped', 'reason': 'Root privileges required'}
            
            # In a real implementation, you would use a tool like LiME or AVML here
            # For example: os.system(f'./limet-{uname -r}.ko "path={output_file} format=lime"')
            
            return {
                'status': 'not_implemented',
                'message': 'Memory dump collection is not implemented in this version'
            }
            
        except Exception as e:
            logger.error(f"Error collecting memory dump: {e}")
            raise


def create_forensic_collector(output_dir: str, system_type: Optional[str] = None, **kwargs) -> CollectorBase:
    """Create an appropriate forensic collector for the current system.
    
    Args:
        output_dir: Directory to store collected data
        system_type: Optional override for system type ('windows' or 'linux')
        **kwargs: Additional arguments to pass to the collector
        
    Returns:
        An instance of a forensic collector
    """
    if system_type is None:
        system_type = platform.system().lower()
    
    if 'windows' in system_type:
        return WindowsForensicCollector(output_dir, **kwargs)
    elif 'linux' in system_type:
        return LinuxForensicCollector(output_dir, **kwargs)
    else:
        raise NotImplementedError(f"Unsupported system type: {system_type}")


def collect_forensic_data(
    output_dir: str,
    collectors: Optional[List[str]] = None,
    system_type: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """Collect forensic data from the system.
    
    Args:
        output_dir: Directory to store collected data
        collectors: List of collector names to run (None for all)
        system_type: Optional override for system type
        **kwargs: Additional arguments to pass to the collector
        
    Returns:
        Dictionary with collection results
    """
    collector = create_forensic_collector(output_dir, system_type, **kwargs)
    
    # If specific collectors are specified, only run those
    if collectors:
        # Create a new collector that only runs the specified methods
        class SelectiveCollector(collector.__class__):
            def collect(self):
                try:
                    logger.info(f"Starting selective forensic collection: {self.collection_id}")
                    
                    for collector_name in collectors:
                        method_name = f"collect_{collector_name}"
                        if not hasattr(self, method_name):
                            logger.warning(f"No such collector: {collector_name}")
                            continue
                            
                        try:
                            logger.info(f"Running collector: {collector_name}")
                            
                            start_time = time.time()
                            result = getattr(self, method_name)()
                            duration = time.time() - start_time
                            
                            self.metadata['collectors'].append({
                                'name': collector_name,
                                'status': 'completed',
                                'duration_seconds': round(duration, 2),
                                'result': result or {}
                            })
                            
                        except Exception as e:
                            logger.error(f"Error in collector {collector_name}: {e}", exc_info=True)
                            self.metadata['collectors'].append({
                                'name': collector_name,
                                'status': 'failed',
                                'error': str(e)
                            })
                    
                    # Save metadata
                    self._save_metadata()
                    
                    # Package the collection if requested
                    output_path = self._package_collection()
                    
                    # Clean up temporary files
                    self._cleanup()
                    
                    return {
                        'status': 'completed',
                        'collection_id': self.collection_id,
                        'output_path': str(output_path),
                        'metadata': self.metadata
                    }
                    
                except Exception as e:
                    logger.error(f"Forensic collection failed: {e}", exc_info=True)
                    self.metadata['status'] = 'failed'
                    self.metadata['error'] = str(e)
                    self._save_metadata()
                    
                    return {
                        'status': 'failed',
                        'collection_id': self.collection_id,
                        'error': str(e),
                        'metadata': self.metadata
                    }
        
        # Create an instance of the selective collector
        collector = SelectiveCollector(output_dir, **kwargs)
    
    # Run the collection
    return collector.collect()
