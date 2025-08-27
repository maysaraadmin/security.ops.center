"""
Forensic Data Collection for EDR.
Collects and preserves forensic evidence from endpoints.
"""
import os
import json
import hashlib
import logging
import platform
import tempfile
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Callable, Union
from enum import Enum
import subprocess
import glob
import stat
import gzip
import io

from ..monitoring.base_monitor import BaseMonitor
from .timeline import TimelineEvent, EventType
from .storage import get_storage_backend

class EvidenceType(str, Enum):
    """Types of forensic evidence that can be collected."""
    MEMORY = 'memory'
    DISK = 'disk'
    NETWORK = 'network'
    PROCESS = 'process'
    FILE = 'file'
    REGISTRY = 'registry'
    LOG = 'log'
    CONFIG = 'config'
    BROWSER = 'browser'
    PREFETCH = 'prefetch'
    SCHEDULED_TASKS = 'scheduled_tasks'
    SERVICES = 'services'
    DRIVERS = 'drivers'
    USER_ACTIVITY = 'user_activity'
    SYSTEM_INFO = 'system_info'

class Evidence:
    """Represents a piece of forensic evidence."""
    
    def __init__(
        self,
        evidence_type: EvidenceType,
        source: str,
        data: Any,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None
    ):
        """Initialize forensic evidence."""
        self.evidence_id = self._generate_id()
        self.evidence_type = evidence_type
        self.source = source
        self.data = data
        self.metadata = metadata or {}
        self.timestamp = timestamp or datetime.utcnow()
        self.tags = []
        
        # Add system information
        self.metadata.update({
            'collected_at': self.timestamp.isoformat() + 'Z',
            'system': {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'machine': platform.machine(),
                'node': platform.node(),
                'processor': platform.processor()
            }
        })
    
    def _generate_id(self) -> str:
        """Generate a unique ID for this evidence."""
        unique_str = f"{datetime.utcnow().isoformat()}-{os.urandom(16).hex()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to this evidence."""
        if tag not in self.tags:
            self.tags.append(tag)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence to dictionary."""
        return {
            'evidence_id': self.evidence_id,
            'evidence_type': self.evidence_type.value,
            'source': self.source,
            'data': self.data if not isinstance(self.data, (bytes, bytearray)) else "<binary data>",
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat() + 'Z',
            'tags': self.tags
        }
    
    def to_json(self) -> str:
        """Convert evidence to JSON string."""
        return json.dumps(self.to_dict(), default=str)
    
    def save_to_file(self, file_path: str) -> bool:
        """Save evidence to a file."""
        try:
            with open(file_path, 'w') as f:
                json.dump(self.to_dict(), f, indent=2, default=str)
            return True
        except Exception as e:
            logging.error(f"Failed to save evidence to {file_path}: {e}")
            return False

class ForensicsCollector:
    """Base class for forensic data collectors."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the forensic collector."""
        self.config = config
        self.logger = logging.getLogger(f"edr.forensics.collector.{self.__class__.__name__}")
        self.evidence: List[Evidence] = []
        
        # Initialize storage backend
        storage_config = config.get('storage', {'type': 'filesystem'})
        self.storage = get_storage_backend(
            storage_config.get('type', 'filesystem'),
            storage_config.get('config', {})
        )
    
    def collect(self) -> List[Evidence]:
        """Collect forensic evidence."""
        raise NotImplementedError
    
    def save_evidence(self, evidence: Evidence) -> bool:
        """Save evidence to storage."""
        try:
            # Add to in-memory collection
            self.evidence.append(evidence)
            
            # Save to storage
            if hasattr(self.storage, 'store_evidence'):
                return self.storage.store_evidence(evidence)
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to save evidence: {e}")
            return False
    
    def get_evidence_by_type(self, evidence_type: Union[str, EvidenceType]) -> List[Evidence]:
        """Get collected evidence by type."""
        if isinstance(evidence_type, str):
            evidence_type = EvidenceType(evidence_type)
        return [e for e in self.evidence if e.evidence_type == evidence_type]
    
    def get_evidence_by_id(self, evidence_id: str) -> Optional[Evidence]:
        """Get evidence by ID."""
        for e in self.evidence:
            if e.evidence_id == evidence_id:
                return e
        return None

class ProcessCollector(ForensicsCollector):
    """Collects information about running processes."""
    
    def collect(self) -> List[Evidence]:
        """Collect information about running processes."""
        self.logger.info("Collecting process information...")
        
        try:
            import psutil
            
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
                try:
                    process_info = proc.info
                    processes.append({
                        'pid': process_info['pid'],
                        'name': process_info['name'],
                        'username': process_info['username'],
                        'command_line': ' '.join(process_info['cmdline']) if process_info['cmdline'] else '',
                        'create_time': datetime.fromtimestamp(process_info['create_time']).isoformat(),
                        'executable': proc.exe(),
                        'status': proc.status(),
                        'cpu_percent': proc.cpu_percent(),
                        'memory_percent': proc.memory_percent(),
                        'open_files': [f.path for f in proc.open_files()],
                        'connections': [
                            {
                                'family': conn.family.name,
                                'type': conn.type.name,
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if hasattr(conn, 'raddr') and conn.raddr else None,
                                'status': conn.status
                            }
                            for conn in proc.connections()
                        ] if proc.connections() else []
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    self.logger.debug(f"Skipping process {proc.pid}: {e}")
            
            evidence = Evidence(
                evidence_type=EvidenceType.PROCESS,
                source='psutil',
                data=processes,
                metadata={
                    'process_count': len(processes),
                    'collection_method': 'psutil'
                }
            )
            
            self.save_evidence(evidence)
            return [evidence]
            
        except ImportError:
            self.logger.error("psutil module not installed. Install with: pip install psutil")
            return []

class FileCollector(ForensicsCollector):
    """Collects file system evidence."""
    
    def collect(
        self, 
        paths: Optional[List[str]] = None, 
        file_patterns: Optional[List[str]] = None,
        max_size_mb: int = 10
    ) -> List[Evidence]:
        """
        Collect file system evidence.
        
        Args:
            paths: List of paths to collect (default: common system paths)
            file_patterns: List of file patterns to include (e.g., ['*.exe', '*.dll'])
            max_size_mb: Maximum file size to collect in MB
        """
        self.logger.info("Collecting file system evidence...")
        
        if not paths:
            # Default paths to collect
            paths = [
                '/tmp',
                '/var/log',
                '/etc',
                '/usr/bin',
                '/usr/sbin',
                '/bin',
                '/sbin',
                '/opt',
                '/root',
                '/home'
            ]
            
            # Add Windows paths if on Windows
            if os.name == 'nt':
                paths.extend([
                    'C:\\Windows\\System32',
                    'C:\\Windows\\SysWOW64',
                    'C:\\Windows\\Temp',
                    'C:\\Users',
                    'C:\\ProgramData',
                    'C:\\Windows\\Prefetch',
                    'C:\\Windows\\System32\\drivers',
                    'C:\\Windows\\System32\\winevt\\Logs'
                ])
        
        if not file_patterns:
            file_patterns = ['*']
        
        max_size_bytes = max_size_mb * 1024 * 1024
        collected_files = []
        
        for path in paths:
            if not os.path.exists(path):
                self.logger.debug(f"Path does not exist: {path}")
                continue
                
            for root, _, files in os.walk(path):
                for file_pattern in file_patterns:
                    for file_path in glob.glob(os.path.join(root, file_pattern)):
                        try:
                            # Skip directories and special files
                            if not os.path.isfile(file_path):
                                continue
                                
                            file_stat = os.stat(file_path)
                            
                            # Skip files that are too large
                            if file_stat.st_size > max_size_bytes:
                                self.logger.debug(f"Skipping large file: {file_path} ({file_stat.st_size} bytes)")
                                continue
                            
                            # Skip unreadable files
                            if not os.access(file_path, os.R_OK):
                                self.logger.debug(f"Skipping unreadable file: {file_path}")
                                continue
                            
                            # Calculate file hashes
                            file_hashes = self._calculate_file_hashes(file_path)
                            
                            # Get file metadata
                            file_meta = {
                                'path': file_path,
                                'size': file_stat.st_size,
                                'created': datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                                'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                                'accessed': datetime.fromtimestamp(file_stat.st_atime).isoformat(),
                                'mode': oct(stat.S_IMODE(file_stat.st_mode)),
                                'owner': file_stat.st_uid,
                                'group': file_stat.st_gid,
                                'hashes': file_hashes
                            }
                            
                            # Add to collected files
                            collected_files.append(file_meta)
                            
                        except Exception as e:
                            self.logger.error(f"Error processing file {file_path}: {e}")
        
        # Create evidence
        evidence = Evidence(
            evidence_type=EvidenceType.FILE,
            source='filesystem',
            data=collected_files,
            metadata={
                'file_count': len(collected_files),
                'max_size_mb': max_size_mb,
                'file_patterns': file_patterns,
                'paths_searched': paths
            }
        )
        
        self.save_evidence(evidence)
        return [evidence]
    
    def _calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate various hashes for a file."""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)
            
            return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
            
        except Exception as e:
            self.logger.error(f"Error calculating hashes for {file_path}: {e}")
            return {}

class RegistryCollector(ForensicsCollector):
    """Collects Windows Registry evidence."""
    
    def collect(self, hive_paths: Optional[List[str]] = None) -> List[Evidence]:
        """
        Collect Windows Registry evidence.
        
        Args:
            hive_paths: List of registry hive paths to collect
        """
        self.logger.info("Collecting Windows Registry evidence...")
        
        if os.name != 'nt':
            self.logger.warning("Registry collection is only supported on Windows")
            return []
        
        try:
            import winreg
        except ImportError:
            self.logger.error("winreg module not available. This collector only works on Windows.")
            return []
        
        if not hive_paths:
            # Default registry hives to collect
            hive_paths = [
                r"HKEY_LOCAL_MACHINE\\SOFTWARE",
                r"HKEY_LOCAL_MACHINE\\SYSTEM",
                r"HKEY_LOCAL_MACHINE\\SECURITY",
                r"HKEY_LOCAL_MACHINE\\SAM",
                r"HKEY_CURRENT_USER\\SOFTWARE",
                r"HKEY_USERS\\.DEFAULT"
            ]
        
        registry_data = {}
        
        for hive_path in hive_paths:
            try:
                # Parse the hive path
                hive_parts = hive_path.split('\\', 1)
                if len(hive_parts) != 2:
                    self.logger.warning(f"Invalid registry path format: {hive_path}")
                    continue
                
                hive_name, subkey_path = hive_parts
                
                # Map hive name to HKEY constant
                hive_map = {
                    'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                    'HKLM': winreg.HKEY_LOCAL_MACHINE,
                    'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                    'HKCU': winreg.HKEY_CURRENT_USER,
                    'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
                    'HKCR': winreg.HKEY_CLASSES_ROOT,
                    'HKEY_USERS': winreg.HKEY_USERS,
                    'HKU': winreg.HKEY_USERS,
                    'HKEY_CURRENT_CONFIG': winreg.HKEY_CURRENT_CONFIG,
                    'HKCC': winreg.HKEY_CURRENT_CONFIG
                }
                
                if hive_name.upper() not in hive_map:
                    self.logger.warning(f"Unsupported registry hive: {hive_name}")
                    continue
                
                hive = hive_map[hive_name.upper()]
                
                # Open the registry key
                try:
                    with winreg.ConnectRegistry(None, hive) as reg:
                        with winreg.OpenKey(reg, subkey_path) as key:
                            registry_data[hive_path] = self._read_registry_key(key)
                except WindowsError as e:
                    self.logger.error(f"Error accessing registry key {hive_path}: {e}")
            
            except Exception as e:
                self.logger.error(f"Error processing registry hive {hive_path}: {e}")
        
        # Create evidence
        evidence = Evidence(
            evidence_type=EvidenceType.REGISTRY,
            source='winreg',
            data=registry_data,
            metadata={
                'hives_collected': len(registry_data),
                'hives_requested': len(hive_paths)
            }
        )
        
        self.save_evidence(evidence)
        return [evidence]
    
    def _read_registry_key(self, key, depth: int = 0, max_depth: int = 10) -> Dict:
        """Recursively read a registry key and its subkeys."""
        if depth > max_depth:
            return {"error": "Maximum recursion depth exceeded"}
        
        result = {
            'values': {},
            'subkeys': {}
        }
        
        try:
            # Get all values
            i = 0
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, i)
                    result['values'][name] = {
                        'value': value,
                        'type': self._get_registry_value_type(value_type)
                    }
                    i += 1
                except OSError:
                    break
            
            # Get all subkeys
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        result['subkeys'][subkey_name] = self._read_registry_key(
                            subkey, depth + 1, max_depth
                        )
                    i += 1
                except OSError:
                    break
                    
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _get_registry_value_type(self, value_type: int) -> str:
        """Convert registry value type to string."""
        try:
            import winreg
            type_map = {
                winreg.REG_BINARY: 'REG_BINARY',
                winreg.REG_DWORD: 'REG_DWORD',
                winreg.REG_DWORD_LITTLE_ENDIAN: 'REG_DWORD_LITTLE_ENDIAN',
                winreg.REG_DWORD_BIG_ENDIAN: 'REG_DWORD_BIG_ENDIAN',
                winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
                winreg.REG_LINK: 'REG_LINK',
                winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
                winreg.REG_NONE: 'REG_NONE',
                winreg.REG_QWORD: 'REG_QWORD',
                winreg.REG_QWORD_LITTLE_ENDIAN: 'REG_QWORD_LITTLE_ENDIAN',
                winreg.REG_RESOURCE_LIST: 'REG_RESOURCE_LIST',
                winreg.REG_FULL_RESOURCE_DESCRIPTOR: 'REG_FULL_RESOURCE_DESCRIPTOR',
                winreg.REG_RESOURCE_REQUIREMENTS_LIST: 'REG_RESOURCE_REQUIREMENTS_LIST',
                winreg.REG_SZ: 'REG_SZ'
            }
            return type_map.get(value_type, f'UNKNOWN_TYPE_{value_type}')
        except Exception:
            return f'UNKNOWN_TYPE_{value_type}'
