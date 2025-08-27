"""
EDR Agent - Data models for the lightweight endpoint monitoring and response agent.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import platform
import socket
import psutil
import uuid

class Platform(Enum):
    """Supported operating system platforms."""
    WINDOWS = 'windows'
    LINUX = 'linux'
    MACOS = 'darwin'
    UNKNOWN = 'unknown'

    @classmethod
    def detect(cls) -> 'Platform':
        """Detect the current platform."""
        system = platform.system().lower()
        if system == 'windows':
            return cls.WINDOWS
        elif system == 'linux':
            return cls.LINUX
        elif system == 'darwin':
            return cls.MACOS
        return cls.UNKNOWN

@dataclass
class SystemInfo:
    """System information model."""
    hostname: str
    os_name: str
    os_version: str
    platform: Platform
    architecture: str
    cpu_cores: int
    total_memory: int  # in bytes
    boot_time: float
    interfaces: List[Dict[str, Any]]
    agent_version: str = "1.0.0"
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def collect(cls) -> 'SystemInfo':
        """Collect system information."""
        # Get network interfaces
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            interface = {
                'name': name,
                'addresses': [],
                'mac': None,
                'ipv4': [],
                'ipv6': []
            }
            
            for addr in addrs:
                addr_info = {
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast,
                    'ptp': addr.ptp
                }
                
                if addr.family == psutil.AF_LINK:
                    interface['mac'] = addr.address
                elif addr.family == socket.AF_INET:
                    interface['ipv4'].append(addr_info)
                elif addr.family == socket.AF_INET6:
                    interface['ipv6'].append(addr_info)
                
                interface['addresses'].append(addr_info)
            
            interfaces.append(interface)
        
        return cls(
            hostname=socket.gethostname(),
            os_name=platform.system(),
            os_version=platform.version(),
            platform=Platform.detect(),
            architecture=platform.machine(),
            cpu_cores=psutil.cpu_count(),
            total_memory=psutil.virtual_memory().total,
            boot_time=psutil.boot_time(),
            interfaces=interfaces
        )

@dataclass
class AgentConfig:
    """Agent configuration model."""
    agent_id: str
    server_url: str
    api_key: str
    checkin_interval: int = 300  # seconds
    max_cpu_percent: float = 10.0
    max_memory_mb: int = 100
    debug: bool = False
    collectors: List[str] = field(default_factory=lambda: [
        'process',
        'file_system',
        'network',
        'system_events'
    ])
    log_level: str = 'INFO'
    log_file: Optional[str] = None
    data_dir: str = '/var/lib/edr'
    proxy: Optional[str] = None
    verify_ssl: bool = True
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentConfig':
        """Create from dictionary."""
        return cls(**data)

@dataclass
class ProcessInfo:
    """Process information model."""
    pid: int
    name: str
    cmdline: List[str]
    username: str
    status: str
    create_time: float
    cpu_percent: float
    memory_percent: float
    num_threads: int
    exe: Optional[str] = None
    cwd: Optional[str] = None
    ppid: Optional[int] = None
    parent_name: Optional[str] = None
    children: List[Dict[str, Any]] = field(default_factory=list)
    connections: List[Dict[str, Any]] = field(default_factory=list)
    open_files: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FileInfo:
    """File system information model."""
    path: str
    size: int
    created: float
    modified: float
    accessed: float
    mode: int
    owner: str
    group: str
    inode: int
    device: int
    nlink: int
    uid: int
    gid: int
    is_dir: bool
    is_file: bool
    is_symlink: bool
    hash_md5: Optional[str] = None
    hash_sha1: Optional[str] = None
    hash_sha256: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

@dataclass
class NetworkConnection:
    """Network connection information model."""
    fd: int
    family: int
    type: int
    laddr: Dict[str, Any]
    raddr: Optional[Dict[str, Any]] = None
    status: Optional[str] = None
    pid: Optional[int] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Event:
    """Base event model."""
    event_type: str
    timestamp: float
    source: str
    data: Dict[str, Any]
    agent_id: str
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'event_type': self.event_type,
            'timestamp': self.timestamp,
            'source': self.source,
            'agent_id': self.agent_id,
            'tags': self.tags,
            'data': self.data,
            'extra': self.extra
        }
