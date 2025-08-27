"""
Network Flow Model

Defines the structure for network flow data used in analysis.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, Any, Optional, List, Tuple
import json

class FlowDirection(Enum):
    """Direction of network traffic flow."""
    INBOUND = auto()    # Traffic coming into the network
    OUTBOUND = auto()   # Traffic going out of the network
    INTERNAL = auto()   # Traffic within the network
    EXTERNAL = auto()   # Traffic between internal and external networks

class Protocol(Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMPv6 = "icmpv6"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    DHCP = "dhcp"
    TLS = "tls"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    OTHER = "other"

@dataclass
class NetworkFlow:
    """
    Represents a network traffic flow with metadata and statistics.
    
    Attributes:
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port (if applicable)
        dst_port: Destination port (if applicable)
        protocol: Network protocol
        bytes_sent: Number of bytes sent
        bytes_received: Number of bytes received
        packets_sent: Number of packets sent
        packets_received: Number of packets received
        start_time: When the flow started
        end_time: When the flow ended
        direction: Flow direction (INBOUND, OUTBOUND, INTERNAL, EXTERNAL)
        metadata: Additional flow metadata
        tags: List of tags for categorization
    """
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    direction: FlowDirection = FlowDirection.EXTERNAL
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        """Get the duration of the flow in seconds."""
        end = self.end_time or datetime.utcnow()
        return (end - self.start_time).total_seconds()
    
    @property
    def total_bytes(self) -> int:
        """Get the total number of bytes transferred."""
        return self.bytes_sent + self.bytes_received
    
    @property
    def total_packets(self) -> int:
        """Get the total number of packets transferred."""
        return self.packets_sent + self.packets_received
    
    @property
    def bytes_per_second(self) -> float:
        """Get the average bytes per second."""
        duration = self.duration
        return self.total_bytes / duration if duration > 0 else 0.0
    
    @property
    def packets_per_second(self) -> float:
        """Get the average packets per second."""
        duration = self.duration
        return self.total_packets / duration if duration > 0 else 0.0
    
    def is_internal(self) -> bool:
        """Check if the flow is between internal IP addresses."""
        return self._is_private_ip(self.src_ip) and self._is_private_ip(self.dst_ip)
    
    def is_external(self) -> bool:
        """Check if the flow is between an internal and external IP."""
        return self._is_private_ip(self.src_ip) != self._is_private_ip(self.dst_ip)
    
    def update_direction(self, local_networks: Optional[List[str]] = None) -> None:
        """
        Update the flow direction based on source and destination IPs.
        
        Args:
            local_networks: List of local network CIDRs (e.g., ['192.168.1.0/24'])
        """
        src_private = self._is_private_ip(self.src_ip, local_networks)
        dst_private = self._is_private_ip(self.dst_ip, local_networks)
        
        if src_private and dst_private:
            self.direction = FlowDirection.INTERNAL
        elif src_private and not dst_private:
            self.direction = FlowDirection.OUTBOUND
        elif not src_private and dst_private:
            self.direction = FlowDirection.INBOUND
        else:
            self.direction = FlowDirection.EXTERNAL
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the flow to a dictionary for serialization."""
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'direction': self.direction.name,
            'metadata': self.metadata,
            'tags': self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetworkFlow':
        """Create a flow from a dictionary."""
        return cls(
            src_ip=data['src_ip'],
            dst_ip=data['dst_ip'],
            src_port=data.get('src_port'),
            dst_port=data.get('dst_port'),
            protocol=data.get('protocol', 'tcp'),
            bytes_sent=data.get('bytes_sent', 0),
            bytes_received=data.get('bytes_received', 0),
            packets_sent=data.get('packets_sent', 0),
            packets_received=data.get('packets_received', 0),
            start_time=datetime.fromisoformat(data['start_time']) if isinstance(data['start_time'], str) else data['start_time'],
            end_time=datetime.fromisoformat(data['end_time']) if data.get('end_time') else None,
            direction=FlowDirection[data.get('direction', 'EXTERNAL')],
            metadata=data.get('metadata', {}),
            tags=data.get('tags', [])
        )
    
    def to_json(self) -> str:
        """Convert the flow to a JSON string."""
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'NetworkFlow':
        """Create a flow from a JSON string."""
        return cls.from_dict(json.loads(json_str))
    
    def __str__(self) -> str:
        """String representation of the flow."""
        return (f"{self.src_ip}:{self.src_port or '*'}' -> '{self.dst_ip}:{self.dst_port or '*'} "
                f"{self.protocol.upper()} "
                f"{self.bytes_sent + self.bytes_received} bytes, "
                f"{self.packets_sent + self.packets_received} pkts, "
                f"{self.duration:.2f}s")
    
    @staticmethod
    def _is_private_ip(ip: str, networks: Optional[List[str]] = None) -> bool:
        """
        Check if an IP address is in a private network range.
        
        Args:
            ip: IP address to check
            networks: Optional list of network CIDRs to check against
            
        Returns:
            bool: True if the IP is in a private network range
        """
        if not ip:
            return False
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check against provided networks if any
            if networks:
                for net in networks:
                    if ip_obj in ipaddress.ip_network(net, strict=False):
                        return True
            
            # Check standard private ranges
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            
        except ValueError:
            return False
