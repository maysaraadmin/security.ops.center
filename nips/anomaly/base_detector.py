"""
Base Anomaly Detection Engine for NIPS
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
import numpy as np
from datetime import datetime, timedelta
import json
import hashlib
import time

class AnomalyType(Enum):
    """Types of anomalies that can be detected."""
    TRAFFIC_SPIKE = "traffic_spike"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    UNUSUAL_PROTOCOL = "unusual_protocol"
    RARE_EVENT = "rare_event"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"

@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    anomaly_type: AnomalyType
    score: float  # 0.0 to 1.0, higher means more severe
    description: str
    timestamp: float
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'anomaly_type': self.anomaly_type.value,
            'score': self.score,
            'description': self.description,
            'timestamp': self.timestamp,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'protocol': self.protocol,
            'port': self.port,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Anomaly':
        """Create an Anomaly from a dictionary."""
        return cls(
            anomaly_type=AnomalyType(data['anomaly_type']),
            score=data['score'],
            description=data['description'],
            timestamp=data['timestamp'],
            source_ip=data.get('source_ip'),
            dest_ip=data.get('dest_ip'),
            protocol=data.get('protocol'),
            port=data.get('port'),
            metadata=data.get('metadata', {})
        )

class BaseDetector(ABC):
    """Base class for all anomaly detectors."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the detector with configuration."""
        self.config = config or {}
        self.anomalies: List[Anomaly] = []
        self._initialize()
    
    @abstractmethod
    def _initialize(self):
        """Initialize the detector's internal state."""
        pass
    
    @abstractmethod
    def analyze(self, data: Dict[str, Any]) -> List[Anomaly]:
        """
        Analyze network data for anomalies.
        
        Args:
            data: Dictionary containing network event data
            
        Returns:
            List of detected anomalies
        """
        pass
    
    def get_anomalies(self, since: Optional[float] = None) -> List[Anomaly]:
        """
        Get all anomalies detected since the specified timestamp.
        
        Args:
            since: Unix timestamp. If None, return all anomalies.
            
        Returns:
            List of anomalies
        """
        if since is None:
            return self.anomalies.copy()
        return [a for a in self.anomalies if a.timestamp >= since]
    
    def clear_anomalies(self, before: Optional[float] = None):
        """
        Clear anomalies from memory.
        
        Args:
            before: If specified, only clear anomalies before this timestamp.
        """
        if before is None:
            self.anomalies.clear()
        else:
            self.anomalies = [a for a in self.anomalies if a.timestamp >= before]
    
    def _add_anomaly(self, 
                    anomaly_type: AnomalyType,
                    score: float,
                    description: str,
                    source_ip: Optional[str] = None,
                    dest_ip: Optional[str] = None,
                    protocol: Optional[str] = None,
                    port: Optional[int] = None,
                    metadata: Optional[Dict[str, Any]] = None) -> Anomaly:
        """
        Add a new anomaly to the list.
        
        Args:
            anomaly_type: Type of anomaly
            score: Anomaly score (0.0 to 1.0)
            description: Human-readable description
            source_ip: Source IP address
            dest_ip: Destination IP address
            protocol: Network protocol
            port: Port number
            metadata: Additional metadata
            
        Returns:
            The created Anomaly object
        """
        # Ensure score is within bounds
        score = max(0.0, min(1.0, score))
        
        anomaly = Anomaly(
            anomaly_type=anomaly_type,
            score=score,
            description=description,
            timestamp=time.time(),
            source_ip=source_ip,
            dest_ip=dest_ip,
            protocol=protocol,
            port=port,
            metadata=metadata or {}
        )
        
        self.anomalies.append(anomaly)
        return anomaly

class TrafficAnalyzer(BaseDetector):
    """Analyzes network traffic for anomalies."""
    
    def _initialize(self):
        """Initialize traffic analysis parameters."""
        # Time window for analysis in seconds
        self.window_size = self.config.get('window_size', 300)  # 5 minutes
        
        # Thresholds for different anomaly types
        self.thresholds = {
            'packet_rate': self.config.get('packet_rate_threshold', 1000),  # packets/sec
            'connection_rate': self.config.get('connection_rate_threshold', 100),  # connections/sec
            'data_volume': self.config.get('data_volume_threshold', 10 * 1024 * 1024),  # 10 MB
            'unique_ports': self.config.get('unique_ports_threshold', 100),  # unique ports
            'unique_ips': self.config.get('unique_ips_threshold', 100),  # unique IPs
        }
        
        # Data structures for sliding window analysis
        self.packets: List[Tuple[float, Dict[str, Any]]] = []
        self.connections: Dict[Tuple[str, str, int, int, str], int] = {}  # (src_ip, dst_ip, src_port, dst_port, protocol) -> count
        self.ip_stats: Dict[str, Dict[str, int]] = {}  # ip -> {'packets': count, 'bytes': total_bytes}
        self.port_stats: Dict[int, Dict[str, int]] = {}  # port -> {'packets': count, 'bytes': total_bytes}
        
        # Behavioral baselines
        self.baselines = {
            'packet_rate': self.thresholds['packet_rate'] / 2,  # Start with half the threshold
            'connection_rate': self.thresholds['connection_rate'] / 2,
            'data_volume': self.thresholds['data_volume'] / 2,
        }
        
        # Learning rate for adaptive thresholds (0.0 to 1.0)
        self.learning_rate = self.config.get('learning_rate', 0.1)
    
    def analyze(self, data: Dict[str, Any]) -> List[Anomaly]:
        """
        Analyze network traffic data for anomalies.
        
        Args:
            data: Dictionary containing network traffic data
            
        Returns:
            List of detected anomalies
        """
        anomalies: List[Anomaly] = []
        current_time = time.time()
        
        # Add packet to window
        self.packets.append((current_time, data))
        
        # Update connection stats
        conn_key = (
            data.get('src_ip', ''),
            data.get('dst_ip', ''),
            data.get('src_port', 0),
            data.get('dst_port', 0),
            data.get('protocol', '').lower()
        )
        self.connections[conn_key] = self.connections.get(conn_key, 0) + 1
        
        # Update IP stats
        src_ip = data.get('src_ip')
        dst_ip = data.get('dst_ip')
        packet_size = data.get('length', 0)
        
        for ip in [src_ip, dst_ip]:
            if not ip:
                continue
            if ip not in self.ip_stats:
                self.ip_stats[ip] = {'packets': 0, 'bytes': 0}
            self.ip_stats[ip]['packets'] += 1
            self.ip_stats[ip]['bytes'] += packet_size
        
        # Update port stats
        dst_port = data.get('dst_port')
        if dst_port is not None:
            if dst_port not in self.port_stats:
                self.port_stats[dst_port] = {'packets': 0, 'bytes': 0}
            self.port_stats[dst_port]['packets'] += 1
            self.port_stats[dst_port]['bytes'] += packet_size
        
        # Remove old packets from the window
        cutoff_time = current_time - self.window_size
        while self.packets and self.packets[0][0] < cutoff_time:
            old_time, old_data = self.packets.pop(0)
            
            # Update connection stats
            old_conn_key = (
                old_data.get('src_ip', ''),
                old_data.get('dst_ip', ''),
                old_data.get('src_port', 0),
                old_data.get('dst_port', 0),
                old_data.get('protocol', '').lower()
            )
            if old_conn_key in self.connections:
                self.connections[old_conn_key] -= 1
                if self.connections[old_conn_key] <= 0:
                    del self.connections[old_conn_key]
            
            # Update IP stats
            old_src_ip = old_data.get('src_ip')
            old_dst_ip = old_data.get('dst_ip')
            old_packet_size = old_data.get('length', 0)
            
            for ip in [old_src_ip, old_dst_ip]:
                if not ip or ip not in self.ip_stats:
                    continue
                self.ip_stats[ip]['packets'] -= 1
                self.ip_stats[ip]['bytes'] -= old_packet_size
                if self.ip_stats[ip]['packets'] <= 0:
                    del self.ip_stats[ip]
            
            # Update port stats
            old_dst_port = old_data.get('dst_port')
            if old_dst_port is not None and old_dst_port in self.port_stats:
                self.port_stats[old_dst_port]['packets'] -= 1
                self.port_stats[old_dst_port]['bytes'] -= old_packet_size
                if self.port_stats[old_dst_port]['packets'] <= 0:
                    del self.port_stats[old_dst_port]
        
        # Calculate current rates
        if self.packets:
            time_span = current_time - self.packets[0][0]
            if time_span > 0:
                packet_rate = len(self.packets) / time_span  # packets per second
                connection_rate = len(self.connections) / time_span  # connections per second
                data_volume = sum(p[1].get('length', 0) for p in self.packets)  # total bytes in window
                
                # Update baselines
                self._update_baseline('packet_rate', packet_rate)
                self._update_baseline('connection_rate', connection_rate)
                self._update_baseline('data_volume', data_volume / time_span)  # bytes per second
                
                # Check for anomalies
                anomalies.extend(self._check_traffic_anomalies(
                    packet_rate=packet_rate,
                    connection_rate=connection_rate,
                    data_volume=data_volume,
                    time_span=time_span
                ))
        
        # Check for port scanning
        if src_ip and dst_ip:
            anomalies.extend(self._check_port_scan(src_ip, dst_ip))
        
        # Check for data exfiltration
        if src_ip and packet_size > 0:
            anomalies.extend(self._check_data_exfiltration(src_ip, packet_size))
        
        return anomalies
    
    def _update_baseline(self, metric: str, current_value: float):
        """Update the baseline for a metric using exponential moving average."""
        if metric in self.baselines:
            self.baselines[metric] = (
                (1 - self.learning_rate) * self.baselines[metric] +
                self.learning_rate * current_value
            )
    
    def _check_traffic_anomalies(self, 
                               packet_rate: float, 
                               connection_rate: float, 
                               data_volume: int,
                               time_span: float) -> List[Anomaly]:
        """Check for traffic anomalies based on current rates."""
        anomalies = []
        
        # Check for traffic spikes
        if packet_rate > self.thresholds['packet_rate']:
            deviation = (packet_rate - self.baselines['packet_rate']) / max(1, self.baselines['packet_rate'])
            score = min(1.0, 0.5 + deviation / 2.0)  # Scale to 0.5-1.0 range
            
            anomalies.append(self._add_anomaly(
                anomaly_type=AnomalyType.TRAFFIC_SPIKE,
                score=score,
                description=f"High packet rate detected: {packet_rate:.1f} packets/sec",
                protocol='any',
                metadata={
                    'packet_rate': packet_rate,
                    'baseline': self.baselines['packet_rate'],
                    'threshold': self.thresholds['packet_rate']
                }
            ))
        
        # Check for connection floods
        if connection_rate > self.thresholds['connection_rate']:
            deviation = (connection_rate - self.baselines['connection_rate']) / max(1, self.baselines['connection_rate'])
            score = min(1.0, 0.5 + deviation / 2.0)
            
            anomalies.append(self._add_anomaly(
                anomaly_type=AnomalyType.BRUTE_FORCE,
                score=score,
                description=f"High connection rate detected: {connection_rate:.1f} connections/sec",
                protocol='any',
                metadata={
                    'connection_rate': connection_rate,
                    'baseline': self.baselines['connection_rate'],
                    'threshold': self.thresholds['connection_rate']
                }
            ))
        
        # Check for data exfiltration (high data volume from a single host)
        data_rate = data_volume / time_span if time_span > 0 else 0
        if data_rate > self.thresholds['data_volume']:
            deviation = (data_rate - self.baselines['data_volume']) / max(1, self.baselines['data_volume'])
            score = min(1.0, 0.5 + deviation / 2.0)
            
            anomalies.append(self._add_anomaly(
                anomaly_type=AnomalyType.DATA_EXFILTRATION,
                score=score,
                description=f"High data volume detected: {data_rate/1024/1024:.2f} MB/s",
                protocol='any',
                metadata={
                    'data_rate': data_rate,
                    'data_volume': data_volume,
                    'baseline': self.baselines['data_volume'],
                    'threshold': self.thresholds['data_volume']
                }
            ))
        
        return anomalies
    
    def _check_port_scan(self, src_ip: str, dst_ip: str) -> List[Anomaly]:
        """Check for port scanning activity."""
        anomalies = []
        
        # Count unique destination ports for this source IP
        unique_ports = set()
        for conn in self.connections:
            if conn[0] == src_ip:  # conn[0] is source IP
                unique_ports.add(conn[3])  # conn[3] is destination port
        
        if len(unique_ports) > self.thresholds['unique_ports']:
            anomalies.append(self._add_anomaly(
                anomaly_type=AnomalyType.PORT_SCAN,
                score=0.8,  # High confidence
                description=f"Port scan detected from {src_ip} to {dst_ip} ({len(unique_ports)} unique ports)",
                source_ip=src_ip,
                dest_ip=dst_ip,
                protocol='tcp',  # Most port scans use TCP
                metadata={
                    'unique_ports': len(unique_ports),
                    'ports': list(unique_ports)[:100],  # Include first 100 ports in metadata
                    'threshold': self.thresholds['unique_ports']
                }
            ))
        
        return anomalies
    
    def _check_data_exfiltration(self, src_ip: str, packet_size: int) -> List[Anomaly]:
        """Check for potential data exfiltration."""
        anomalies = []
        
        if src_ip in self.ip_stats:
            ip_data = self.ip_stats[src_ip]
            
            # Check for large data transfers to external IPs
            if ip_data['bytes'] > self.thresholds['data_volume']:
                anomalies.append(self._add_anomaly(
                    anomaly_type=AnomalyType.DATA_EXFILTRATION,
                    score=0.7,  # Medium-high confidence
                    description=f"Potential data exfiltration from {src_ip} ({ip_data['bytes']/1024/1024:.2f} MB)",
                    source_ip=src_ip,
                    protocol='any',
                    metadata={
                        'bytes_transferred': ip_data['bytes'],
                        'packet_count': ip_data['packets'],
                        'threshold': self.thresholds['data_volume']
                    }
                ))
        
        return anomalies

class AnomalyDetector:
    """Main anomaly detection engine that coordinates multiple detectors."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the anomaly detector with configuration."""
        self.config = config or {}
        self.detectors: Dict[str, BaseDetector] = {}
        self._initialize_detectors()
    
    def _initialize_detectors(self):
        """Initialize all configured anomaly detectors."""
        # Traffic analyzer for network-level anomalies
        traffic_config = self.config.get('traffic_analyzer', {})
        self.detectors['traffic'] = TrafficAnalyzer(traffic_config)
        
        # Add more detectors here as needed
        # Example: self.detectors['dns'] = DNSAnomalyDetector(self.config.get('dns_analyzer', {}))
    
    def analyze(self, data: Dict[str, Any]) -> List[Anomaly]:
        """
        Analyze network data using all configured detectors.
        
        Args:
            data: Dictionary containing network event data
            
        Returns:
            List of all detected anomalies
        """
        anomalies = []
        
        for detector_name, detector in self.detectors.items():
            try:
                detector_anomalies = detector.analyze(data)
                anomalies.extend(detector_anomalies)
            except Exception as e:
                # Log the error but continue with other detectors
                print(f"Error in {detector_name} detector: {e}")
        
        return anomalies
    
    def get_anomalies(self, since: Optional[float] = None) -> List[Anomaly]:
        """
        Get all anomalies from all detectors.
        
        Args:
            since: Unix timestamp. If None, return all anomalies.
            
        Returns:
            List of all anomalies
        """
        all_anomalies = []
        for detector in self.detectors.values():
            all_anomalies.extend(detector.get_anomalies(since=since))
        
        # Sort by timestamp (newest first)
        all_anomalies.sort(key=lambda x: x.timestamp, reverse=True)
        return all_anomalies
    
    def clear_anomalies(self, before: Optional[float] = None):
        """
        Clear anomalies from all detectors.
        
        Args:
            before: If specified, only clear anomalies before this timestamp.
        """
        for detector in self.detectors.values():
            detector.clear_anomalies(before=before)
