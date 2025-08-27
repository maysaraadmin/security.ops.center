"""
Network Traffic Visibility Module

Provides comprehensive visibility into network traffic patterns, including:
- East-west (internal) traffic monitoring
- North-south (external) traffic analysis
- Traffic flow aggregation and analysis
- Protocol and application visibility
"""
import asyncio
import logging
import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Deque, Any, Callable
import json
from pathlib import Path

from .models.flow import NetworkFlow, FlowDirection
from .models.alert import NetworkAlert, AlertSeverity
from .utils.net_utils import is_private_ip, is_rfc1918, get_service_name

logger = logging.getLogger('ndr.traffic_visibility')

@dataclass
class TrafficStats:
    """Traffic statistics for a specific time window."""
    timestamp: datetime
    total_bytes: int = 0
    total_packets: int = 0
    total_flows: int = 0
    bytes_by_protocol: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    packets_by_protocol: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    top_talkers: Dict[Tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))  # (src, dst) -> bytes
    top_ports: Dict[int, int] = field(default_factory=lambda: defaultdict(int))  # port -> count

@dataclass
class TrafficVisibilityConfig:
    """Configuration for network traffic visibility."""
    # Time window for traffic statistics (seconds)
    stats_interval: int = 60
    
    # Retention period for historical data (seconds)
    history_retention: int = 3600  # 1 hour
    
    # Thresholds for traffic anomalies (percentage of baseline)
    traffic_spike_threshold: float = 2.0  # 200% of baseline
    traffic_drop_threshold: float = 0.5   # 50% of baseline
    
    # Baseline calculation window (days)
    baseline_window_days: int = 7
    
    # Path to store historical data
    data_dir: str = "data/ndr/traffic"
    
    # Enable/disable features
    enable_flow_analysis: bool = True
    enable_protocol_analysis: bool = True
    enable_traffic_baselining: bool = True
    
    # Internal networks (for east-west traffic detection)
    internal_networks: List[str] = field(default_factory=lambda: [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        'fc00::/7'  # ULA (RFC 4193)
    ])

class TrafficVisibilityEngine:
    """
    Provides comprehensive visibility into network traffic patterns.
    """
    
    def __init__(self, config: Optional[TrafficVisibilityConfig] = None):
        """Initialize the traffic visibility engine."""
        self.config = config or TrafficVisibilityConfig()
        self.active = False
        
        # Traffic statistics
        self.current_stats = TrafficStats(datetime.utcnow())
        self.historical_stats: Deque[TrafficStats] = deque(maxlen=1000)
        
        # Traffic baselines
        self.baselines: Dict[str, Dict[str, float]] = {
            'hourly': defaultdict(float),
            'daily': defaultdict(float)
        }
        
        # Traffic patterns
        self.traffic_patterns: Dict[str, Any] = {
            'protocol_distribution': {},
            'top_talkers': [],
            'top_ports': [],
            'traffic_trends': {}
        }
        
        # Callbacks
        self.alert_callbacks: List[Callable[[NetworkAlert], None]] = []
        self.stats_callbacks: List[Callable[[TrafficStats], None]] = []
        
        # Initialize data directory
        self.data_dir = Path(self.config.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Load historical data if available
        self._load_historical_data()
    
    async def start(self):
        """Start the traffic visibility engine."""
        if self.active:
            return
            
        self.active = True
        logger.info("Traffic visibility engine started")
        
        # Start periodic tasks
        asyncio.create_task(self._stats_aggregator())
        
        if self.config.enable_traffic_baselining:
            asyncio.create_task(self._update_baselines())
    
    async def stop(self):
        """Stop the traffic visibility engine."""
        self.active = False
        logger.info("Traffic visibility engine stopped")
        
        # Save current state
        self._save_historical_data()
    
    def register_alert_callback(self, callback: Callable[[NetworkAlert], None]):
        """Register a callback for traffic alerts."""
        self.alert_callbacks.append(callback)
    
    def register_stats_callback(self, callback: Callable[[TrafficStats], None]):
        """Register a callback for traffic statistics."""
        self.stats_callbacks.append(callback)
    
    async def process_flow(self, flow: NetworkFlow):
        """Process a network flow for traffic analysis."""
        if not self.active:
            return
            
        # Update current statistics
        self._update_traffic_stats(flow)
        
        # Analyze flow for anomalies
        if self.config.enable_flow_analysis:
            await self._analyze_flow(flow)
    
    def _update_traffic_stats(self, flow: NetworkFlow):
        """Update traffic statistics with a new flow."""
        now = datetime.utcnow()
        
        # Check if we need to rotate the stats window
        time_since_last = (now - self.current_stats.timestamp).total_seconds()
        if time_since_last >= self.config.stats_interval:
            self._rotate_stats(now)
        
        # Update statistics
        self.current_stats.total_bytes += flow.bytes_sent + flow.bytes_received
        self.current_stats.total_packets += flow.packets_sent + flow.packets_received
        self.current_stats.total_flows += 1
        
        # Update protocol distribution
        protocol = flow.protocol.upper() if flow.protocol else 'UNKNOWN'
        self.current_stats.bytes_by_protocol[protocol] += flow.bytes_sent + flow.bytes_received
        self.current_stats.packets_by_protocol[protocol] += flow.packets_sent + flow.packets_received
        
        # Update top talkers
        talker_key = (flow.src_ip, flow.dst_ip)
        self.current_stats.top_talkers[talker_key] += flow.bytes_sent + flow.bytes_received
        
        # Update top ports
        if flow.dst_port:
            self.current_stats.top_ports[flow.dst_port] += 1
        if flow.src_port and flow.src_port > 1024:  # Ignore ephemeral source ports
            self.current_stats.top_ports[flow.src_port] += 1
    
    def _rotate_stats(self, timestamp: datetime):
        """Rotate the current statistics to historical data."""
        # Finalize current stats
        self.current_stats.timestamp = timestamp
        
        # Add to historical data
        self.historical_stats.append(self.current_stats)
        
        # Notify subscribers
        for callback in self.stats_callbacks:
            try:
                callback(self.current_stats)
            except Exception as e:
                logger.error(f"Error in stats callback: {e}")
        
        # Start new stats window
        self.current_stats = TrafficStats(timestamp)
        
        # Clean up old data
        self._cleanup_old_data()
    
    async def _analyze_flow(self, flow: NetworkFlow):
        """Analyze a flow for anomalies and interesting patterns."""
        # Check for unusual traffic patterns
        self._check_traffic_anomalies(flow)
        
        # Check for suspicious ports
        self._check_suspicious_ports(flow)
        
        # Check for protocol anomalies
        if self.config.enable_protocol_analysis:
            self._check_protocol_anomalies(flow)
    
    def _check_traffic_anomalies(self, flow: NetworkFlow):
        """Check for traffic anomalies compared to baselines."""
        if not self.config.enable_traffic_baselining:
            return
            
        # TODO: Implement traffic anomaly detection against baselines
        # This would compare current traffic patterns to historical baselines
        # and generate alerts for significant deviations
        pass
    
    def _check_suspicious_ports(self, flow: NetworkFlow):
        """Check for traffic on suspicious or unusual ports."""
        if not flow.dst_port:
            return
            
        # Check for well-known suspicious ports
        suspicious_ports = {
            4444,  # Metasploit
            31337, # Back Orifice
            47120, # Windows Remote Desktop
            50050, # Kubernetes API - often targeted
            50051, # gRPC - often targeted
        }
        
        if flow.dst_port in suspicious_ports:
            self._generate_alert(
                title=f"Suspicious Port Activity",
                description=f"Traffic detected on known suspicious port {flow.dst_port} ({get_service_name(flow.dst_port, flow.protocol)})",
                severity=AlertSeverity.MEDIUM,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                metadata={
                    'port': flow.dst_port,
                    'service': get_service_name(flow.dst_port, flow.protocol),
                    'threat_type': 'suspicious_port_activity'
                }
            )
    
    def _check_protocol_anomalies(self, flow: NetworkFlow):
        """Check for protocol-level anomalies."""
        # Example: Detect HTTP on non-standard ports
        if flow.protocol.lower() == 'tcp' and flow.dst_port == 8080:
            self._generate_alert(
                title="HTTP on Non-Standard Port",
                description=f"HTTP traffic detected on non-standard port {flow.dst_port}",
                severity=AlertSeverity.LOW,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                metadata={
                    'port': flow.dst_port,
                    'protocol': flow.protocol,
                    'threat_type': 'non_standard_port_usage'
                }
            )
    
    async def _stats_aggregator(self):
        """Periodically aggregate and analyze traffic statistics."""
        while self.active:
            try:
                # Rotate stats at the configured interval
                now = datetime.utcnow()
                time_since_last = (now - self.current_stats.timestamp).total_seconds()
                
                if time_since_last >= self.config.stats_interval:
                    self._rotate_stats(now)
                
                # Sleep until next interval
                sleep_time = max(1, self.config.stats_interval - time_since_last)
                await asyncio.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Error in stats aggregator: {e}")
                await asyncio.sleep(1)
    
    async def _update_baselines(self):
        """Update traffic baselines based on historical data."""
        while self.active:
            try:
                # Update baselines every hour
                await asyncio.sleep(3600)
                
                # TODO: Implement baseline calculation
                # This would analyze historical data to establish normal traffic patterns
                
            except Exception as e:
                logger.error(f"Error updating baselines: {e}")
    
    def _cleanup_old_data(self):
        """Clean up old historical data beyond the retention period."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.config.history_retention)
        
        # Remove old stats
        while self.historical_stats and self.historical_stats[0].timestamp < cutoff:
            self.historical_stats.popleft()
    
    def _generate_alert(self, **kwargs):
        """Generate a traffic-related alert."""
        alert = NetworkAlert(**kwargs)
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def _load_historical_data(self):
        """Load historical traffic data from disk."""
        try:
            history_file = self.data_dir / 'traffic_history.json'
            if history_file.exists():
                with open(history_file, 'r') as f:
                    data = json.load(f)
                    # TODO: Load and deserialize historical data
        except Exception as e:
            logger.error(f"Error loading historical data: {e}")
    
    def _save_historical_data(self):
        """Save historical traffic data to disk."""
        try:
            history_file = self.data_dir / 'traffic_history.json'
            data = {
                'version': '1.0',
                'timestamp': datetime.utcnow().isoformat(),
                'historical_stats': [
                    {
                        'timestamp': stats.timestamp.isoformat(),
                        'total_bytes': stats.total_bytes,
                        'total_packets': stats.total_packets,
                        'total_flows': stats.total_flows,
                        'bytes_by_protocol': dict(stats.bytes_by_protocol),
                        'packets_by_protocol': dict(stats.packets_by_protocol),
                        'top_talkers': {f"{src}->{dst}": bytes for (src, dst), bytes in stats.top_talkers.items()},
                        'top_ports': dict(stats.top_ports)
                    }
                    for stats in self.historical_stats
                ]
            }
            
            with open(history_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving historical data: {e}")
    
    def get_traffic_summary(self, window_seconds: int = 300) -> Dict[str, Any]:
        """Get a summary of recent network traffic."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)
        
        summary = {
            'timestamp': now.isoformat(),
            'window_seconds': window_seconds,
            'total_bytes': 0,
            'total_packets': 0,
            'total_flows': 0,
            'bytes_by_protocol': defaultdict(int),
            'packets_by_protocol': defaultdict(int),
            'top_talkers': [],
            'top_ports': []
        }
        
        # Include current stats
        stats_list = list(self.historical_stats)
        if self.current_stats.total_flows > 0:
            stats_list.append(self.current_stats)
        
        # Aggregate data within the time window
        for stats in stats_list:
            if stats.timestamp >= cutoff:
                summary['total_bytes'] += stats.total_bytes
                summary['total_packets'] += stats.total_packets
                summary['total_flows'] += stats.total_flows
                
                for proto, bytes_count in stats.bytes_by_protocol.items():
                    summary['bytes_by_protocol'][proto] += bytes_count
                
                for proto, pkt_count in stats.packets_by_protocol.items():
                    summary['packets_by_protocol'][proto] += pkt_count
                
                # Track top talkers and ports (simplified)
                for (src, dst), bytes_count in stats.top_talkers.items():
                    summary['top_talkers'].append({
                        'source': src,
                        'destination': dst,
                        'bytes': bytes_count
                    })
                
                for port, count in stats.top_ports.items():
                    summary['top_ports'].append({
                        'port': port,
                        'service': get_service_name(port, 'tcp'),
                        'count': count
                    })
        
        # Sort and limit top talkers and ports
        summary['top_talkers'] = sorted(
            summary['top_talkers'],
            key=lambda x: x['bytes'],
            reverse=True
        )[:10]  # Top 10 talkers
        
        summary['top_ports'] = sorted(
            summary['top_ports'],
            key=lambda x: x['count'],
            reverse=True
        )[:10]  # Top 10 ports
        
        # Convert defaultdict to regular dict for JSON serialization
        summary['bytes_by_protocol'] = dict(summary['bytes_by_protocol'])
        summary['packets_by_protocol'] = dict(summary['packets_by_protocol'])
        
        return summary
    
    def get_flow_direction(self, flow: NetworkFlow) -> FlowDirection:
        """Determine if traffic is east-west or north-south."""
        src_internal = any(
            ipaddress.ip_address(flow.src_ip) in ipaddress.ip_network(net, strict=False)
            for net in self.config.internal_networks
        )
        
        dst_internal = any(
            ipaddress.ip_address(flow.dst_ip) in ipaddress.ip_network(net, strict=False)
            for net in self.config.internal_networks
        )
        
        if src_internal and dst_internal:
            return FlowDirection.INTERNAL
        elif src_internal and not dst_internal:
            return FlowDirection.OUTBOUND
        elif not src_internal and dst_internal:
            return FlowDirection.INBOUND
        else:
            return FlowDirection.EXTERNAL
