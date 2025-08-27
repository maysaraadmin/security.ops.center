"""
Network Traffic Collector

Collects and processes network traffic for analysis.
"""
import asyncio
import logging
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any

# Protocol analyzers
from .protocols.dns import DNSAnalyzer
from .protocols.http import HTTPAnalyzer

logger = logging.getLogger('ndr.collector')

class NetworkCollector:
    """Collects and processes network traffic."""
    
    def __init__(self, interface: str = None):
        """
        Initialize the network collector.
        
        Args:
            interface: Network interface to capture on (ignored in this implementation)
        """
        self.running = False
        self.flows: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.max_flows = 1000
        self.analyzers = {
            'dns': DNSAnalyzer(),
            'http': HTTPAnalyzer()
        }
        
        # Generate initial sample data
        self._generate_sample_data()
    
    def _generate_sample_data(self):
        """Generate sample network flow data for demo purposes."""
        protocols = ['tcp', 'udp']
        ports = [80, 443, 53, 22, 3389]
        
        for i in range(50):  # Generate 50 sample flows
            src_ip = f"192.168.1.{random.randint(1, 254)}"
            dst_ip = f"10.0.0.{random.randint(1, 254)}"
            protocol = random.choice(protocols)
            
            flow = {
                'timestamp': datetime.now() - timedelta(seconds=random.randint(0, 300)),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice(ports),
                'protocol': protocol,
                'bytes': random.randint(100, 10000),
                'flags': '...A...'  # SYN-ACK
            }
            self.flows.append(flow)
    
    def start(self):
        """Start the collector."""
        if self.running:
            return
            
        self.running = True
        # In a real implementation, this would start actual packet capture
        logger.info("Network collector started")
    
    def stop(self):
        """Stop the collector."""
        self.running = False
        logger.info("Network collector stopped")
    
    def get_recent_flows(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent network flows.
        
        Args:
            limit: Maximum number of flows to return
            
        Returns:
            List of recent flow dictionaries, sorted by timestamp (newest first)
        """
        return sorted(
            self.flows[-self.max_flows:],
            key=lambda x: x['timestamp'],
            reverse=True
        )[:limit]
    
    def get_alerts(self) -> List[Dict[str, Any]]:
        """
        Get any generated alerts.
        
        Returns:
            List of alert dictionaries
        """
        alerts = self.alerts.copy()
        self.alerts.clear()
        return alerts
