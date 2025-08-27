"""
Load Balancer for NIPS High Availability

Distributes network traffic across multiple NIPS nodes to ensure
scalability and high availability.
"""
import random
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum, auto
from .cluster_manager import ClusterNode


class LoadBalanceStrategy(Enum):
    ROUND_ROBIN = auto()
    LEAST_CONNECTIONS = auto()
    RANDOM = auto()
    SOURCE_IP_HASH = auto()


@dataclass
class BackendNode:
    """Represents a backend NIPS node for load balancing."""
    node: ClusterNode
    active_connections: int = 0
    weight: int = 1
    is_healthy: bool = True


class LoadBalancer:
    """
    Implements various load balancing algorithms to distribute traffic
    across multiple NIPS nodes.
    """
    
    def __init__(self, strategy: LoadBalanceStrategy = LoadBalanceStrategy.ROUND_ROBIN):
        """
        Initialize the load balancer.
        
        Args:
            strategy: The load balancing strategy to use
        """
        self.strategy = strategy
        self.backends: Dict[str, BackendNode] = {}
        self.current_index = 0  # For round-robin
        self.logger = logging.getLogger('nips.cluster.load_balancer')
    
    def update_backends(self, nodes: List[ClusterNode]) -> None:
        """
        Update the list of available backend nodes.
        
        Args:
            nodes: List of available cluster nodes
        """
        current_backends = set(self.backends.keys())
        new_backends = set()
        
        # Add or update backends
        for node in nodes:
            new_backends.add(node.node_id)
            if node.node_id not in self.backends:
                self.backends[node.node_id] = BackendNode(node=node)
                self.logger.info(f"Added new backend node: {node.node_id}")
        
        # Remove old backends
        for node_id in current_backends - new_backends:
            del self.backends[node_id]
            self.logger.info(f"Removed backend node: {node_id}")
        
        self.logger.debug(f"Updated backends: {[n.node_id for n in self.backends.values()]}")
    
    def get_backend(self, client_ip: Optional[str] = None) -> Optional[ClusterNode]:
        """
        Select a backend node based on the configured strategy.
        
        Args:
            client_ip: Client IP for IP hash strategy
            
        Returns:
            Selected ClusterNode or None if no backends available
        """
        if not self.backends:
            self.logger.warning("No backends available")
            return None
        
        healthy_backends = [b for b in self.backends.values() if b.is_healthy]
        if not healthy_backends:
            self.logger.error("No healthy backends available")
            return None
        
        if self.strategy == LoadBalanceStrategy.ROUND_ROBIN:
            return self._round_robin(healthy_backends)
        elif self.strategy == LoadBalanceStrategy.LEAST_CONNECTIONS:
            return self._least_connections(healthy_backends)
        elif self.strategy == LoadBalanceStrategy.RANDOM:
            return self._random(healthy_backends)
        elif self.strategy == LoadBalanceStrategy.SOURCE_IP_HASH:
            return self._source_ip_hash(healthy_backends, client_ip or "")
        else:
            self.logger.warning(f"Unknown strategy: {self.strategy}, using round-robin")
            return self._round_robin(healthy_backends)
    
    def _round_robin(self, backends: List[BackendNode]) -> ClusterNode:
        """Round-robin load balancing strategy."""
        backend = backends[self.current_index % len(backends)]
        self.current_index = (self.current_index + 1) % len(backends)
        return backend.node
    
    def _least_connections(self, backends: List[BackendNode]) -> ClusterNode:
        """Least connections load balancing strategy."""
        return min(backends, key=lambda x: x.active_connections).node
    
    def _random(self, backends: List[BackendNode]) -> ClusterNode:
        """Random load balancing strategy."""
        return random.choice(backends).node
    
    def _source_ip_hash(self, backends: List[BackendNode], client_ip: str) -> ClusterNode:
        """Source IP hash load balancing strategy."""
        if not client_ip:
            self.logger.warning("No client IP provided for IP hash, using random")
            return self._random(backends)
            
        # Simple hash function for IP to index
        index = sum(ord(c) for c in client_ip) % len(backends)
        return backends[index].node
    
    def connection_opened(self, node_id: str) -> None:
        """Notify the load balancer that a new connection was opened."""
        if node_id in self.backends:
            self.backends[node_id].active_connections += 1
    
    def connection_closed(self, node_id: str) -> None:
        """Notify the load balancer that a connection was closed."""
        if node_id in self.backends and self.backends[node_id].active_connections > 0:
            self.backends[node_id].active_connections -= 1
    
    def set_node_health(self, node_id: str, is_healthy: bool) -> None:
        """Update the health status of a backend node."""
        if node_id in self.backends:
            self.backends[node_id].is_healthy = is_healthy
            status = "healthy" if is_healthy else "unhealthy"
            self.logger.info(f"Marked node {node_id} as {status}")
