"""
Cluster Manager for NIPS High Availability

Manages the cluster membership, health checks, and configuration synchronization
across multiple NIPS nodes in a high availability setup.
"""
import time
import threading
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum, auto


class NodeStatus(Enum):
    ACTIVE = auto()
    STANDBY = auto()
    FAILED = auto()


@dataclass
class ClusterNode:
    node_id: str
    ip_address: str
    status: NodeStatus = NodeStatus.STANDBY
    last_heartbeat: float = field(default_factory=time.time)
    priority: int = 100


class ClusterManager:
    def __init__(self, node_id: str, cluster_nodes: Dict[str, str], heartbeat_interval: int = 5):
        """
        Initialize the Cluster Manager.
        
        Args:
            node_id: Unique identifier for this node
            cluster_nodes: Dict of {node_id: ip_address} for all nodes in the cluster
            heartbeat_interval: Interval in seconds between heartbeats
        """
        self.node_id = node_id
        self.heartbeat_interval = heartbeat_interval
        self.nodes: Dict[str, ClusterNode] = {}
        self.is_active = False
        self.heartbeat_thread = None
        self.logger = logging.getLogger('nips.cluster.manager')
        
        # Initialize node information
        for nid, ip in cluster_nodes.items():
            status = NodeStatus.ACTIVE if nid == node_id else NodeStatus.STANDBY
            self.nodes[nid] = ClusterNode(
                node_id=nid,
                ip_address=ip,
                status=status,
                priority=100  # Default priority, can be configured
            )
        
        self.logger.info(f"Cluster manager initialized for node {node_id}")
    
    def start(self) -> None:
        """Start the cluster manager and begin health monitoring."""
        if self.is_active:
            self.logger.warning("Cluster manager is already running")
            return
            
        self.is_active = True
        self.heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name=f"Cluster-Heartbeat-{self.node_id}"
        )
        self.heartbeat_thread.start()
        self.logger.info("Cluster manager started")
    
    def stop(self) -> None:
        """Stop the cluster manager and clean up resources."""
        self.is_active = False
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=5)
        self.logger.info("Cluster manager stopped")
    
    def _heartbeat_loop(self) -> None:
        """Main loop for sending and processing heartbeats."""
        while self.is_active:
            try:
                self._send_heartbeats()
                self._check_node_health()
                time.sleep(self.heartbeat_interval)
            except Exception as e:
                self.logger.error(f"Error in heartbeat loop: {e}", exc_info=True)
                time.sleep(1)  # Prevent tight loop on errors
    
    def _send_heartbeats(self) -> None:
        """Send heartbeat to all cluster nodes."""
        current_time = time.time()
        # In a real implementation, this would send UDP/TCP heartbeats to other nodes
        self.nodes[self.node_id].last_heartbeat = current_time
        self.logger.debug(f"Sent heartbeat at {current_time}")
    
    def _check_node_health(self) -> None:
        """Check the health of all nodes in the cluster."""
        current_time = time.time()
        timeout = self.heartbeat_interval * 3  # 3 missed heartbeats = failure
        
        for node_id, node in list(self.nodes.items()):
            if node_id == self.node_id:
                continue  # Skip self
                
            time_since_heartbeat = current_time - node.last_heartbeat
            
            if time_since_heartbeat > timeout and node.status != NodeStatus.FAILED:
                self.logger.warning(f"Node {node_id} failed (no heartbeat for {time_since_heartbeat:.1f}s)")
                node.status = NodeStatus.FAILED
                self._handle_node_failure(node_id)
    
    def _handle_node_failure(self, failed_node_id: str) -> None:
        """Handle the failure of a cluster node."""
        # In a real implementation, this would trigger failover procedures
        self.logger.info(f"Initiating failover for node {failed_node_id}")
        
        # Find the next available standby node with highest priority
        standby_nodes = [
            node for node in self.nodes.values() 
            if node.status == NodeStatus.STANDBY and node.node_id != self.node_id
        ]
        
        if standby_nodes:
            # Sort by priority (highest first) and take the first one
            next_active = sorted(standby_nodes, key=lambda x: -x.priority)[0]
            self.logger.info(f"Promoting node {next_active.node_id} to ACTIVE")
            next_active.status = NodeStatus.ACTIVE
            # In a real implementation, we would notify the node to become active
    
    def get_active_nodes(self) -> List[ClusterNode]:
        """Get a list of all active nodes in the cluster."""
        return [node for node in self.nodes.values() if node.status == NodeStatus.ACTIVE]
    
    def get_node_status(self, node_id: str) -> Optional[NodeStatus]:
        """Get the status of a specific node."""
        node = self.nodes.get(node_id)
        return node.status if node else None
    
    def is_leader(self) -> bool:
        """Check if this node is the current leader/primary."""
        # In this simple implementation, the first active node is the leader
        active_nodes = self.get_active_nodes()
        return bool(active_nodes) and active_nodes[0].node_id == self.node_id
