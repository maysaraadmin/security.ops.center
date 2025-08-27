"""
Example Usage of NIPS High Availability Components

This module demonstrates how to use the cluster, load balancing, failover,
and state management components together in a NIPS node.
"""
import logging
import time
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('nips.example')

# Import our HA components
from .cluster_manager import ClusterManager, NodeStatus
from .load_balancer import LoadBalancer, LoadBalanceStrategy
from .failover_manager import FailoverManager, FailoverState
from .state_manager import StateManager, StateType, StateConsistency


class NIPSNode:
    """
    Example NIPS node implementation demonstrating high availability features.
    """
    
    def __init__(self, node_id: str, cluster_nodes: Dict[str, str]):
        """
        Initialize the NIPS node with high availability features.
        
        Args:
            node_id: Unique identifier for this node
            cluster_nodes: Dictionary of {node_id: ip_address} for all nodes in the cluster
        """
        self.node_id = node_id
        self.is_running = False
        
        # Initialize HA components
        self.cluster = ClusterManager(node_id, cluster_nodes)
        self.load_balancer = LoadBalancer(strategy=LoadBalanceStrategy.ROUND_ROBIN)
        self.failover = FailoverManager(node_id)
        self.state = StateManager(node_id)
        
        # Register callbacks
        self._register_callbacks()
        
        logger.info(f"Initialized NIPS node {node_id}")
    
    def _register_callbacks(self) -> None:
        """Register callbacks for various HA events."""
        # Register failover callbacks
        self.failover.register_callback('before_failover', self._on_before_failover)
        self.failover.register_callback('after_failover', self._on_after_failover)
        self.failover.register_callback('state_change', self._on_failover_state_change)
        
        # Register state change subscribers
        self.state.subscribe(StateType.CONFIGURATION, self._on_config_update)
        self.state.subscribe(StateType.THREAT_INTEL, self._on_threat_intel_update)
    
    def start(self) -> None:
        """Start the NIPS node and all HA components."""
        if self.is_running:
            logger.warning("NIPS node is already running")
            return
        
        logger.info("Starting NIPS node...")
        
        try:
            # Start cluster manager first
            self.cluster.start()
            
            # Start failover manager
            self.failover.start()
            
            # Initialize load balancer with current cluster state
            self._update_load_balancer()
            
            # Mark as running
            self.is_running = True
            
            logger.info("NIPS node started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start NIPS node: {e}", exc_info=True)
            self.stop()
            raise
    
    def stop(self) -> None:
        """Stop the NIPS node and clean up resources."""
        logger.info("Stopping NIPS node...")
        
        # Stop components
        self.failover.stop()
        self.cluster.stop()
        
        self.is_running = False
        logger.info("NIPS node stopped")
    
    def _update_load_balancer(self) -> None:
        """Update the load balancer with current cluster state."""
        # Get all active nodes from cluster manager
        active_nodes = [
            node for node in self.cluster.nodes.values()
            if node.status == NodeStatus.ACTIVE
        ]
        
        # Update load balancer
        self.load_balancer.update_backends(active_nodes)
        logger.debug(f"Updated load balancer with {len(active_nodes)} active nodes")
    
    def process_traffic(self, traffic: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process network traffic through the NIPS.
        
        Args:
            traffic: Dictionary containing traffic data
            
        Returns:
            Dict containing processing results
        """
        if not self.is_running:
            raise RuntimeError("NIPS node is not running")
        
        # Get the appropriate backend for this traffic
        client_ip = traffic.get('source_ip', '')
        backend = self.load_balancer.get_backend(client_ip)
        
        if not backend:
            logger.error("No available backends for traffic processing")
            return {"status": "error", "message": "No available backends"}
        
        # In a real implementation, this would forward traffic to the selected backend
        # and return the results. For this example, we'll just log the action.
        logger.info(f"Processing traffic from {client_ip} via {backend.node_id}")
        
        # Simulate processing
        time.sleep(0.1)
        
        return {
            "status": "processed",
            "node": self.node_id,
            "backend": backend.node_id,
            "timestamp": time.time()
        }
    
    # --- Callback Handlers ---
    
    def _on_before_failover(self) -> None:
        """Called before a failover operation begins."""
        logger.warning("Preparing for failover...")
        # Perform any necessary preparation, such as pausing traffic processing
    
    def _on_after_failover(self, success: bool) -> None:
        """Called after a failover operation completes."""
        status = "succeeded" if success else "failed"
        logger.warning(f"Failover {status}")
        
        if success:
            # Update load balancer with new cluster state
            self._update_load_balancer()
    
    def _on_failover_state_change(self, old_state: FailoverState, new_state: FailoverState) -> None:
        """Called when the failover state changes."""
        logger.info(f"Failover state changed from {old_state.name} to {new_state.name}")
    
    def _on_config_update(self, state) -> None:
        """Called when configuration state is updated."""
        logger.info(f"Configuration updated to version {state.version}")
        # Apply configuration changes to this node
    
    def _on_threat_intel_update(self, state) -> None:
        """Called when threat intelligence data is updated."""
        logger.info(f"Threat intelligence updated to version {state.version}")
        # Update local threat intelligence cache


def run_example():
    """Run an example demonstrating the NIPS HA features."""
    # Define our test cluster
    cluster_nodes = {
        "node1": "192.168.1.101",
        "node2": "192.168.1.102",
        "node3": "192.168.1.103"
    }
    
    # Create and start a node
    node = NIPSNode("node1", cluster_nodes)
    
    try:
        # Start the node
        node.start()
        
        # Simulate some traffic processing
        for i in range(5):
            result = node.process_traffic({
                "source_ip": f"10.0.0.{i}",
                "destination_ip": "192.168.1.1",
                "protocol": "tcp",
                "port": 80
            })
            logger.info(f"Processed traffic: {result}")
        
        # Simulate a configuration update
        node.state.update_state(
            StateType.CONFIGURATION,
            {"max_connections": 1000, "inspection_depth": "full"},
            StateConsistency.STRONG
        )
        
        # Let the node run for a bit
        time.sleep(2)
        
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        # Clean up
        node.stop()


if __name__ == "__main__":
    run_example()
