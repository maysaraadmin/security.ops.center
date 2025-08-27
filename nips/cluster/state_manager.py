"""
State Manager for NIPS High Availability

Manages the synchronization of state across cluster nodes to ensure
consistency during failover and recovery operations.
"""
import time
import logging
import threading
import json
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
import hashlib


class StateType(Enum):
    """Types of state that can be synchronized."""
    CONFIGURATION = auto()
    SESSION = auto()
    THREAT_INTEL = auto()
    RULES = auto()


class StateConsistency(Enum):
    """Consistency levels for state synchronization."""
    STRONG = auto()  # Synchronous replication
    EVENTUAL = auto()  # Asynchronous replication
    NONE = auto()  # No replication


@dataclass
class StateVersion:
    """Represents a versioned piece of state."""
    state_type: StateType
    data: Dict[str, Any]
    version: int = 0
    timestamp: float = field(default_factory=time.time)
    checksum: str = ""
    
    def __post_init__(self):
        self._update_checksum()
    
    def _update_checksum(self) -> None:
        """Update the checksum for the state data."""
        data_str = json.dumps(self.data, sort_keys=True)
        self.checksum = hashlib.sha256(data_str.encode()).hexdigest()
    
    def update(self, new_data: Dict[str, Any]) -> None:
        """Update the state data and increment version."""
        self.data.update(new_data)
        self.version += 1
        self.timestamp = time.time()
        self._update_checksum()


class StateManager:
    """
    Manages state synchronization across the NIPS cluster.
    
    This component is responsible for ensuring that all nodes in the cluster
    maintain a consistent view of important system state, particularly during
    failover scenarios.
    """
    
    def __init__(self, node_id: str):
        """
        Initialize the State Manager.
        
        Args:
            node_id: The ID of this node
        """
        self.node_id = node_id
        self.states: Dict[StateType, StateVersion] = {}
        self.logger = logging.getLogger('nips.cluster.state')
        self._lock = threading.RLock()
        self._subscribers: Dict[StateType, List[Callable[[StateVersion], None]]] = {}
        
        # Initialize empty states for all state types
        for state_type in StateType:
            self.states[state_type] = StateVersion(
                state_type=state_type,
                data={},
                version=0
            )
            self._subscribers[state_type] = []
    
    def subscribe(self, state_type: StateType, callback: Callable[[StateVersion], None]) -> None:
        """
        Subscribe to state updates for a specific state type.
        
        Args:
            state_type: The type of state to subscribe to
            callback: Function to call when the state is updated
        """
        with self._lock:
            if callback not in self._subscribers[state_type]:
                self._subscribers[state_type].append(callback)
                self.logger.debug(f"Added subscriber for {state_type.name}")
    
    def unsubscribe(self, state_type: StateType, callback: Callable[[StateVersion], None]) -> None:
        """
        Unsubscribe from state updates.
        
        Args:
            state_type: The type of state to unsubscribe from
            callback: The callback function to remove
        """
        with self._lock:
            if callback in self._subscribers[state_type]:
                self._subscribers[state_type].remove(callback)
                self.logger.debug(f"Removed subscriber from {state_type.name}")
    
    def update_state(
        self,
        state_type: StateType,
        updates: Dict[str, Any],
        consistency: StateConsistency = StateConsistency.STRONG
    ) -> bool:
        """
        Update the state with new data.
        
        Args:
            state_type: The type of state to update
            updates: Dictionary of updates to apply
            consistency: The desired consistency level for this update
            
        Returns:
            bool: True if the update was successful, False otherwise
        """
        with self._lock:
            state = self.states[state_type]
            
            # Apply the updates
            old_version = state.version
            state.update(updates)
            
            self.logger.info(
                f"Updated {state_type.name} state to version {state.version} "
                f"(consistency: {consistency.name})"
            )
            
            # In a real implementation, this would handle replication based on consistency level
            if consistency == StateConsistency.STRONG:
                # Synchronous replication to all nodes
                self._replicate_state(state_type, state, sync=True)
            elif consistency == StateConsistency.EVENTUAL:
                # Asynchronous replication
                self._replicate_state(state_type, state, sync=False)
            # For NONE, we don't replicate
            
            # Notify subscribers
            self._notify_subscribers(state_type, state)
            
            return True
    
    def get_state(self, state_type: StateType) -> StateVersion:
        """
        Get the current state for a specific type.
        
        Args:
            state_type: The type of state to retrieve
            
        Returns:
            StateVersion: The current state version
        """
        with self._lock:
            return self.states[state_type]
    
    def _replicate_state(self, state_type: StateType, state: StateVersion, sync: bool = True) -> None:
        """
        Replicate state to other nodes in the cluster.
        
        Args:
            state_type: The type of state being replicated
            state: The state version to replicate
            sync: If True, wait for replication to complete
        """
        # In a real implementation, this would send the state to other nodes
        # For now, we'll just log the operation
        mode = "synchronously" if sync else "asynchronously"
        self.logger.debug(
            f"Replicating {state_type.name} state {mode} (v{state.version})"
        )
        
        # Simulate network delay for async replication
        if not sync:
            def delayed_replication():
                time.sleep(0.1)  # Simulate network delay
                self.logger.debug(
                    f"Completed async replication of {state_type.name} state (v{state.version})"
                )
            
            thread = threading.Thread(target=delayed_replication, daemon=True)
            thread.start()
    
    def _notify_subscribers(self, state_type: StateType, state: StateVersion) -> None:
        """
        Notify all subscribers about a state update.
        
        Args:
            state_type: The type of state that was updated
            state: The new state version
        """
        for callback in self._subscribers[state_type]:
            try:
                callback(state)
            except Exception as e:
                self.logger.error(
                    f"Error in {state_type.name} subscriber: {e}",
                    exc_info=True
                )
    
    def synchronize_from_peer(self, state_type: StateType, peer_state: Dict[str, Any]) -> bool:
        """
        Synchronize state from a peer node.
        
        Args:
            state_type: The type of state being synchronized
            peer_state: The state data from the peer
            
        Returns:
            bool: True if synchronization was successful, False otherwise
        """
        with self._lock:
            current_state = self.states[state_type]
            
            # Check if the peer state is newer
            if peer_state.get('version', -1) > current_state.version:
                self.logger.info(
                    f"Updating {state_type.name} state from peer "
                    f"(v{current_state.version} -> v{peer_state.get('version')})"
                )
                
                # Apply the update
                current_state.data = peer_state.get('data', {})
                current_state.version = peer_state.get('version', 0)
                current_state.timestamp = peer_state.get('timestamp', time.time())
                current_state.checksum = peer_state.get('checksum', '')
                
                # Notify subscribers
                self._notify_subscribers(state_type, current_state)
                
                return True
            
            return False
