"""
NIPS High Availability & Scalability Module

Provides clustering, load balancing, and failover capabilities for the NIPS.
"""

from .cluster_manager import ClusterManager
from .load_balancer import LoadBalancer
from .failover_manager import FailoverManager
from .state_manager import StateManager

__all__ = ['ClusterManager', 'LoadBalancer', 'FailoverManager', 'StateManager']
