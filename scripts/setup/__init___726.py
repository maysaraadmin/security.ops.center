"""
Network Intrusion Prevention System (NIPS) service for SIEM.

This module provides network-based intrusion prevention capabilities by monitoring
network traffic and taking actions to prevent detected threats.
"""

# Import core components
from .models import NIPSRule, NIPSAlert, NIPSStats, NIPSRuleType
from .rules import NIPSRuleEngine
from .service import NIPSService, create_nips_service

# Re-export public API
__all__ = [
    'NIPSService',
    'create_nips_service',
    'NIPSRule',
    'NIPSAlert',
    'NIPSStats',
    'NIPSRuleType',
    'NIPSRuleEngine'
]

# Create a default instance for backward compatibility
_nips_service = None

def get_nips_service(config: dict = None) -> NIPSService:
    """
    Get or create a singleton NIPS service instance.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        NIPSService: The NIPS service instance
    """
    global _nips_service
    if _nips_service is None:
        _nips_service = create_nips_service(config=config)
    return _nips_service

# Backward compatibility alias
NIPSManager = NIPSService

# Singleton instance for backward compatibility
def get_nips_manager():
    """Get the NIPS service instance (legacy API)."""
    return get_nips_service()

# Legacy singleton instance
nips_manager = get_nips_service()
