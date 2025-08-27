"""
SIEM Components Package

This package contains various components that can be used by the SIEM system.
"""

# Import component factory functions here
from .log_collector import create_component as create_log_collector

# Export the component factory functions
__all__ = [
    'create_log_collector'
]
