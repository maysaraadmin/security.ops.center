"""
EDR Agent - Lightweight endpoint monitoring and response.

This module provides a cross-platform EDR agent with minimal performance impact.
"""

__version__ = "1.0.0"
__all__ = [
    'EDRAgent',
    'Platform',
    'AgentConfig',
    'SystemInfo',
]

from .agent import EDRAgent
from .models import Platform, AgentConfig, SystemInfo
