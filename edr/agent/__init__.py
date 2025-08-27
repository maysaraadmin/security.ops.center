"""
EDR Agent Package
----------------
This package contains the core EDR (Endpoint Detection and Response) agent implementation.
"""

# Import key components to make them available at the package level
from .edr_agent import EDRAgent, EDREvent, EventSeverity

__all__ = ['EDRAgent', 'EDREvent', 'EventSeverity']
