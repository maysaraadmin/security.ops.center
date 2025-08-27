"""
Network Detection and Response (NDR) Module

Provides comprehensive network visibility, threat detection, and response capabilities.
Integrates with EDR and SIEM for unified security operations.
"""
from .collector import NetworkCollector
from .analyzer import NetworkAnalyzer
from .responder import NetworkResponder
from .models.flow import NetworkFlow
from .models.alert import NetworkAlert

__version__ = '1.0.0'
__all__ = [
    'NetworkCollector',
    'NetworkAnalyzer',
    'NetworkResponder',
    'NetworkFlow',
    'NetworkAlert'
]
