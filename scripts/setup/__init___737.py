"""
Managers package for SIEM system.

This package contains various manager classes that handle different aspects
of the SIEM system, such as network detection and response (NDR),
data loss prevention (DLP), and file integrity monitoring (FIM).
"""

__all__ = ['BaseManager', 'ndr', 'dlp', 'fim']

# Import base manager
from .base import BaseManager
