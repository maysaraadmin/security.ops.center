"""
SIEM Collectors Package

This package contains collectors for gathering security events from various sources.
"""
from .base import BaseCollector
from .manager import CollectorManager

__all__ = ['BaseCollector', 'CollectorManager']
