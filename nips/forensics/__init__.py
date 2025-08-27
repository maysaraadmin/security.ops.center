"""
NIPS Forensics Module

This package provides comprehensive logging and forensics capabilities for the NIPS,
including attack logging, packet capture, and event metadata storage.
"""

from .logger import ForensicLogger
from .pcap_manager import PCAPManager
from .event_store import EventStore
from .incident_manager import IncidentManager

__all__ = ['ForensicLogger', 'PCAPManager', 'EventStore', 'IncidentManager']
