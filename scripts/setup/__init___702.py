"""
Network Intrusion Prevention System (NIPS) Core Module

This module provides the core functionality for detecting and preventing
network-based attacks in real-time.
"""

from .nips_engine import NIPSEngine
from .signature_detector import SignatureDetector
from .anomaly_detector import AnomalyDetector
from .protocol_analyzer import ProtocolAnalyzer
from .traffic_inspector import TrafficInspector
from .threat_intel import ThreatIntelligence
from .response_engine import ResponseEngine

__all__ = [
    'NIPSEngine',
    'SignatureDetector',
    'AnomalyDetector',
    'ProtocolAnalyzer',
    'TrafficInspector',
    'ThreatIntelligence',
    'ResponseEngine'
]
