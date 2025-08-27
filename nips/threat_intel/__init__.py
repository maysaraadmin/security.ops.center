"""
Threat Intelligence Integration for NIPS

Provides integration with various threat intelligence feeds and platforms.
"""

from .feed_manager import ThreatFeedManager
from .intel_client import ThreatIntelClient
from .ioc_processor import IOCProcessor
from .enrichment import ThreatEnrichment
from .cache import IOCache

__all__ = [
    'ThreatFeedManager',
    'ThreatIntelClient',
    'IOCProcessor',
    'ThreatEnrichment',
    'IOCache'
]
