"""
Core components of the EDR system.
"""

# Core EDR components
from .base import EDRBase, EDRConfig
from .event import EDREvent, EventType, EventSeverity
from .agent import EDRAgent
from .detection import DetectionRule, DetectionEngine
from .threat_detector import ThreatDetector
