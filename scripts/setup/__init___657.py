"""
EDR (Endpoint Detection and Response) System

This package provides endpoint monitoring, threat detection, and response capabilities.
"""

__version__ = "0.1.0"

# Import main components
from .agent import EDRAgent
from .server import EDRServer, EDRAgentServer
from .detection import DetectionRule
from .response import ResponseAction, LogAction, ProcessKillAction, ResponseEngine

__all__ = [
    'EDRAgent',
    'EDRServer',
    'EDRAgentServer',
    'DetectionRule',
    'ResponseAction',
    'ResponseEngine',
    'LogAction',
    'ProcessKillAction'
]
