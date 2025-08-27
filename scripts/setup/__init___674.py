"""
User and Entity Behavior Analytics (UEBA) Module

This module provides behavior analytics to detect anomalies in user and entity activities.
"""

__version__ = "1.0.0"
__all__ = ['UebaEngine', 'models', 'analyzers', 'utils']

from .engine import UebaEngine
from . import models
from . import analyzers
from . import utils
