"""
Behavior models for UEBA.

This package contains various behavior models used for anomaly detection.
"""

from .base import BehaviorModel
from .statistical import StatisticalModel
from .machine_learning import IsolationForestModel, OneClassSVMModel

__all__ = ['BehaviorModel', 'StatisticalModel', 'IsolationForestModel', 'OneClassSVMModel']
