"""
Data Loss Prevention (DLP) Module

This module provides data loss prevention capabilities including:
- Content inspection and classification
- Policy management and enforcement
- Endpoint and network monitoring
- Incident response and alerting
"""

from .policies import DLPPolicyManager
from .classifiers import ContentClassifier
from .engine import DLPEngine
from .enforcer import PolicyEnforcer, PolicyScope
from .actions import ActionType, ActionFactory, ActionContext
from .alerts import (
    Alert,
    AlertContext,
    AlertSeverity,
    AlertStatus,
    AlertManager,
    EmailNotifier,
    alert_manager  # Default instance
)

__all__ = [
    'DLPEngine',
    'DLPPolicyManager',
    'ContentClassifier',
    'PolicyEnforcer',
    'PolicyScope',
    'ActionType',
    'ActionFactory',
    'ActionContext',
    'Alert',
    'AlertContext',
    'AlertSeverity',
    'AlertStatus',
    'AlertManager',
    'EmailNotifier',
    'alert_manager'  # Default instance
]
