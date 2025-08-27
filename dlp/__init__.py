"""
DLP Package

This package contains the Data Loss Prevention system components.
"""

# Import core components to make them available at the package level
from .dlp_gui import main
from dlp.core import (
    DataType,
    ClassificationResult,
    DLPScanner,
    DLPUserInteraction,
    PolicyEngine
)

__all__ = [
    'main',
    'DataType',
    'ClassificationResult',
    'DLPScanner',
    'DLPUserInteraction',
    'PolicyEngine'
]
