"""
Data Loss Prevention (DLP) Module

Provides data discovery, classification, and protection capabilities.
"""

__version__ = "1.0.0"

from .core import DLPScanner, ClassificationResult
from .policies import PolicyEngine, DataPattern
from .sources import (
    FileSystemScanner,
    DatabaseScanner,
    EmailScanner,
    CloudStorageScanner
)
from .classifiers import (
    RegexClassifier,
    MLClassifier,
    FileTypeClassifier
)

__all__ = [
    'DLPScanner',
    'ClassificationResult',
    'PolicyEngine',
    'DataPattern',
    'FileSystemScanner',
    'DatabaseScanner',
    'EmailScanner',
    'CloudStorageScanner',
    'RegexClassifier',
    'MLClassifier',
    'FileTypeClassifier'
]
