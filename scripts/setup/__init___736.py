"""
SIEM Log Processing

This package provides advanced log processing capabilities for the SIEM system,
including log collection, normalization, enrichment, and correlation.
"""

from .pipeline import (
    ProcessingStage,
    FieldExtractor,
    Enricher,
    Filter,
    BatchProcessor,
    LogPipeline,
)

from .source_manager import (
    SourceConfig,
    SourceStats,
    LogSourceManager,
)

__all__ = [
    # Pipeline components
    'ProcessingStage',
    'FieldExtractor',
    'Enricher',
    'Filter',
    'BatchProcessor',
    'LogPipeline',
    
    # Source management
    'SourceConfig',
    'SourceStats',
    'LogSourceManager',
]
