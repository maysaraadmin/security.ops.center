"""
Data Classifier Module

This module provides functionality for identifying and classifying sensitive data
using various detection methods including regex patterns, keywords, and machine learning.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Any, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum, auto
import hashlib
import json

logger = logging.getLogger('dlp.classifier')

class DataType(Enum):
    """Types of sensitive data that can be detected."""
    # Personal Identifiable Information (PII)
    NAME = auto()
    EMAIL = auto()
    PHONE = auto()
    SSN = auto()  # Social Security Number (US)
    PASSPORT = auto()
    DRIVER_LICENSE = auto()
    
    # Financial Information
    CREDIT_CARD = auto()
    BANK_ACCOUNT = auto()
    
    # Health Information (PHI)
    MEDICAL_RECORD = auto()
    HEALTH_INSURANCE = auto()
    
    # Corporate Data
    IP_ADDRESS = auto()
    API_KEY = auto()
    DATABASE_CONNECTION = auto()
    
    # Custom types can be added dynamically
    CUSTOM = auto()

@dataclass
class DetectionResult:
    """Represents the result of a data classification operation."""
    data_type: DataType
    confidence: float  # 0.0 to 1.0
    matched_text: str
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the detection result to a dictionary."""
        return {
            'data_type': self.data_type.name,
            'confidence': self.confidence,
            'matched_text': self.matched_text,
            'context': self.context
        }

class DataClassifier:
    ""
    Classifies data based on predefined patterns and rules.
    
    This class provides methods to identify and classify sensitive data
    in text content using regular expressions, keyword matching, and
    other detection techniques.
    """
    
    def __init__(self):
        """Initialize the data classifier with default patterns."""
        self.patterns: Dict[DataType, List[Tuple[Pattern, float]]] = {}
        self.keywords: Dict[DataType, List[Tuple[str, float]]] = {}
        self.fingerprints: Dict[str, DataType] = {}
        self._initialize_default_patterns()
    
    def _initialize_default_patterns(self) -> None:
        """Initialize the default detection patterns."""
        # Email addresses
        self.add_pattern(
            DataType.EMAIL,
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            0.95
        )
        
        # US Social Security Numbers (SSN)
        self.add_pattern(
            DataType.SSN,
            r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',
            0.9
        )
        
        # Credit Card Numbers
        self.add_pattern(
            DataType.CREDIT_CARD,
            r'\b(?:\d[ -]*?){13,16}\b',
            0.8
        )
        
        # Phone Numbers (US format)
        self.add_pattern(
            DataType.PHONE,
            r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            0.85
        )
        
        # Add keyword-based detection
        self.add_keywords(
            DataType.API_KEY,
            [
                ('api[_-]?key', 0.9),
                ('secret[_-]?key', 0.95),
                ('private[_-]?key', 0.95),
            ]
        )
    
    def add_pattern(
        self, 
        data_type: DataType, 
        pattern: str, 
        confidence: float = 0.8,
        flags: int = re.IGNORECASE
    ) -> None:
        """Add a regex pattern for detecting a specific data type.
        
        Args:
            data_type: The type of data to detect
            pattern: Regular expression pattern
            confidence: Confidence level (0.0 to 1.0)
            flags: Regular expression flags
        """
        if data_type not in self.patterns:
            self.patterns[data_type] = []
        
        try:
            compiled = re.compile(pattern, flags)
            self.patterns[data_type].append((compiled, confidence))
        except re.error as e:
            logger.error(f"Invalid regex pattern for {data_type}: {pattern} - {e}")
    
    def add_keywords(
        self, 
        data_type: DataType, 
        keywords: List[Tuple[str, float]]
    ) -> None:
        """Add keywords for detecting a specific data type.
        
        Args:
            data_type: The type of data to detect
            keywords: List of (keyword, confidence) tuples
        """
        if data_type not in self.keywords:
            self.keywords[data_type] = []
        
        self.keywords[data_type].extend(keywords)
    
    def add_fingerprint(
        self, 
        data_type: DataType, 
        content: str, 
        threshold: float = 0.9
    ) -> str:
        """Add a fingerprint for exact or near-duplicate detection.
        
        Args:
            data_type: The type of data being fingerprinted
            content: The content to create a fingerprint for
            threshold: Similarity threshold for matching (0.0 to 1.0)
            
        Returns:
            The fingerprint ID
        """
        # Simple hash-based fingerprinting
        # In a real implementation, you might use more sophisticated techniques
        # like MinHash, SimHash, or TLSH
        fingerprint = hashlib.sha256(content.encode('utf-8')).hexdigest()
        self.fingerprints[fingerprint] = data_type
        return fingerprint
    
    def classify(self, text: str) -> List[DetectionResult]:
        """Classify sensitive data in the given text.
        
        Args:
            text: The text to analyze
            
        Returns:
            List of detection results
        """
        results = []
        
        # Check for patterns
        for data_type, patterns in self.patterns.items():
            for pattern, confidence in patterns:
                for match in pattern.finditer(text):
                    result = DetectionResult(
                        data_type=data_type,
                        confidence=confidence,
                        matched_text=match.group(0),
                        context={
                            'start_pos': match.start(),
                            'end_pos': match.end(),
                            'pattern': pattern.pattern
                        }
                    )
                    results.append(result)
        
        # Check for keywords
        for data_type, keyword_list in self.keywords.items():
            for keyword, confidence in keyword_list:
                if re.search(keyword, text, re.IGNORECASE):
                    result = DetectionResult(
                        data_type=data_type,
                        confidence=confidence,
                        matched_text=keyword,
                        context={
                            'detection_method': 'keyword',
                            'keyword': keyword
                        }
                    )
                    results.append(result)
        
        # Check for fingerprints (exact matches)
        for fingerprint, data_type in self.fingerprints.items():
            if fingerprint in text:
                result = DetectionResult(
                    data_type=data_type,
                    confidence=1.0,
                    matched_text=fingerprint,
                    context={
                        'detection_method': 'fingerprint',
                        'fingerprint': fingerprint
                    }
                )
                results.append(result)
        
        # Remove duplicates and sort by confidence (highest first)
        seen = set()
        unique_results = []
        
        for result in sorted(results, key=lambda x: x.confidence, reverse=True):
            # Create a unique key for each detection
            key = (result.data_type, result.matched_text, 
                   result.context.get('start_pos', 0), 
                   result.context.get('end_pos', 0))
            
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        return unique_results
    
    def contains_sensitive_data(self, text: str, min_confidence: float = 0.7) -> bool:
        """Check if the text contains any sensitive data above the confidence threshold.
        
        Args:
            text: The text to check
            min_confidence: Minimum confidence threshold (0.0 to 1.0)
            
        Returns:
            True if sensitive data is detected, False otherwise
        """
        results = self.classify(text)
        return any(r.confidence >= min_confidence for r in results)
    
    def redact(
        self, 
        text: str, 
        replacement: str = "[REDACTED]", 
        min_confidence: float = 0.7
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Redact sensitive data from the text.
        
        Args:
            text: The text to redact
            replacement: The replacement string for sensitive data
            min_confidence: Minimum confidence threshold for redaction
            
        Returns:
            A tuple of (redacted_text, redaction_details)
        """
        results = self.classify(text)
        redactions = []
        
        # Sort by position (right to left to avoid offset issues)
        filtered_results = [
            r for r in results 
            if r.confidence >= min_confidence and 
            'start_pos' in r.context and 
            'end_pos' in r.context
        ]
        
        # Sort by start position in reverse order
        filtered_results.sort(key=lambda x: x.context['start_pos'], reverse=True)
        
        # Apply redactions
        redacted = text
        
        for result in filtered_results:
            start = result.context['start_pos']
            end = result.context['end_pos']
            
            # Record the redaction
            redactions.append({
                'data_type': result.data_type.name,
                'confidence': result.confidence,
                'original_text': text[start:end],
                'start_pos': start,
                'end_pos': end,
                'context': result.context
            })
            
            # Apply the redaction
            redacted = redacted[:start] + replacement + redacted[end:]
        
        return redacted, redactions
