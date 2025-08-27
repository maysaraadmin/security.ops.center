"""
Data Classifiers for DLP

Classifiers for identifying and categorizing sensitive data.
"""
import re
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple, Set, Pattern, Union
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path

# Import core types
from .core import DataType, ClassificationResult, MatchConfidence
from .policies import DataPattern, load_standard_patterns

logger = logging.getLogger('dlp.classifiers')

class BaseClassifier(ABC):
    """Base class for all DLP classifiers."""
    
    def __init__(self, **kwargs):
        self.name = self.__class__.__name__
        self.config = kwargs
        self.patterns: Dict[str, DataPattern] = {}
        self._load_patterns()
    
    @abstractmethod
    async def classify(
        self, 
        content: str, 
        metadata: Dict[str, Any]
    ) -> Union[ClassificationResult, List[ClassificationResult], None]:
        """Classify content and return classification results."""
        raise NotImplementedError
    
    def _load_patterns(self):
        """Load patterns for this classifier."""
        # Load standard patterns by default
        self.patterns.update(load_standard_patterns())
        
        # Load custom patterns if specified
        custom_patterns = self.config.get('patterns', [])
        for pattern_data in custom_patterns:
            if isinstance(pattern_data, dict):
                pattern = DataPattern(**pattern_data)
                self.patterns[pattern.name] = pattern
    
    def _create_result(
        self,
        data_type: DataType,
        match: str,
        context: str = "",
        location: str = "",
        line_number: Optional[int] = None,
        rule_id: Optional[str] = None,
        confidence: MatchConfidence = MatchConfidence.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """Create a classification result."""
        return ClassificationResult(
            data_type=data_type,
            confidence=confidence,
            match=match,
            context=context,
            location=location,
            line_number=line_number,
            rule_id=rule_id,
            metadata=metadata or {}
        )

class RegexClassifier(BaseClassifier):
    """
    Classifies data using regular expression patterns.
    
    This is the most common type of classifier for DLP, using regex patterns
    to identify structured data like credit card numbers, SSNs, etc.
    """
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.patterns = {}
        self._compile_patterns()
        self.min_confidence = self.config.get('min_confidence', 0.7)
    
    async def classify(
        self, 
        content: str, 
        metadata: Dict[str, Any]
    ) -> List[ClassificationResult]:
        """Classify content using regex patterns."""
        results = []
        
        for pattern_name, pattern in self.patterns.items():
            if not pattern.patterns:
                continue
                
            # Skip if the content is too short for this pattern
            if len(content) < pattern.required_matches * 10:  # Arbitrary minimum
                continue
                
            # Check for exact matches first (if any)
            if pattern.match_type == 'exact':
                for p in pattern.patterns:
                    if p in content:
                        results.append(self._create_result(
                            data_type=DataType[pattern.data_type.upper()],
                            match=p,
                            context=self._get_context(content, p),
                            location=metadata.get('path', ''),
                            rule_id=pattern_name,
                            confidence=MatchConfidence.HIGH
                        ))
            # Check for regex matches
            else:
                for regex in pattern.patterns:
                    for match in regex.finditer(content):
                        if not match.group(0):
                            continue
                            
                        # Skip if this is an exception
                        if self._is_exception(match.group(0), pattern):
                            continue
                            
                        # Check if we need to match multiple patterns in proximity
                        if pattern.required_matches > 1:
                            if not self._has_required_matches(content, pattern, match.start()):
                                continue
                        
                        # Add the match
                        results.append(self._create_result(
                            data_type=DataType[pattern.data_type.upper()],
                            match=match.group(0),
                            context=self._get_context(content, match.group(0)),
                            location=metadata.get('path', ''),
                            line_number=self._get_line_number(content, match.start()),
                            rule_id=pattern_name,
                            confidence=MatchConfidence.HIGH if pattern.confidence > 0.8 else 
                                      MatchConfidence.MEDIUM if pattern.confidence > 0.5 else 
                                      MatchConfidence.LOW,
                            metadata={
                                'pattern': pattern_name,
                                'match_type': pattern.match_type,
                                'full_match': match.group(0)
                            }
                        ))
        
        return results
    
    def _compile_patterns(self):
        """Compile regex patterns for faster matching."""
        # Load standard patterns
        self.patterns = load_standard_patterns()
        
        # Add custom patterns
        custom_patterns = self.config.get('patterns', [])
        for pattern_data in custom_patterns:
            if isinstance(pattern_data, dict):
                pattern = DataPattern(**pattern_data)
                if pattern.match_type == 'regex':
                    pattern.patterns = [re.compile(p, re.IGNORECASE | re.MULTILINE) 
                                      for p in pattern.patterns]
                self.patterns[pattern.name] = pattern
    
    def _is_exception(self, match: str, pattern: DataPattern) -> bool:
        """Check if a match is in the exception list."""
        if not pattern.exceptions:
            return False
            
        for exception in pattern.exceptions:
            if re.search(exception, match, re.IGNORECASE):
                return True
        return False
    
    def _has_required_matches(
        self, 
        content: str, 
        pattern: DataPattern, 
        pos: int
    ) -> bool:
        """Check if there are enough matches within the proximity window."""
        if pattern.required_matches <= 1:
            return True
            
        window_start = max(0, pos - (pattern.proximity or 1000))
        window_end = min(len(content), pos + (pattern.proximity or 1000))
        window = content[window_start:window_end]
        
        # Count matches of all patterns in this pattern group
        match_count = 0
        for p in pattern.patterns:
            match_count += len(list(p.finditer(window)))
            if match_count >= pattern.required_matches:
                return True
                
        return False
    
    def _get_context(self, content: str, match: str, context_size: int = 100) -> str:
        """Get context around a match."""
        if not match:
            return ""
            
        start = max(0, content.find(match) - context_size)
        end = min(len(content), content.find(match) + len(match) + context_size)
        return content[start:end].strip()
    
    def _get_line_number(self, content: str, pos: int) -> int:
        """Get line number for a character position."""
        return content.count('\n', 0, pos) + 1

class MLClassifier(BaseClassifier):
    """
    Classifies data using machine learning models.
    
    This is a placeholder for more advanced classification using trained models
    to identify sensitive data that may not be easily matched with regex.
    """
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.model_path = self.config.get('model_path')
        self.model = self._load_model()
        self.min_confidence = self.config.get('min_confidence', 0.7)
    
    async def classify(
        self, 
        content: str, 
        metadata: Dict[str, Any]
    ) -> List[ClassificationResult]:
        """Classify content using a machine learning model."""
        if not self.model or not content.strip():
            return []
            
        try:
            # This is a placeholder for actual ML model inference
            # In practice, you'd use something like:
            # predictions = await self.model.predict([content])
            
            # For now, we'll just return an empty list
            return []
            
        except Exception as e:
            logger.error(f"Error in ML classification: {e}")
            return []
    
    def _load_model(self):
        """Load the ML model."""
        if not self.model_path:
            logger.warning("No model path specified for MLClassifier")
            return None
            
        try:
            # This is a placeholder for actual model loading
            # In practice, you'd use something like:
            # import tensorflow as tf
            # return tf.saved_model.load(self.model_path)
            return None
            
        except Exception as e:
            logger.error(f"Error loading ML model: {e}")
            return None

class FileTypeClassifier(BaseClassifier):
    """
    Classifies files based on their type and content.
    
    This can be used to detect sensitive file types (e.g., private keys, 
    configuration files with secrets) or to filter files before further analysis.
    """
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.sensitive_file_types = self.config.get('sensitive_file_types', [
            # Common sensitive file types
            'pem', 'key', 'p12', 'pfx', 'cer', 'crt', 'p7b', 'p7c', 'p7s',
            'pkcs7', 'p8', 'pk8', 'jks', 'keystore', 'truststore', 'jceks',
            'ovpn', 'tblk', 'tblk.tar', 'tblk.zip', 'ppk', 'kdbx', 'kdb',
            'agilekeychain', 'keychain', 'pem', 'p8', 'pk8', 'p12', 'pfx',
            'p7b', 'p7c', 'p7s', 'pkcs7', 'jks', 'keystore', 'truststore',
            'jceks', 'ovpn', 'tblk', 'tblk.tar', 'tblk.zip', 'ppk', 'kdbx',
            'kdb', 'agilekeychain', 'keychain', 'pem', 'p8', 'pk8', 'p12',
            'pfx', 'p7b', 'p7c', 'p7s', 'pkcs7', 'jks', 'keystore',
            'truststore', 'jceks', 'ovpn', 'tblk', 'tblk.tar', 'tblk.zip',
            'ppk', 'kdbx', 'kdb', 'agilekeychain', 'keychain', 'pem', 'p8',
            'pk8', 'p12', 'pfx', 'p7b', 'p7c', 'p7s', 'pkcs7', 'jks',
            'keystore', 'truststore', 'jceks', 'ovpn', 'tblk', 'tblk.tar',
            'tblk.zip', 'ppk', 'kdbx', 'kdb', 'agilekeychain', 'keychain'
        ])
        
        # File signatures (magic numbers)
        self.file_signatures = {
            # Add file signatures here if needed
        }
    
    async def classify(
        self, 
        content: str, 
        metadata: Dict[str, Any]
    ) -> List[ClassificationResult]:
        """Classify files based on their type and content."""
        results = []
        
        # Check file extension
        file_path = metadata.get('path', '')
        file_ext = Path(file_path).suffix.lower().lstrip('.')
        
        if file_ext in self.sensitive_file_types:
            results.append(self._create_result(
                data_type=DataType.CREDENTIALS,
                match=f"Sensitive file type: .{file_ext}",
                context=f"File with sensitive extension: {file_path}",
                location=file_path,
                rule_id=f"sensitive_extension_{file_ext}",
                confidence=MatchConfidence.HIGH
            ))
        
        # Check for sensitive content patterns
        sensitive_patterns = [
            (r'-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----', 'private_key'),
            (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
            (r'sk_live_[0-9a-zA-Z]{24,}', 'stripe_secret_key'),
            (r'xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}', 'slack_bot_token'),
            (r'xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}', 'slack_user_token'),
            (r'xoxa-2-[0-9a-zA-Z]{1,48}', 'slack_app_token'),
            (r'xoxs-[0-9]{1,}-[0-9a-zA-Z]{1,}', 'slack_session_token'),
        ]
        
        for pattern, pattern_name in sensitive_patterns:
            if re.search(pattern, content, re.MULTILINE):
                results.append(self._create_result(
                    data_type=DataType.CREDENTIALS,
                    match=f"Sensitive content: {pattern_name}",
                    context=f"File contains {pattern_name}",
                    location=file_path,
                    rule_id=f"sensitive_content_{pattern_name}",
                    confidence=MatchConfidence.HIGH
                ))
        
        return results

# Factory function to create classifiers
def create_classifier(classifier_type: str, **kwargs) -> BaseClassifier:
    """Create a classifier of the specified type."""
    classifiers = {
        'regex': RegexClassifier,
        'ml': MLClassifier,
        'file_type': FileTypeClassifier,
    }
    
    if classifier_type not in classifiers:
        raise ValueError(f"Unknown classifier type: {classifier_type}")
        
    return classifiers[classifier_type](**kwargs)
