"""
Content Classifiers for DLP

Implements various classifiers for detecting sensitive content using different techniques.
"""
import re
import logging
import hashlib
from typing import Dict, List, Optional, Set, Any, Tuple, Union
from dataclasses import dataclass, field
import numpy as np
from pathlib import Path
import magic

# Optional ML imports
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

@dataclass
class ClassificationResult:
    """Container for classification results."""
    is_sensitive: bool = False
    confidence: float = 0.0
    matched_patterns: List[Dict] = field(default_factory=list)
    content_type: Optional[str] = None
    content_hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class ContentClassifier:
    """
    Classifies content using multiple techniques to detect sensitive information.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the content classifier.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.magic = magic.Magic(mime=True)
        self._init_classifiers()
        
        # Initialize patterns and keywords
        self.patterns = self._load_default_patterns()
        self.keywords = self._load_keyword_lists()
        
        # Initialize ML models if available
        self.ml_models = {}
        if ML_AVAILABLE:
            self._init_ml_models()
    
    def _init_classifiers(self) -> None:
        """Initialize various classifiers and analyzers."""
        self.file_type_analyzer = FileTypeAnalyzer()
        self.metadata_analyzer = MetadataAnalyzer()
        self.behavior_analyzer = BehaviorAnalyzer()
    
    def _init_ml_models(self) -> None:
        """Initialize machine learning models."""
        # This is a placeholder for ML model initialization
        # In a real implementation, you would load pre-trained models here
        pass
    
    def _load_default_patterns(self) -> Dict:
        """Load default patterns for content matching."""
        return {
            'credit_card': {
                'patterns': [
                    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'
                ],
                'sensitivity': 'high',
                'description': 'Credit card numbers'
            },
            'ssn': {
                'patterns': [
                    r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',
                    r'\b\d{3}\s\d{2}\s\d{4}\b'
                ],
                'sensitivity': 'high',
                'description': 'Social Security Numbers'
            },
            'email': {
                'patterns': [
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                ],
                'sensitivity': 'medium',
                'description': 'Email addresses'
            },
            'ip_address': {
                'patterns': [
                    r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                    r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'
                ],
                'sensitivity': 'medium',
                'description': 'IP addresses'
            }
        }
    
    def _load_keyword_lists(self) -> Dict[str, Set[str]]:
        """Load keyword lists for content classification."""
        return {
            'confidential': {
                'confidential', 'secret', 'top secret', 'classified',
                'restricted', 'proprietary', 'internal use only'
            },
            'financial': {
                'credit card', 'bank account', 'routing number', 'ssn',
                'social security', 'tax id', 'ein', 'tin'
            },
            'pii': {
                'name', 'address', 'phone', 'email', 'date of birth',
                'driver\'s license', 'passport', 'national id'
            }
        }
    
    def classify(self, content: Union[str, bytes], context: Optional[Dict] = None) -> ClassificationResult:
        """
        Classify content to determine if it contains sensitive information.
        
        Args:
            content: The content to classify (string or bytes)
            context: Additional context about the content
            
        Returns:
            ClassificationResult containing the classification results
        """
        context = context or {}
        result = ClassificationResult()
        
        # Convert bytes to string if needed
        content_str = content.decode('utf-8', errors='ignore') if isinstance(content, bytes) else str(content)
        
        # Analyze file type and metadata
        result.content_type = self._detect_content_type(content)
        result.metadata = self.metadata_analyzer.analyze(content, context)
        result.content_hash = self._calculate_content_hash(content)
        
        # Check for sensitive patterns
        result.matched_patterns = self._match_patterns(content_str)
        
        # Check for sensitive keywords
        keyword_matches = self._check_keywords(content_str)
        if keyword_matches:
            result.matched_patterns.extend(keyword_matches)
        
        # Use ML-based classification if available
        if ML_AVAILABLE and self.ml_models:
            ml_result = self._classify_with_ml(content_str, result.content_type)
            if ml_result.is_sensitive:
                result.is_sensitive = True
                result.confidence = max(result.confidence, ml_result.confidence)
        
        # Determine overall sensitivity
        if result.matched_patterns:
            result.is_sensitive = True
            # Set confidence based on the highest sensitivity match
            sensitivities = {'low': 0.5, 'medium': 0.75, 'high': 0.95}
            max_sensitivity = max(
                [sensitivities.get(p.get('sensitivity', 'low'), 0.5) 
                 for p in result.matched_patterns],
                default=0.0
            )
            result.confidence = max(result.confidence, max_sensitivity)
        
        # Add behavior analysis
        behavior_analysis = self.behavior_analyzer.analyze(context)
        if behavior_analysis.get('suspicious', False):
            result.is_sensitive = True
            result.confidence = max(result.confidence, 0.8)
            result.metadata['behavior_analysis'] = behavior_analysis
        
        return result
    
    def _detect_content_type(self, content: Union[str, bytes]) -> str:
        """Detect the content type (MIME type) of the content."""
        try:
            if isinstance(content, bytes):
                return self.magic.from_buffer(content[:1024])
            return 'text/plain'
        except Exception as e:
            self.logger.warning(f"Error detecting content type: {str(e)}")
            return 'application/octet-stream'
    
    def _calculate_content_hash(self, content: Union[str, bytes]) -> str:
        """Calculate a hash of the content for identification."""
        if isinstance(content, str):
            content = content.encode('utf-8', errors='ignore')
        return hashlib.sha256(content).hexdigest()
    
    def _match_patterns(self, content: str) -> List[Dict]:
        """Match content against known sensitive patterns."""
        matches = []
        
        for pattern_type, pattern_data in self.patterns.items():
            for pattern in pattern_data.get('patterns', []):
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                        matches.append({
                            'type': pattern_type,
                            'pattern': pattern,
                            'match': match.group(0),
                            'start': match.start(),
                            'end': match.end(),
                            'sensitivity': pattern_data.get('sensitivity', 'medium'),
                            'description': pattern_data.get('description', '')
                        })
                except re.error as e:
                    self.logger.warning(f"Invalid regex pattern {pattern}: {str(e)}")
        
        return matches
    
    def _check_keywords(self, content: str) -> List[Dict]:
        """Check content for sensitive keywords."
        
        Args:
            content: The content to check for keywords
            
        Returns:
            List of dictionaries containing keyword matches
        """
        matches = []
        content_lower = content.lower()
        
        for category, keywords in self.keywords.items():
            for keyword in keywords:
                if keyword.lower() in content_lower:
                    matches.append({
                        'type': 'keyword',
                        'category': category,
                        'keyword': keyword,
                        'sensitivity': 'medium',
                        'description': f'Sensitive keyword: {keyword}'
                    })
        
        return matches
    
    def _classify_with_ml(self, content: str, content_type: str) -> ClassificationResult:
        """
        Classify content using machine learning models.
        
        Args:
            content: The content to classify
            content_type: MIME type of the content
            
        Returns:
            ClassificationResult with ML-based classification
        """
        result = ClassificationResult()
        
        try:
            # This is a placeholder for ML-based classification
            # In a real implementation, you would use pre-trained models here
            # For example:
            # if 'text/' in content_type:
            #     features = self.vectorizer.transform([content])
            #     prediction = self.model.predict_proba(features)
            #     result.is_sensitive = prediction[0][1] > 0.5
            #     result.confidence = float(prediction[0][1])
            pass
            
        except Exception as e:
            self.logger.error(f"Error in ML classification: {str(e)}", exc_info=True)
        
        return result


class FileTypeAnalyzer:
    """Analyzes file types and extensions."""
    
    def __init__(self):
        self.risky_extensions = {
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.jse', '.wsf', '.wsh', '.msi', '.pif', '.scr', '.hta'
        }
    
    def is_risky_extension(self, filename: str) -> bool:
        """Check if a file has a risky extension."""
        if not filename:
            return False
        return Path(filename).suffix.lower() in self.risky_extensions


class MetadataAnalyzer:
    """Analyzes file metadata."""
    
    def analyze(self, content: Union[str, bytes], context: Dict) -> Dict:
        """
        Analyze file metadata.
        
        Args:
            content: The content to analyze
            context: Additional context
            
        Returns:
            Dictionary containing metadata analysis results
        """
        metadata = {}
        
        try:
            if isinstance(content, bytes):
                # Basic metadata
                metadata['size'] = len(content)
                
                # Calculate hashes
                metadata['hashes'] = {
                    'md5': hashlib.md5(content).hexdigest(),
                    'sha1': hashlib.sha1(content).hexdigest(),
                    'sha256': hashlib.sha256(content).hexdigest()
                }
                
        except Exception as e:
            logging.getLogger(__name__).warning(f"Error analyzing metadata: {str(e)}")
        
        return metadata


class BehaviorAnalyzer:
    """Analyzes user behavior for suspicious patterns."""
    
    def analyze(self, context: Dict) -> Dict:
        """
        Analyze user behavior for suspicious patterns.
        
        Args:
            context: Context containing user behavior data
            
        Returns:
            Dictionary containing behavior analysis results
        """
        result = {
            'suspicious': False,
            'indicators': []
        }
        
        # Example: Check for unusual access patterns
        if context.get('access_time', {}).get('is_after_hours', False):
            result['suspicious'] = True
            result['indicators'].append('After hours access')
        
        # Example: Check for bulk downloads
        if context.get('operation') == 'download' and context.get('file_count', 0) > 10:
            result['suspicious'] = True
            result['indicators'].append('Bulk download detected')
        
        return result
