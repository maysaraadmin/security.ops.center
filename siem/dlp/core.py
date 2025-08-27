""
DLP Core Engine

Implements the main DLP scanning and analysis functionality.
"""
import re
import logging
from typing import Dict, List, Optional, Union, Any, Tuple
from pathlib import Path
import magic
import hashlib

class DLPEngine:
    """
    Main DLP engine that coordinates content inspection and analysis.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the DLP engine with optional configuration.
        
        Args:
            config: Configuration dictionary for the DLP engine
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.patterns = self._load_default_patterns()
        self.magic = magic.Magic(mime=True)
        
    def _load_default_patterns(self) -> Dict[str, Dict]:
        """Load default patterns for content inspection."""
        return {
            'credit_card': {
                'patterns': [
                    r'\b(?:\d[ -]*?){13,16}\b',  # Most credit card formats
                ],
                'sensitivity': 'high'
            },
            'ssn': {
                'patterns': [
                    r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',  # SSN with optional separators
                ],
                'sensitivity': 'high'
            },
            'email': {
                'patterns': [
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                ],
                'sensitivity': 'medium'
            },
        }
    
    def analyze_content(self, content: Union[str, bytes], context: Optional[Dict] = None) -> Dict:
        """
        Analyze content for sensitive information.
        
        Args:
            content: The content to analyze (string or bytes)
            context: Additional context about the content (e.g., file path, user info)
            
        Returns:
            Dict containing analysis results and any findings
        """
        context = context or {}
        findings = []
        
        # Convert bytes to string if needed
        content_str = content.decode('utf-8', errors='ignore') if isinstance(content, bytes) else str(content)
        
        # Check for sensitive patterns
        for pattern_type, pattern_data in self.patterns.items():
            for pattern in pattern_data['patterns']:
                matches = re.finditer(pattern, content_str, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    findings.append({
                        'type': pattern_type,
                        'sensitivity': pattern_data['sensitivity'],
                        'match': match.group(0),
                        'start': match.start(),
                        'end': match.end(),
                        'context': context
                    })
        
        # Analyze file metadata if available
        file_metadata = self._analyze_file_metadata(content, context)
        
        # Generate content fingerprint
        content_fingerprint = self._generate_fingerprint(content)
        
        return {
            'findings': findings,
            'metadata': file_metadata,
            'fingerprint': content_fingerprint,
            'context': context
        }
    
    def _analyze_file_metadata(self, content: Union[str, bytes], context: Dict) -> Dict:
        """Analyze file metadata and type."""
        result = {}
        
        try:
            if isinstance(content, bytes):
                # Get MIME type
                result['mime_type'] = self.magic.from_buffer(content[:1024])
                
                # Calculate basic hashes
                result['md5'] = hashlib.md5(content).hexdigest()
                result['sha1'] = hashlib.sha1(content).hexdigest()
                result['sha256'] = hashlib.sha256(content).hexdigest()
                
                # File size
                result['size'] = len(content)
        
        except Exception as e:
            self.logger.error(f"Error analyzing file metadata: {str(e)}", exc_info=True)
        
        return result
    
    def _generate_fingerprint(self, content: Union[str, bytes]) -> str:
        """Generate a fingerprint for the content."""
        if isinstance(content, str):
            content = content.encode('utf-8', errors='ignore')
        return hashlib.sha256(content).hexdigest()
    
    def update_patterns(self, new_patterns: Dict):
        """
        Update the patterns used for content inspection.
        
        Args:
            new_patterns: Dictionary of pattern types and their definitions
        """
        self.patterns.update(new_patterns)
        self.logger.info(f"Updated DLP patterns. Total pattern types: {len(self.patterns)}")
    
    def add_custom_pattern(self, pattern_type: str, pattern: str, sensitivity: str = 'medium'):
        """
        Add a custom pattern for content inspection.
        
        Args:
            pattern_type: Type of pattern (e.g., 'credit_card', 'ssn')
            pattern: Regular expression pattern
            sensitivity: Sensitivity level ('low', 'medium', 'high')
        """
        if pattern_type not in self.patterns:
            self.patterns[pattern_type] = {'patterns': [], 'sensitivity': sensitivity}
        
        if pattern not in self.patterns[pattern_type]['patterns']:
            self.patterns[pattern_type]['patterns'].append(pattern)
            self.logger.info(f"Added new pattern for type: {pattern_type}")
