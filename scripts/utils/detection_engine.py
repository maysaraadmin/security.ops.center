"""
DLP Detection Engine - Identifies sensitive data patterns in content.
"""
import re
from typing import Dict, List, Optional, Tuple, Pattern, Callable, Any
import logging
from dataclasses import dataclass, field

@dataclass
class DLPRule:
    """Represents a DLP detection rule."""
    rule_id: str
    name: str
    description: str
    severity: str  # low, medium, high, critical
    patterns: List[Pattern]
    keywords: List[str] = field(default_factory=list)
    min_confidence: float = 0.8
    enabled: bool = True
    action: str = 'alert'  # alert, block, quarantine
    
    def match(self, content: str) -> Optional[Dict[str, Any]]:
        """
        Check if the content matches this DLP rule.
        
        Args:
            content: Content to check for sensitive data
            
        Returns:
            Match details if found, None otherwise
        """
        if not self.enabled:
            return None
            
        matched_patterns = []
        matched_keywords = []
        
        # Check patterns
        for pattern in self.patterns:
            if match := pattern.search(content):
                matched_patterns.append({
                    'pattern': pattern.pattern,
                    'match': match.group(0),
                    'start': match.start(),
                    'end': match.end()
                })
        
        # Check keywords
        content_lower = content.lower()
        for keyword in self.keywords:
            if keyword.lower() in content_lower:
                matched_keywords.append(keyword)
        
        # Determine confidence
        confidence = 0.0
        if matched_patterns and matched_keywords:
            confidence = 1.0  # Both patterns and keywords matched
        elif matched_patterns:
            confidence = 0.8  # Only patterns matched
        elif matched_keywords:
            confidence = 0.5  # Only keywords matched
        
        if confidence >= self.min_confidence:
            return {
                'rule_id': self.rule_id,
                'name': self.name,
                'description': self.description,
                'severity': self.severity,
                'confidence': min(1.0, confidence * 1.1),  # Slight boost
                'action': self.action,
                'patterns': matched_patterns,
                'keywords': matched_keywords,
                'content_preview': self._get_content_preview(content, matched_patterns)
            }
        return None
    
    def _get_content_preview(self, content: str, matches: List[Dict]) -> str:
        """Generate a preview of the content with matches highlighted."""
        if not matches:
            return content[:200] + ('...' if len(content) > 200 else '')
        
        # Get the first match for preview
        first_match = matches[0]
        start = max(0, first_match['start'] - 50)
        end = min(len(content), first_match['end'] + 50)
        preview = content[start:end]
        
        if start > 0:
            preview = '...' + preview
        if end < len(content):
            preview = preview + '...'
            
        return preview

class DLPDecoder:
    """Helper class for decoding different content types."""
    
    @staticmethod
    def decode_text(content: bytes) -> str:
        """Decode text content with appropriate encoding detection."""
        # Try UTF-8 first, then fall back to other encodings
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                continue
        # If all else fails, use replace strategy
        return content.decode('utf-8', errors='replace')
    
    @staticmethod
    def is_binary(content: bytes) -> bool:
        """Check if content appears to be binary."""
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
        return bool(content.translate(None, text_chars))

class DLPDetectionEngine:
    """Core DLP detection engine that scans content for sensitive data."""
    
    def __init__(self):
        self.rules: Dict[str, DLPRule] = {}
        self.logger = logging.getLogger(__name__)
        self._setup_default_rules()
    
    def add_rule(self, rule: DLPRule) -> None:
        """Add a DLP rule to the engine."""
        self.rules[rule.rule_id] = rule
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a DLP rule by ID."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False
    
    def scan_content(self, content: bytes, content_type: str = None) -> List[Dict]:
        """
        Scan content for sensitive data.
        
        Args:
            content: The content to scan (bytes)
            content_type: Optional content type hint (e.g., 'text/plain', 'application/pdf')
            
        Returns:
            List of matches with details
        """
        results = []
        
        try:
            # Handle binary content
            if DLPDecoder.is_binary(content):
                # For now, just check if we can extract text
                # In a real implementation, you'd use appropriate libraries for different file types
                try:
                    text_content = DLPDecoder.decode_text(content)
                except Exception as e:
                    self.logger.warning(f"Failed to decode binary content: {e}")
                    return results
            else:
                text_content = DLPDecoder.decode_text(content)
            
            # Check against all rules
            for rule in self.rules.values():
                if match := rule.match(text_content):
                    results.append(match)
            
        except Exception as e:
            self.logger.error(f"Error scanning content: {e}", exc_info=True)
        
        return results
    
    def _setup_default_rules(self):
        """Initialize the engine with some common DLP rules."""
        # Credit card numbers
        self.add_rule(DLPRule(
            rule_id="dlp-ccn-001",
            name="Credit Card Number",
            description="Detects credit card numbers (Visa, MasterCard, Amex, etc.)",
            severity="high",
            patterns=[
                re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b'),
            ],
            keywords=["card number", "credit card", "visa", "mastercard", "amex", "discover"],
            action="block"
        ))
        
        # Social Security Numbers (US)
        self.add_rule(DLPRule(
            rule_id="dlp-ssn-001",
            name="US Social Security Number",
            description="Detects US Social Security Numbers",
            severity="high",
            patterns=[
                re.compile(r'\b(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b'),
                re.compile(r'\b(?!000|666)[0-8][0-9]{2}\s?(?!00)[0-9]{2}\s?(?!0000)[0-9]{4}\b'),
            ],
            keywords=["ssn", "social security", "ss#", "ssn#"],
            action="block"
        ))
        
        # Email addresses
        self.add_rule(DLPRule(
            rule_id="dlp-email-001",
            name="Email Address",
            description="Detects email addresses",
            severity="low",
            patterns=[
                re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            ],
            action="alert"
        ))
        
        # API Keys
        self.add_rule(DLPRule(
            rule_id="dlp-apikey-001",
            name="API Keys",
            description="Detects common API key patterns",
            severity="high",
            patterns=[
                re.compile(r'\b[A-Za-z0-9]{32}\b'),  # MD5-like
                re.compile(r'\b[A-Za-z0-9]{40}\b'),  # SHA-1
                re.compile(r'\b[A-Za-z0-9]{64}\b'),  # SHA-256
                re.compile(r'sk_(live|test)_[A-Za-z0-9]{24}'),  # Stripe
                re.compile(r'(?i)AIza[0-9A-Za-z\\-_]{35}'),  # Google API key
            ],
            keywords=["api_key", "api-key", "apikey", "secret_key", "private_key"],
            action="block"
        ))
        
        # Passwords in config files
        self.add_rule(DLPRule(
            rule_id="dlp-password-001",
            name="Passwords in Config",
            description="Detects password fields in configuration files",
            severity="critical",
            patterns=[],
            keywords=[
                "password=", "passwd=", "pwd=", "pass: ", 
                "password: ", "passwd: ", "pwd: ",
                '"password":', '"passwd":', '"pwd":',
                "'password':", "'passwd':", "'pwd':"
            ],
            action="block"
        ))
