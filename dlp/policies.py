"""
DLP Policy Engine

Defines and manages data protection policies and patterns.
"""
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Pattern, Union, Any, Callable
import json
import yaml

class MatchType(Enum):
    """Types of pattern matching."""
    REGEX = "regex"
    KEYWORD = "keyword"
    ML_MODEL = "ml_model"
    EXACT = "exact"
    FUZZY = "fuzzy"

@dataclass
class DataPattern:
    """Pattern for identifying sensitive data."""
    name: str
    description: str = ""
    patterns: List[Union[str, Pattern]] = field(default_factory=list)
    match_type: MatchType = MatchType.REGEX
    data_type: str = "custom"
    confidence: float = 0.8
    required_matches: int = 1
    proximity: Optional[int] = None  # For multi-pattern matching
    context_required: List[str] = field(default_factory=list)
    exceptions: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        # Compile regex patterns if not already compiled
        if self.match_type == MatchType.REGEX:
            compiled_patterns = []
            for pattern in self.patterns:
                if isinstance(pattern, str):
                    compiled_patterns.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
                else:
                    compiled_patterns.append(pattern)
            self.patterns = compiled_patterns

class PolicyAction(Enum):
    """Actions to take when a policy is matched."""
    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    REDACT = "redact"
    AUDIT = "audit"
    NOTIFY = "notify"

@dataclass
class PolicyRule:
    """A single DLP policy rule."""
    id: str
    name: str
    description: str = ""
    priority: int = 0
    enabled: bool = True
    patterns: List[Union[str, DataPattern]] = field(default_factory=list)
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    actions: List[Union[str, PolicyAction]] = field(default_factory=list)
    scope: Dict[str, Any] = field(default_factory=dict)
    
    def matches(self, content: str, metadata: Dict[str, Any]) -> bool:
        """Check if content matches this policy."""
        # Check scope conditions (e.g., file type, location)
        if not self._matches_scope(metadata):
            return False
            
        # Check conditions
        if not self._check_conditions(metadata):
            return False
            
        # Check patterns
        return self._matches_patterns(content)
    
    def _matches_scope(self, metadata: Dict[str, Any]) -> bool:
        """Check if metadata matches policy scope."""
        for key, value in self.scope.items():
            if key not in metadata or metadata[key] != value:
                return False
        return True
    
    def _check_conditions(self, metadata: Dict[str, Any]) -> bool:
        """Evaluate policy conditions against metadata."""
        # This is a simplified implementation
        # In practice, you'd want a more robust condition evaluation engine
        for condition in self.conditions:
            field = condition.get('field')
            operator = condition.get('op')
            value = condition.get('value')
            
            if field not in metadata:
                return False
                
            actual_value = metadata[field]
            
            if operator == 'equals' and actual_value != value:
                return False
            elif operator == 'contains' and value not in str(actual_value):
                return False
            # Add more operators as needed
                
        return True
    
    def _matches_patterns(self, content: str) -> bool:
        """Check if content matches any of the policy patterns."""
        if not self.patterns:
            return False
            
        for pattern in self.patterns:
            if isinstance(pattern, str):
                # Simple string matching
                if pattern.lower() in content.lower():
                    return True
            elif isinstance(pattern, DataPattern):
                # Use the DataPattern's matching logic
                if pattern.match_type == MatchType.REGEX:
                    for regex in pattern.patterns:
                        if regex.search(content):
                            return True
                # Add other match types as needed
                
        return False

class PolicyEngine:
    """Manages and evaluates DLP policies."""
    
    def __init__(self):
        self.policies: List[PolicyRule] = []
        self.patterns: Dict[str, DataPattern] = {}
        
    def add_policy(self, policy: Union[PolicyRule, Dict]) -> None:
        """Add a policy to the engine."""
        if isinstance(policy, dict):
            policy = self._create_policy_from_dict(policy)
        self.policies.append(policy)
    
    def add_policies_from_file(self, file_path: str) -> None:
        """Load policies from a JSON or YAML file."""
        with open(file_path, 'r') as f:
            if file_path.endswith('.json'):
                policies_data = json.load(f)
            else:  # Assume YAML
                policies_data = yaml.safe_load(f)
                
        if isinstance(policies_data, list):
            for policy_data in policies_data:
                self.add_policy(policy_data)
        else:
            self.add_policy(policies_data)
    
    def add_pattern(self, pattern: Union[DataPattern, Dict]) -> None:
        """Add a data pattern to the engine."""
        if isinstance(pattern, dict):
            pattern = DataPattern(**pattern)
        self.patterns[pattern.name] = pattern
    
    def evaluate(self, content: str, metadata: Optional[Dict] = None) -> List[Dict]:
        """
        Evaluate content against all policies.
        
        Returns:
            List of dictionaries with policy matches and actions
        """
        if metadata is None:
            metadata = {}
            
        matches = []
        
        for policy in sorted(self.policies, key=lambda p: p.priority, reverse=True):
            if not policy.enabled:
                continue
                
            if policy.matches(content, metadata):
                match = {
                    'policy_id': policy.id,
                    'policy_name': policy.name,
                    'actions': [a.value if isinstance(a, PolicyAction) else a 
                              for a in policy.actions],
                    'metadata': {
                        'matched_at': 'content',  # or specific location
                        'confidence': 0.9,  # Would be calculated
                        'context': content[:200]  # Preview of matched content
                    }
                }
                matches.append(match)
                
                # If policy is high priority, we might want to stop after first match
                if policy.priority >= 90:  # Arbitrary threshold
                    break
                    
        return matches
    
    def _create_policy_from_dict(self, data: Dict) -> PolicyRule:
        """Create a PolicyRule from a dictionary."""
        # Convert action strings to enums
        actions = []
        for action in data.get('actions', []):
            if isinstance(action, str):
                try:
                    actions.append(PolicyAction(action.lower()))
                except ValueError:
                    actions.append(action)  # Keep as string if not a standard action
            else:
                actions.append(action)
        
        # Convert pattern names to DataPattern objects
        patterns = []
        for pattern in data.get('patterns', []):
            if isinstance(pattern, str) and pattern in self.patterns:
                patterns.append(self.patterns[pattern])
            else:
                patterns.append(pattern)
        
        return PolicyRule(
            id=data['id'],
            name=data.get('name', ''),
            description=data.get('description', ''),
            priority=data.get('priority', 0),
            enabled=data.get('enabled', True),
            patterns=patterns,
            conditions=data.get('conditions', []),
            actions=actions,
            scope=data.get('scope', {})
        )

def load_standard_patterns() -> Dict[str, DataPattern]:
    """Load common data patterns for PII, PCI, PHI, etc."""
    patterns = {}
    
    # Credit Card Numbers (simplified)
    patterns['credit_card'] = DataPattern(
        name="credit_card",
        description="Credit card numbers (Visa, MasterCard, Amex, etc.)",
        patterns=[
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b',
            r'\b(?:4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4})\b',
        ],
        data_type="pci",
        confidence=0.95
    )
    
    # Social Security Numbers (US)
    patterns['ssn'] = DataPattern(
        name="ssn",
        description="US Social Security Numbers",
        patterns=[
            r'\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b',
            r'\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b'
        ],
        data_type="pii",
        confidence=0.9
    )
    
    # Add more standard patterns as needed...
    
    return patterns
