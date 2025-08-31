"""
Log Parser and Normalizer for SIEM

This module provides functionality to parse and normalize log data from various sources
into a common schema for the SIEM.
"""
import re
import json
import logging
import ipaddress
from typing import Dict, List, Optional, Any, Union, Callable, Pattern, Tuple
from datetime import datetime
from enum import Enum

logger = logging.getLogger('siem.parser')

class LogLevel(Enum):
    """Standard log levels for normalized events."""
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7

class EventOutcome(Enum):
    """Standard event outcomes for normalized events."""
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"

class LogParser:
    """Parses and normalizes log data into a common schema."""
    
    # Common field mappings for different log types
    COMMON_FIELD_MAPPINGS = {
        # Timestamp fields
        'timestamp': [
            '@timestamp', 'timestamp', 'time', 'datetime', 'date',
            'event_time', 'eventtime', 'log_timestamp'
        ],
        # Source IP fields
        'source_ip': [
            'src_ip', 'source_ip', 'sourceaddress', 'source_address',
            'client_ip', 'clientip', 'src', 'ip_src', 'source'
        ],
        # Destination IP fields
        'destination_ip': [
            'dst_ip', 'destination_ip', 'dest_ip', 'destinationaddress',
            'destination_address', 'dest', 'ip_dst', 'destination'
        ],
        # Username fields
        'user_name': [
            'user', 'username', 'user_name', 'userid', 'user_id',
            'account_name', 'accountname', 'login'
        ],
        # Event name/type fields
        'event_name': [
            'event_name', 'eventname', 'event_type', 'eventtype',
            'name', 'type', 'event', 'action'
        ],
        # Event outcome fields
        'event_outcome': [
            'outcome', 'result', 'status', 'event_outcome', 'action'
        ]
    }
    
    # Common patterns for extracting data from log messages
    COMMON_PATTERNS = {
        'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|::',
        'mac': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
        'url': r'https?://[^\s/$.?#].[^\s]*',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'cve': r'\bCVE-\d{4}-\d{4,}\b',
        'http_method': r'\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\b',
        'http_status': r'\b\d{3}\b',
        'port': r'\b\d{1,5}\b',
    }
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the log parser.
        
        Args:
            config: Configuration dictionary with parser settings
        """
        self.config = config or {}
        self.rules = self._load_rules()
        self.field_mappings = self._init_field_mappings()
        self.patterns = self._init_patterns()
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load parsing and normalization rules."""
        # Default rules can be overridden by config
        default_rules = [
            # Windows Event Log rules
            {
                'name': 'windows_security_4624',
                'description': 'Windows Security Event 4624 - Successful logon',
                'conditions': [
                    {'field': 'event_id', 'op': 'equals', 'value': 4624},
                    {'field': 'log_name', 'op': 'equals', 'value': 'Security'}
                ],
                'actions': [
                    {'action': 'set', 'field': 'event_outcome', 'value': 'success'},
                    {'action': 'set', 'field': 'event_type', 'value': 'authentication'},
                    {'action': 'set', 'field': 'event_category', 'value': 'logon'}
                ]
            },
            # Add more default rules here
        ]
        
        # Merge with rules from config
        return self.config.get('rules', []) + default_rules
    
    def _init_field_mappings(self) -> Dict[str, List[str]]:
        """Initialize field mappings from config."""
        mappings = {}
        # Start with common mappings
        for field, aliases in self.COMMON_FIELD_MAPPINGS.items():
            mappings[field] = list(aliases)  # Make a copy
        
        # Add/override with config mappings
        if 'field_mappings' in self.config:
            for field, aliases in self.config['field_mappings'].items():
                if field in mappings:
                    mappings[field].extend(aliases)
                else:
                    mappings[field] = list(aliases)
        
        return mappings
    
    def _init_patterns(self) -> Dict[str, Pattern]:
        """Compile regex patterns."""
        patterns = {}
        # Add common patterns
        for name, pattern in self.COMMON_PATTERNS.items():
            try:
                patterns[name] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                logger.warning(f"Invalid regex pattern for {name}: {e}")
        
        # Add custom patterns from config
        if 'patterns' in self.config:
            for name, pattern in self.config['patterns'].items():
                try:
                    patterns[name] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    logger.warning(f"Invalid custom regex pattern {name}: {e}")
        
        return patterns
    
    def parse(self, log_data: Union[Dict[str, Any], str, bytes]) -> Dict[str, Any]:
        """Parse a log entry into a normalized format.
        
        Args:
            log_data: The log data to parse (dict, JSON string, or bytes)
            
        Returns:
            Dict containing the normalized log data
        """
        # Convert input to a dictionary if it's a string or bytes
        if isinstance(log_data, (str, bytes)):
            try:
                if isinstance(log_data, bytes):
                    log_data = log_data.decode('utf-8', errors='replace')
                # Try to parse as JSON first
                try:
                    log_data = json.loads(log_data)
                except json.JSONDecodeError:
                    # If not JSON, treat as raw message
                    log_data = {'message': log_data}
            except Exception as e:
                logger.error(f"Error parsing log data: {e}", exc_info=True)
                return {'error': str(e), 'raw': str(log_data)[:1000] + '...'}
        
        # Start with the original data
        normalized = dict(log_data)
        
        # Apply field mappings
        self._apply_field_mappings(normalized)
        
        # Apply parsing rules
        self._apply_rules(normalized)
        
        # Extract common patterns from message if it exists
        if 'message' in normalized and isinstance(normalized['message'], str):
            self._extract_patterns(normalized)
        
        # Add metadata
        self._add_metadata(normalized)
        
        return normalized
    
    def _apply_field_mappings(self, data: Dict[str, Any]) -> None:
        """Apply field mappings to the data."""
        # Create a case-insensitive mapping of all field names
        field_map = {}
        for target, sources in self.field_mappings.items():
            for src in sources:
                field_map[src.lower()] = target
        
        # Process each field in the data
        for field in list(data.keys()):
            if field.lower() in field_map:
                target = field_map[field.lower()]
                if target != field:  # Only move if the names are different
                    if target not in data:  # Don't overwrite existing target fields
                        data[target] = data[field]
                    del data[field]
    
    def _apply_rules(self, data: Dict[str, Any]) -> None:
        """Apply parsing and normalization rules to the data."""
        for rule in self.rules:
            try:
                if self._matches_conditions(rule.get('conditions', []), data):
                    self._apply_actions(rule.get('actions', []), data)
            except Exception as e:
                logger.error(f"Error applying rule {rule.get('name', 'unnamed')}: {e}", exc_info=True)
    
    def _matches_conditions(self, conditions: List[Dict[str, Any]], data: Dict[str, Any]) -> bool:
        """Check if the data matches all conditions."""
        for condition in conditions:
            field = condition.get('field')
            op = condition.get('op', 'equals')
            value = condition.get('value')
            
            # Skip if field doesn't exist (unless using exists:false)
            if field not in data:
                if op == 'not_exists' or (op == 'not_equals' and value is None):
                    continue
                return False
            
            field_value = data[field]
            
            # Apply the operator
            if op == 'equals':
                if field_value != value:
                    return False
            elif op == 'not_equals':
                if field_value == value:
                    return False
            elif op == 'contains':
                if value not in str(field_value):
                    return False
            elif op == 'not_contains':
                if value in str(field_value):
                    return False
            elif op == 'exists':
                # Field already exists (we checked above)
                pass
            elif op == 'not_exists':
                return False
            elif op == 'matches':
                if not re.search(str(value), str(field_value)):
                    return False
            elif op == 'greater_than':
                try:
                    if not (float(field_value) > float(value)):
                        return False
                except (ValueError, TypeError):
                    return False
            elif op == 'less_than':
                try:
                    if not (float(field_value) < float(value)):
                        return False
                except (ValueError, TypeError):
                    return False
            else:
                logger.warning(f"Unknown operator: {op}")
                return False
        
        return True
    
    def _apply_actions(self, actions: List[Dict[str, Any]], data: Dict[str, Any]) -> None:
        """Apply actions to the data."""
        for action in actions:
            action_type = action.get('action')
            field = action.get('field')
            value = action.get('value')
            
            if action_type == 'set':
                if field and value is not None:
                    data[field] = value
            elif action_type == 'copy':
                if field in data and value and value not in data:
                    data[value] = data[field]
            elif action_type == 'rename':
                if field in data and value and value != field:
                    data[value] = data[field]
                    del data[field]
            elif action_type == 'delete':
                if field in data:
                    del data[field]
            elif action_type == 'add_tag':
                if 'tags' not in data:
                    data['tags'] = []
                if value and value not in data['tags']:
                    data['tags'].append(value)
            elif action_type == 'remove_tag':
                if 'tags' in data and value in data['tags']:
                    data['tags'].remove(value)
    
    def _extract_patterns(self, data: Dict[str, Any]) -> None:
        """Extract common patterns from the message field."""
        message = data['message']
        
        # Initialize extracted fields if they don't exist
        if 'extracted' not in data:
            data['extracted'] = {}
        
        # Extract known patterns
        for name, pattern in self.patterns.items():
            matches = pattern.findall(message)
            if matches:
                if name not in data['extracted']:
                    data['extracted'][name] = []
                
                for match in matches:
                    if match not in data['extracted'][name]:
                        data['extracted'][name].append(match)
    
    def _add_metadata(self, data: Dict[str, Any]) -> None:
        """Add metadata to the normalized event."""
        # Add timestamp if not present
        if '@timestamp' not in data:
            data['@timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Add event ID if not present
        if 'event_id' not in data and 'event_id' in data.get('extracted', {}):
            data['event_id'] = data['extracted']['event_id'][0]
        
        # Add source and destination IPs to network object if they exist
        if 'source_ip' in data or 'destination_ip' in data:
            data.setdefault('network', {})
            if 'source_ip' in data:
                data['network']['source_ip'] = data['source_ip']
            if 'destination_ip' in data:
                data['network']['destination_ip'] = data['destination_ip']
        
        # Add user info to user object if it exists
        if 'user_name' in data:
            data.setdefault('user', {})
            data['user']['name'] = data['user_name']
        
        # Add event category if not present
        if 'event_category' not in data:
            # Try to infer category from event type
            if 'event_type' in data:
                event_type = data['event_type'].lower()
                if 'auth' in event_type or 'login' in event_type or 'logon' in event_type:
                    data['event_category'] = 'authentication'
                elif 'network' in event_type or 'traffic' in event_type:
                    data['event_category'] = 'network'
                elif 'file' in event_type or 'document' in event_type:
                    data['event_category'] = 'file'
                elif 'malware' in event_type or 'virus' in event_type or 'threat' in event_type:
                    data['event_category'] = 'threat'
                else:
                    data['event_category'] = 'general'
            else:
                data['event_category'] = 'unknown'
        
        # Add event severity if not present
        if 'severity' not in data:
            if 'event_outcome' in data and data['event_outcome'] == 'failure':
                data['severity'] = 'high'
            else:
                data['severity'] = 'info'
        
        # Add processing timestamp
        data['@timestamp_processed'] = datetime.utcnow().isoformat() + 'Z'

# Example usage
if __name__ == "__main__":
    # Example log data
    log_entry = {
        "timestamp": "2023-04-01T12:34:56Z",
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "user": "jdoe",
        "event_id": 4624,
        "log_name": "Security",
        "message": "Successful logon for user jdoe from 192.168.1.100 to 8.8.8.8 via HTTPS"
    }
    
    # Create a parser with default configuration
    parser = LogParser()
    
    # Parse the log entry
    normalized = parser.parse(log_entry)
    
    # Print the normalized result
    print("Original:", json.dumps(log_entry, indent=2))
    print("\nNormalized:", json.dumps(normalized, indent=2))
