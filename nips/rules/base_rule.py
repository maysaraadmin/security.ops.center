"""
Base Rule System for NIPS Signature-Based Detection
"""
import re
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Pattern, Any, Union
import ipaddress
import hashlib

class RuleAction(Enum):
    """Actions to take when a rule matches."""
    ALERT = "alert"
    DROP = "drop"
    REJECT = "reject"
    PASS = "pass"
    LOG = "log"

class Protocol(Enum):
    """Network protocols supported by the rule system."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    IP = "ip"
    HTTP = "http"
    DNS = "dns"
    FTP = "ftp"
    SMTP = "smtp"
    ANY = "any"

class RuleDirection(Enum):
    """Traffic direction for rule matching."""
    ANY = "<->"
    TO_SERVER = "->"
    FROM_SERVER = "<-"

@dataclass
class RuleOptions:
    """Options for rule matching behavior."""
    nocase: bool = False
    depth: Optional[int] = None
    offset: int = 0
    distance: int = 0
    within: int = 0
    http_uri: bool = False
    http_header: bool = False
    http_cookie: bool = False
    http_raw_uri: bool = False
    http_raw_header: bool = False
    http_raw_cookie: bool = False
    http_method: bool = False
    http_client_body: bool = False
    http_server_body: bool = False
    ssl_cert: bool = False
    flow: Optional[Dict[str, bool]] = None
    threshold: Optional[Dict[str, Union[int, str]]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    reference: List[Dict[str, str]] = field(default_factory=list)
    classtype: Optional[str] = None
    priority: int = 1
    sid: Optional[int] = None
    rev: int = 1
    msg: str = ""

@dataclass
class SignatureRule:
    """A signature-based detection rule."""
    action: RuleAction
    protocol: Protocol
    source: str
    source_port: str
    direction: RuleDirection
    destination: str
    destination_port: str
    options: RuleOptions
    raw_rule: str = ""
    
    def __post_init__(self):
        # Generate a unique ID if not provided
        if not hasattr(self, 'id') or not self.id:
            self.id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate a unique ID for the rule."""
        rule_str = f"{self.action.value} {self.protocol.value} {self.source} {self.source_port} {self.direction.value} {self.destination} {self.destination_port}"
        return hashlib.sha256(rule_str.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary for serialization."""
        return {
            'id': self.id,
            'action': self.action.value,
            'protocol': self.protocol.value,
            'source': self.source,
            'source_port': self.source_port,
            'direction': self.direction.value,
            'destination': self.destination,
            'destination_port': self.destination_port,
            'options': {
                'nocase': self.options.nocase,
                'depth': self.options.depth,
                'offset': self.options.offset,
                'distance': self.options.distance,
                'within': self.options.within,
                'http_uri': self.options.http_uri,
                'http_header': self.options.http_header,
                'http_cookie': self.options.http_cookie,
                'http_raw_uri': self.options.http_raw_uri,
                'http_raw_header': self.options.http_raw_header,
                'http_raw_cookie': self.options.http_raw_cookie,
                'http_method': self.options.http_method,
                'http_client_body': self.options.http_client_body,
                'http_server_body': self.options.http_server_body,
                'ssl_cert': self.options.ssl_cert,
                'flow': self.options.flow or {},
                'threshold': self.options.threshold or {},
                'metadata': self.options.metadata,
                'reference': self.options.reference,
                'classtype': self.options.classtype,
                'priority': self.options.priority,
                'sid': self.options.sid,
                'rev': self.options.rev,
                'msg': self.options.msg
            },
            'raw_rule': self.raw_rule
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SignatureRule':
        """Create a rule from a dictionary."""
        options_data = data.get('options', {})
        options = RuleOptions(
            nocase=options_data.get('nocase', False),
            depth=options_data.get('depth'),
            offset=options_data.get('offset', 0),
            distance=options_data.get('distance', 0),
            within=options_data.get('within', 0),
            http_uri=options_data.get('http_uri', False),
            http_header=options_data.get('http_header', False),
            http_cookie=options_data.get('http_cookie', False),
            http_raw_uri=options_data.get('http_raw_uri', False),
            http_raw_header=options_data.get('http_raw_header', False),
            http_raw_cookie=options_data.get('http_raw_cookie', False),
            http_method=options_data.get('http_method', False),
            http_client_body=options_data.get('http_client_body', False),
            http_server_body=options_data.get('http_server_body', False),
            ssl_cert=options_data.get('ssl_cert', False),
            flow=options_data.get('flow'),
            threshold=options_data.get('threshold'),
            metadata=options_data.get('metadata', {}),
            reference=options_data.get('reference', []),
            classtype=options_data.get('classtype'),
            priority=options_data.get('priority', 1),
            sid=options_data.get('sid'),
            rev=options_data.get('rev', 1),
            msg=options_data.get('msg', '')
        )
        
        rule = cls(
            action=RuleAction(data['action']),
            protocol=Protocol(data['protocol']),
            source=data['source'],
            source_port=data['source_port'],
            direction=RuleDirection(data.get('direction', RuleDirection.ANY.value)),
            destination=data['destination'],
            destination_port=data['destination_port'],
            options=options,
            raw_rule=data.get('raw_rule', '')
        )
        
        # Set the ID if provided
        if 'id' in data:
            rule.id = data['id']
            
        return rule

class RuleParser:
    """Parser for Snort-like rule syntax."""
    
    @staticmethod
    def parse_rule(rule_str: str) -> SignatureRule:
        """Parse a Snort-like rule string into a SignatureRule object."""
        # Basic rule format:
        # action protocol src_ip src_port direction dst_ip dst_port (options)
        rule_parts = rule_str.strip().split(' ', 7)
        
        if len(rule_parts) < 7:
            raise ValueError(f"Invalid rule format: {rule_str}")
            
        action_str, protocol_str, src, sport, direction_str, dst, dport = rule_parts[:7]
        options_str = rule_parts[7] if len(rule_parts) > 7 else ""
        
        # Parse action
        try:
            action = RuleAction(action_str.lower())
        except ValueError:
            raise ValueError(f"Invalid action: {action_str}")
        
        # Parse protocol
        try:
            protocol = Protocol(protocol_str.lower())
        except ValueError:
            raise ValueError(f"Invalid protocol: {protocol_str}")
        
        # Parse direction
        try:
            direction = RuleDirection(direction_str)
        except ValueError:
            raise ValueError(f"Invalid direction: {direction_str}")
        
        # Parse options
        options = RuleParser._parse_options(options_str)
        
        # Create and return the rule
        rule = SignatureRule(
            action=action,
            protocol=protocol,
            source=src,
            source_port=sport,
            direction=direction,
            destination=dst,
            destination_port=dport,
            options=options,
            raw_rule=rule_str
        )
        
        return rule
    
    @staticmethod
    def _parse_options(options_str: str) -> RuleOptions:
        """Parse rule options string into a RuleOptions object."""
        options = RuleOptions()
        
        if not options_str or not options_str.startswith('(') or not options_str.endswith(';'):
            return options
            
        # Remove parentheses and split into key-value pairs
        options_str = options_str[1:-1].strip()
        option_pairs = [opt.strip() for opt in options_str.split(';') if opt.strip()]
        
        for pair in option_pairs:
            if ':' in pair:
                key, value = pair.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'msg':
                    options.msg = value.strip('"')
                elif key == 'classtype':
                    options.classtype = value
                elif key == 'sid':
                    try:
                        options.sid = int(value)
                    except ValueError:
                        pass
                elif key == 'rev':
                    try:
                        options.rev = int(value)
                    except ValueError:
                        pass
                elif key == 'priority':
                    try:
                        options.priority = int(value)
                    except ValueError:
                        pass
                elif key == 'metadata':
                    options.metadata = json.loads(value)
                elif key == 'reference':
                    ref_parts = value.split(',', 1)
                    if len(ref_parts) == 2:
                        ref_type, ref_value = ref_parts
                        options.reference.append({
                            'type': ref_type.strip(),
                            'value': ref_value.strip()
                        })
            else:
                # Boolean options
                key = pair.strip().lower()
                if key == 'nocase':
                    options.nocase = True
                elif key == 'http_uri':
                    options.http_uri = True
                elif key == 'http_header':
                    options.http_header = True
                elif key == 'http_cookie':
                    options.http_cookie = True
                elif key == 'http_raw_uri':
                    options.http_raw_uri = True
                elif key == 'http_raw_header':
                    options.http_raw_header = True
                elif key == 'http_raw_cookie':
                    options.http_raw_cookie = True
                elif key == 'http_method':
                    options.http_method = True
                elif key == 'http_client_body':
                    options.http_client_body = True
                elif key == 'http_server_body':
                    options.http_server_body = True
                elif key == 'ssl_cert':
                    options.ssl_cert = True
        
        return options
