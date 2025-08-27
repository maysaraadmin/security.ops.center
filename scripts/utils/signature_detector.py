"""
Signature-based Detection for NIPS

This module implements signature-based detection for identifying known attack patterns
in network traffic. It supports multiple signature formats including Suricata and Snort rules.
"""

import os
import re
import logging
import gzip
import shutil
import tempfile
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Pattern, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import urllib.request
import json

# Third-party imports
try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger('nips.signature_detector')

@dataclass
class Signature:
    """Represents a detection signature."""
    sid: int
    gid: int = 1
    rev: int = 1
    action: str = 'alert'
    protocol: str = 'any'
    src_addr: str = 'any'
    src_port: str = 'any'
    direction: str = '->'
    dst_addr: str = 'any'
    dst_port: str = 'any'
    msg: str = ''
    metadata: Dict[str, Any] = field(default_factory=dict)
    content: List[Dict[str, Any]] = field(default_factory=list)
    pcre: List[Dict[str, Any]] = field(default_factory=list)
    flow: Dict[str, Any] = field(default_factory=dict)
    reference: Dict[str, List[str]] = field(default_factory=dict)
    classtype: str = 'unknown'
    priority: int = 3
    raw: str = ''
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert signature to dictionary."""
        return {
            'sid': self.sid,
            'gid': self.gid,
            'rev': self.rev,
            'action': self.action,
            'protocol': self.protocol,
            'src_addr': self.src_addr,
            'src_port': self.src_port,
            'direction': self.direction,
            'dst_addr': self.dst_addr,
            'dst_port': self.dst_port,
            'msg': self.msg,
            'metadata': self.metadata,
            'content': self.content,
            'pcre': self.pcre,
            'flow': self.flow,
            'reference': self.reference,
            'classtype': self.classtype,
            'priority': self.priority,
            'enabled': self.enabled
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Signature':
        """Create a Signature from a dictionary."""
        return cls(**data)
    
    def match(self, packet: Dict[str, Any]) -> bool:
        """Check if the signature matches the given packet."""
        # Check protocol
        if self.protocol != 'any' and self.protocol.lower() != packet.get('protocol', '').lower():
            return False
        
        # Check source address
        if not self._match_address(self.src_addr, packet.get('src_addr', '')):
            return False
        
        # Check source port
        if not self._match_port(self.src_port, packet.get('src_port', 0)):
            return False
        
        # Check destination address
        if not self._match_address(self.dst_addr, packet.get('dst_addr', '')):
            return False
        
        # Check destination port
        if not self._match_port(self.dst_port, packet.get('dst_port', 0)):
            return False
        
        # Check content matches
        if self.content:
            payload = packet.get('payload', b'')
            if not self._match_content(payload):
                return False
        
        # Check PCRE matches
        if self.pcre:
            payload = packet.get('payload', b'').decode('utf-8', errors='ignore')
            if not self._match_pcre(payload):
                return False
        
        return True
    
    def _match_address(self, pattern: str, addr: str) -> bool:
        """Check if an address matches the pattern."""
        if pattern == 'any':
            return True
        
        # Handle CIDR notation
        if '/' in pattern:
            try:
                import ipaddress
                network = ipaddress.ip_network(pattern, strict=False)
                ip = ipaddress.ip_address(addr)
                return ip in network
            except ValueError:
                return False
        
        # Handle negated addresses
        if pattern.startswith('!'):
            return addr != pattern[1:]
        
        # Handle IP lists
        if pattern.startswith('[') and pattern.endswith(']'):
            addrs = [a.strip() for a in pattern[1:-1].split(',')]
            return addr in addrs
        
        # Direct match
        return addr == pattern
    
    def _match_port(self, pattern: str, port: int) -> bool:
        """Check if a port matches the pattern."""
        if pattern == 'any':
            return True
        
        # Handle port ranges
        if ':' in pattern:
            try:
                start, end = map(int, pattern.split(':'))
                return start <= port <= end
            except (ValueError, IndexError):
                return False
        
        # Handle negated ports
        if pattern.startswith('!'):
            return port != int(pattern[1:])
        
        # Handle port lists
        if pattern.startswith('[') and pattern.endswith(']'):
            ports = [int(p.strip()) for p in pattern[1:-1].split(',')]
            return port in ports
        
        # Direct match
        return port == int(pattern)
    
    def _match_content(self, payload: bytes) -> bool:
        """Check if the payload matches content rules."""
        for content_rule in self.content:
            content = content_rule.get('content', b'')
            if not content:
                continue
                
            # Convert content to bytes if it's a string
            if isinstance(content, str):
                content = content.encode('utf-8')
            
            # Check if content is in payload
            if content not in payload:
                return False
            
            # Check for content modifiers
            if 'offset' in content_rule and content_rule['offset'] != 0:
                offset = content_rule['offset']
                if payload[offset:offset+len(content)] != content:
                    return False
            
            if 'depth' in content_rule:
                depth = content_rule['depth']
                if content not in payload[:depth]:
                    return False
            
            if 'distance' in content_rule and 'within' in content_rule:
                # More complex content matching with relative positioning
                # This is a simplified version
                distance = content_rule['distance']
                within = content_rule['within']
                
                # Find the previous content match
                prev_content = content_rule.get('previous_content')
                if prev_content:
                    if isinstance(prev_content, str):
                        prev_content = prev_content.encode('utf-8')
                    prev_pos = payload.find(prev_content)
                    if prev_pos == -1:
                        return False
                    
                    # Check if current content is within the specified range
                    search_start = prev_pos + len(prev_content) + distance
                    search_end = search_start + within
                    
                    if search_end > len(payload):
                        return False
                    
                    if content not in payload[search_start:search_end]:
                        return False
        
        return True
    
    def _match_pcre(self, payload: str) -> bool:
        """Check if the payload matches PCRE rules."""
        for pcre_rule in self.pcre:
            pattern = pcre_rule.get('pattern')
            if not pattern:
                continue
                
            # Compile the regex with appropriate flags
            flags = 0
            if pcre_rule.get('caseless', False):
                flags |= re.IGNORECASE
            if pcre_rule.get('dotall', False):
                flags |= re.DOTALL
            if pcre_rule.get('multiline', False):
                flags |= re.MULTILINE
                
            try:
                regex = re.compile(pattern, flags)
                if not regex.search(payload):
                    return False
            except re.error:
                logger.warning(f"Invalid PCRE pattern: {pattern}")
                return False
        
        return True

class SignatureDetector:
    """Signature-based detection engine for NIPS."""
    
    def __init__(self, rules_dir: str, update_url: Optional[str] = None):
        """Initialize the signature detector.
        
        Args:
            rules_dir: Directory containing signature rule files
            update_url: URL to fetch updated signatures from (optional)
        """
        self.rules_dir = Path(rules_dir)
        self.update_url = update_url
        self.signatures: Dict[Tuple[int, int], Signature] = {}
        self.enabled_signatures: Set[Tuple[int, int]] = set()
        self.signature_groups: Dict[str, Set[Tuple[int, int]]] = {}
        self.categories: Dict[str, Set[Tuple[int, int]]] = {}
        self.last_updated: Optional[datetime] = None
        self.signature_hashes: Dict[Tuple[int, int], str] = {}
        
        # Create rules directory if it doesn't exist
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Load signatures
        self.load_signatures()
        
        logger.info(f"Initialized signature detector with {len(self.signatures)} signatures")
    
    def load_signatures(self) -> int:
        """Load signatures from rule files in the rules directory.
        
        Returns:
            Number of signatures loaded
        """
        loaded = 0
        self.signatures.clear()
        self.enabled_signatures.clear()
        self.signature_groups.clear()
        self.categories.clear()
        
        # Load rules from all files in the rules directory
        for rule_file in self.rules_dir.glob('*.rules'):
            try:
                loaded += self._load_rule_file(rule_file)
            except Exception as e:
                logger.error(f"Error loading rule file {rule_file}: {e}")
        
        self.last_updated = datetime.now()
        logger.info(f"Loaded {loaded} signatures from {self.rules_dir}")
        return loaded
    
    def _load_rule_file(self, file_path: Path) -> int:
        """Load signatures from a single rule file.
        
        Args:
            file_path: Path to the rule file
            
        Returns:
            Number of signatures loaded from the file
        """
        if not file_path.is_file():
            logger.warning(f"Rule file not found: {file_path}")
            return 0
        
        loaded = 0
        file_hash = self._calculate_file_hash(file_path)
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                try:
                    # Parse the signature
                    signature = self._parse_signature(line)
                    if not signature:
                        continue
                    
                    # Add to signatures dictionary
                    key = (signature.gid, signature.sid)
                    self.signatures[key] = signature
                    
                    # Add to enabled signatures if not disabled
                    if signature.enabled:
                        self.enabled_signatures.add(key)
                    
                    # Add to categories
                    category = signature.metadata.get('category', 'uncategorized')
                    if category not in self.categories:
                        self.categories[category] = set()
                    self.categories[category].add(key)
                    
                    # Store file hash for change detection
                    self.signature_hashes[key] = file_hash
                    
                    loaded += 1
                    
                except Exception as e:
                    logger.warning(f"Error parsing signature: {line[:100]}... Error: {e}")
        
        return loaded
    
    def _parse_signature(self, rule_text: str) -> Optional[Signature]:
        """Parse a signature from a rule string.
        
        Args:
            rule_text: The rule text to parse
            
        Returns:
            Parsed Signature object or None if invalid
        """
        # Skip comments and empty lines
        rule_text = rule_text.strip()
        if not rule_text or rule_text.startswith('#'):
            return None
        
        # Handle disabled rules
        enabled = not rule_text.startswith('#')
        if not enabled:
            rule_text = rule_text[1:].lstrip()
        
        # Extract action
        action_end = rule_text.find(' ')
        if action_end == -1:
            return None
        
        action = rule_text[:action_end]
        rule_text = rule_text[action_end:].lstrip()
        
        # Extract protocol
        proto_end = rule_text.find(' ')
        if proto_end == -1:
            return None
        
        protocol = rule_text[:proto_end].lower()
        rule_text = rule_text[proto_end:].lstrip()
        
        # Extract source address and port
        src_addr, src_port, rule_text = self._parse_address_port(rule_text)
        if src_addr is None:
            return None
        
        # Extract direction
        if rule_text.startswith('->'):
            direction = '->'
            rule_text = rule_text[2:].lstrip()
        elif rule_text.startswith('<>'):
            direction = '<>'
            rule_text = rule_text[2:].lstrip()
        else:
            return None
        
        # Extract destination address and port
        dst_addr, dst_port, rule_text = self._parse_address_port(rule_text)
        if dst_addr is None:
            return None
        
        # The rest is options
        options = rule_text.strip(';').split(';')
        
        # Parse options
        msg = ''
        metadata = {}
        content_rules = []
        pcre_rules = []
        flow = {}
        reference = {}
        classtype = 'unknown'
        priority = 3
        sid = 0
        gid = 1
        rev = 1
        
        for opt in options:
            opt = opt.strip()
            if not opt:
                continue
            
            if ':' in opt:
                key, value = opt.split(':', 1)
                key = key.strip().lower()
                value = value.strip(' "')
                
                if key == 'msg':
                    msg = value
                elif key == 'sid':
                    sid = int(value)
                elif key == 'gid':
                    gid = int(value)
                elif key == 'rev':
                    rev = int(value)
                elif key == 'classtype':
                    classtype = value
                elif key == 'priority':
                    priority = int(value)
                elif key == 'metadata':
                    # Parse metadata (key1 value1, key2 value2, ...)
                    for meta_item in value.split(','):
                        meta_item = meta_item.strip()
                        if ' ' in meta_item:
                            meta_key, meta_value = meta_item.split(' ', 1)
                            metadata[meta_key] = meta_value
                elif key == 'reference':
                    # Parse reference (type, url)
                    ref_type, ref_url = value.split(',', 1)
                    ref_type = ref_type.strip()
                    ref_url = ref_url.strip()
                    if ref_type not in reference:
                        reference[ref_type] = []
                    reference[ref_type].append(ref_url)
                elif key == 'content':
                    # Parse content rule
                    content_rule = {'content': value}
                    
                    # Parse content modifiers
                    mod_start = value.find('|')
                    if mod_start != -1 and value.endswith('|'):
                        content_rule['content'] = value[1:-1]  # Remove pipes
                        
                        # Parse content modifiers
                        mods = value[mod_start+1:].split('|')
                        for mod in mods:
                            if not mod:
                                continue
                            
                            if mod[0] in ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'):
                                # Hex string
                                content_rule['hex'] = True
                            elif mod == 'nocase':
                                content_rule['nocase'] = True
                            elif mod == 'rawbytes':
                                content_rule['rawbytes'] = True
                            elif mod.startswith('offset:'):
                                content_rule['offset'] = int(mod[7:])
                            elif mod.startswith('depth:'):
                                content_rule['depth'] = int(mod[6:])
                            elif mod.startswith('distance:'):
                                content_rule['distance'] = int(mod[9:])
                            elif mod.startswith('within:'):
                                content_rule['within'] = int(mod[7:])
                    
                    content_rules.append(content_rule)
                elif key == 'pcre':
                    # Parse PCRE rule
                    pcre_rule = {'pattern': value}
                    
                    # Parse PCRE modifiers
                    mod_start = value.rfind('/')
                    if mod_start > 0:
                        pcre_rule['pattern'] = value[1:mod_start]  # Remove leading / and modifiers
                        modifiers = value[mod_start+1:]
                        
                        pcre_rule['caseless'] = 'i' in modifiers
                        pcre_rule['multiline'] = 'm' in modifiers
                        pcre_rule['dotall'] = 's' in modifiers
                        pcre_rule['extended'] = 'x' in modifiers
                        pcre_rule['ungreedy'] = 'U' in modifiers
                    
                    pcre_rules.append(pcre_rule)
                elif key == 'flow':
                    # Parse flow options (established, to_server, to_client, etc.)
                    flow_opts = value.split(',')
                    for opt in flow_opts:
                        opt = opt.strip()
                        if '|' in opt:
                            k, v = opt.split('|', 1)
                            flow[k] = v
                        else:
                            flow[opt] = True
        
        # Create and return the signature
        return Signature(
            sid=sid,
            gid=gid,
            rev=rev,
            action=action,
            protocol=protocol,
            src_addr=src_addr,
            src_port=src_port,
            direction=direction,
            dst_addr=dst_addr,
            dst_port=dst_port,
            msg=msg,
            metadata=metadata,
            content=content_rules,
            pcre=pcre_rules,
            flow=flow,
            reference=reference,
            classtype=classtype,
            priority=priority,
            raw=rule_text,
            enabled=enabled
        )
    
    def _parse_address_port(self, text: str) -> Tuple[Optional[str], Optional[str], str]:
        """Parse an address and port from rule text.
        
        Args:
            text: The text to parse
            
        Returns:
            Tuple of (address, port, remaining_text)
        """
        # Handle negated addresses
        negated = text.startswith('!')
        if negated:
            text = text[1:].lstrip()
        
        # Handle address groups
        if text.startswith('['):
            end = text.find(']')
            if end == -1:
                return None, None, text
            
            addr = text[1:end]
            text = text[end+1:].lstrip()
        else:
            # Single address
            space_pos = text.find(' ')
            if space_pos == -1:
                return None, None, text
            
            addr = text[:space_pos]
            text = text[space_pos:].lstrip()
        
        # Handle port if present
        port = 'any'
        if text.startswith(':'):
            text = text[1:].lstrip()
            
            if text.startswith('['):
                # Port list or range
                end = text.find(']')
                if end == -1:
                    return None, None, text
                
                port = text[1:end]
                text = text[end+1:].lstrip()
            else:
                # Single port or range
                space_pos = text.find(' ')
                if space_pos == -1:
                    return None, None, text
                
                port = text[:space_pos]
                text = text[space_pos:].lstrip()
        
        # Add negation back to address if needed
        if negated:
            addr = f'!{addr}'
        
        return addr, port, text
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate the SHA-256 hash of a file."""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def update_signatures(self, force: bool = False) -> bool:
        """Update signatures from the update URL.
        
        Args:
            force: Force update even if signatures are up to date
            
        Returns:
            True if updates were applied, False otherwise
        """
        if not self.update_url:
            logger.warning("No update URL configured")
            return False
        
        try:
            # Check if update is needed
            if not force and not self._check_for_updates():
                logger.info("Signatures are up to date")
                return False
            
            # Download and extract signatures
            logger.info(f"Downloading signatures from {self.update_url}")
            temp_dir = Path(tempfile.mkdtemp())
            try:
                # Download the file
                archive_path = temp_dir / 'signatures.tar.gz'
                urllib.request.urlretrieve(self.update_url, archive_path)
                
                # Extract the archive
                import tarfile
                with tarfile.open(archive_path, 'r:gz') as tar:
                    tar.extractall(temp_dir)
                
                # Copy rule files to the rules directory
                updated = False
                for rule_file in temp_dir.glob('**/*.rules'):
                    dest_file = self.rules_dir / rule_file.name
                    shutil.copy2(rule_file, dest_file)
                    logger.debug(f"Updated rule file: {dest_file}")
                    updated = True
                
                if not updated:
                    logger.warning("No rule files found in the update")
                    return False
                
                # Reload signatures
                self.load_signatures()
                logger.info("Signatures updated successfully")
                return True
                
            finally:
                # Clean up temporary directory
                shutil.rmtree(temp_dir, ignore_errors=True)
                
        except Exception as e:
            logger.error(f"Failed to update signatures: {e}")
            return False
    
    def _check_for_updates(self) -> bool:
        """Check if signature updates are available.
        
        Returns:
            True if updates are available, False otherwise
        """
        try:
            # Try to get the last modified time of the remote file
            req = urllib.request.Request(self.update_url, method='HEAD')
            with urllib.request.urlopen(req) as response:
                last_modified = response.headers.get('Last-Modified')
                if last_modified:
                    from email.utils import parsedate_to_datetime
                    remote_time = parsedate_to_datetime(last_modified)
                    if self.last_updated and remote_time <= self.last_updated:
                        return False
            return True
        except Exception as e:
            logger.warning(f"Failed to check for updates: {e}")
            return True  # Assume updates are available if we can't check
    
    def match(self, packet: Dict[str, Any]) -> List[Signature]:
        """Match a packet against all enabled signatures.
        
        Args:
            packet: The packet to match against
            
        Returns:
            List of matching signatures
        """
        matches = []
        
        for key in self.enabled_signatures:
            signature = self.signatures.get(key)
            if not signature:
                continue
                
            try:
                if signature.match(packet):
                    matches.append(signature)
            except Exception as e:
                logger.warning(f"Error matching signature {signature.sid}: {e}")
        
        return matches
    
    def enable_signature(self, gid: int, sid: int, enable: bool = True) -> bool:
        """Enable or disable a signature by GID and SID.
        
        Args:
            gid: The generator ID
            sid: The signature ID
            enable: Whether to enable or disable the signature
            
        Returns:
            True if the signature was found and updated, False otherwise
        """
        key = (gid, sid)
        if key not in self.signatures:
            return False
        
        if enable:
            self.enabled_signatures.add(key)
        elif key in self.enabled_signatures:
            self.enabled_signatures.remove(key)
        
        self.signatures[key].enabled = enable
        return True
    
    def enable_signature_group(self, group: str, enable: bool = True) -> int:
        """Enable or disable all signatures in a group.
        
        Args:
            group: The group name
            enable: Whether to enable or disable the signatures
            
        Returns:
            Number of signatures updated
        """
        updated = 0
        
        for key in self.signature_groups.get(group, set()):
            if key in self.signatures:
                self.signatures[key].enabled = enable
                if enable:
                    self.enabled_signatures.add(key)
                elif key in self.enabled_signatures:
                    self.enabled_signatures.remove(key)
                updated += 1
        
        return updated
    
    def enable_category(self, category: str, enable: bool = True) -> int:
        """Enable or disable all signatures in a category.
        
        Args:
            category: The category name
            enable: Whether to enable or disable the signatures
            
        Returns:
            Number of signatures updated
        """
        updated = 0
        
        for key in self.categories.get(category, set()):
            if key in self.signatures:
                self.signatures[key].enabled = enable
                if enable:
                    self.enabled_signatures.add(key)
                elif key in self.enabled_signatures:
                    self.enabled_signatures.remove(key)
                updated += 1
        
        return updated
    
    def get_signature(self, gid: int, sid: int) -> Optional[Signature]:
        """Get a signature by GID and SID.
        
        Args:
            gid: The generator ID
            sid: The signature ID
            
        Returns:
            The Signature object or None if not found
        """
        return self.signatures.get((gid, sid))
    
    def get_signatures(self, enabled_only: bool = False) -> List[Signature]:
        """Get all signatures.
        
        Args:
            enabled_only: If True, only return enabled signatures
            
        Returns:
            List of Signature objects
        """
        if enabled_only:
            return [self.signatures[key] for key in self.enabled_signatures 
                   if key in self.signatures]
        return list(self.signatures.values())
    
    def get_categories(self) -> List[str]:
        """Get all signature categories.
        
        Returns:
            List of category names
        """
        return list(self.categories.keys())
    
    def get_signatures_by_category(self, category: str) -> List[Signature]:
        """Get all signatures in a category.
        
        Args:
            category: The category name
            
        Returns:
            List of Signature objects in the category
        """
        return [self.signatures[key] for key in self.categories.get(category, []) 
               if key in self.signatures]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get signature detection statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_signatures': len(self.signatures),
            'enabled_signatures': len(self.enabled_signatures),
            'categories': len(self.categories),
            'last_updated': self.last_updated.isoformat() if self.last_updated else None
        }
