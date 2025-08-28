"""
Enhanced File-based log collector for SIEM.
Collects and parses logs from files and directories with support for multiple formats.
"""
import os
import time
import json
import re
import gzip
import bz2
import lzma
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple, Union, Callable, Pattern
from datetime import datetime
import glob
import logging

from .base import BaseCollector

class FileCollector(BaseCollector):
    """Collects logs from files and directories."""
    
    def _setup(self) -> None:
        """Set up the enhanced file collector with format support."""
        self.config.setdefault('paths', ['/var/log'])
        self.config.setdefault('file_patterns', ['*.log', '*.json', '*.csv', '*.xml', '*.gz', '*.bz2', '*.xz'])
        self.config.setdefault('recursive', True)
        self.config.setdefault('encoding', 'utf-8')
        self.config.setdefault('read_from_beginning', False)
        self.config.setdefault('buffer_size', 65536)  # 64KB buffer size
        self.config.setdefault('max_line_length', 500000)  # Max line length to prevent memory issues
        
        # Format-specific configurations
        self.config.setdefault('format', 'auto')  # auto, json, csv, syslog, cef, leef, xml, etc.
        self.config.setdefault('csv_delimiter', ',')
        self.config.setdefault('csv_fieldnames', None)  # If None, first line is used as header
        
        # Track file positions and states
        self.file_positions: Dict[str, int] = {}
        self.active_files: Set[str] = set()
        self._running = False
        self._file_handles: Dict[str, Any] = {}
        self._file_parsers: Dict[str, Callable] = {
            'json': self._parse_json,
            'csv': self._parse_csv,
            'syslog': self._parse_syslog,
            'cef': self._parse_cef,
            'leef': self._parse_leef,
            'xml': self._parse_xml,
        }
        
        # Compressed file handlers
        self._compression_handlers = {
            '.gz': (gzip.open, 'rt', self.config['encoding']),
            '.bz2': (bz2.open, 'rt', self.config['encoding']),
            '.xz': (lzma.open, 'rt', self.config['encoding']),
        }
        
        # Pre-compile common patterns
        self._patterns = {
            'cef': re.compile(r'CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)')
        }
        
        # Load previous positions if available
        self._load_positions()
    
    def _load_positions(self) -> None:
        """Load file positions from disk."""
        try:
            pos_file = self.config.get('position_file', 'file_positions.json')
            if os.path.exists(pos_file):
                with open(pos_file, 'r') as f:
                    self.file_positions = json.load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load file positions: {e}")
    
    def _save_positions(self) -> None:
        """Save current file positions to disk."""
        try:
            pos_file = self.config.get('position_file', 'file_positions.json')
            with open(pos_file, 'w') as f:
                json.dump(self.file_positions, f)
        except Exception as e:
            self.logger.error(f"Failed to save file positions: {e}")
    
    def _get_files(self) -> List[str]:
        """Get list of files to monitor."""
        files = set()
        
        for path in self.config['paths']:
            if os.path.isfile(path):
                files.add(os.path.abspath(path))
            elif os.path.isdir(path):
                for pattern in self.config['file_patterns']:
                    pattern_path = os.path.join(path, '**' if self.config['recursive'] else '', pattern)
                    files.update(
                        os.path.abspath(f) for f in glob.glob(pattern_path, recursive=self.config['recursive'])
                        if os.path.isfile(f)
                    )
        
        return sorted(files)
    
    # Format-specific parsers
    def _parse_text(self, line: str) -> Dict[str, Any]:
        """Parse a plain text log line."""
        return {
            'message': line,
            'event': {
                'kind': 'event',
                'category': ['file'],
                'type': ['log']
            }
        }
        
    def _parse_json(self, line: str) -> Dict[str, Any]:
        """Parse a JSON log line."""
        try:
            entry = json.loads(line)
            if not isinstance(entry, dict):
                entry = {'message': str(entry)}
            return entry
        except json.JSONDecodeError:
            return self._parse_text(line)
            
    def _parse_csv(self, line: str) -> Dict[str, Any]:
        """Parse a CSV log line."""
        try:
            reader = csv.reader([line])
            fields = next(reader)
            
            if not hasattr(self, '_csv_fieldnames'):
                if self.config['csv_fieldnames']:
                    self._csv_fieldnames = self.config['csv_fieldnames']
                else:
                    # First line is header
                    self._csv_fieldnames = fields
                    return None
            
            if len(fields) == len(self._csv_fieldnames):
                return dict(zip(self._csv_fieldnames, fields))
            return {'message': line}
        except Exception:
            return self._parse_text(line)
            
    def _parse_xml(self, line: str) -> Dict[str, Any]:
        """Parse an XML log line."""
        try:
            root = ET.fromstring(line)
            return self._xml_to_dict(root)
        except ET.ParseError:
            return self._parse_text(line)
            
    def _xml_to_dict(self, element: ET.Element) -> Dict[str, Any]:
        """Convert XML element to dictionary."""
        result = {}
        for child in element:
            child_data = self._xml_to_dict(child)
            if child.tag in result:
                if isinstance(result[child.tag], list):
                    result[child.tag].append(child_data)
                else:
                    result[child.tag] = [result[child.tag], child_data]
            else:
                result[child.tag] = child_data
        
        if not result:  # Leaf node
            return element.text or ''
        return result
        
    def _parse_syslog(self, line: str) -> Dict[str, Any]:
        """Parse a syslog message."""
        # This is a simplified version - the full implementation is in syslog_collector.py
        entry = {
            'message': line,
            'event': {
                'kind': 'event',
                'category': ['network'],
                'type': ['protocol']
            },
            'log': {
                'syslog': {}
            }
        }
        
        # Try to parse the priority
        if line.startswith('<'):
            try:
                end_pri = line.index('>')
                pri = int(line[1:end_pri])
                entry['log']['syslog'].update({
                    'priority': pri,
                    'facility': pri // 8,
                    'severity': pri % 8
                })
                entry['message'] = line[end_pri+1:].strip()
            except (ValueError, IndexError):
                pass
                
        return entry
        
    def _parse_cef(self, line: str) -> Dict[str, Any]:
        """Parse a CEF (Common Event Format) message."""
        match = self._patterns['cef'].match(line)
        if not match:
            return self._parse_text(line)
            
        version, device_vendor, device_product, device_version, signature_id, name = match.groups()
        
        # Parse the key-value pairs
        extensions = {}
        rest = line[match.end():].strip()
        for pair in re.finditer(r'([^= ]+)=((?:[^= ]+ )+[^= ]+|(?:[^= ]+))', rest):
            key, value = pair.groups()
            # Handle escaped equals signs and spaces
            value = re.sub(r'\\([ =])', r'\1', value)
            extensions[key] = value
            
        return {
            'cef_version': version,
            'device': {
                'vendor': device_vendor,
                'product': device_product,
                'version': device_version
            },
            'event': {
                'id': signature_id,
                'name': name,
                'kind': 'event',
                'category': ['intrusion_detection']
            },
            **extensions
        }
        
    def _parse_leef(self, line: str) -> Dict[str, Any]:
        """Parse a LEEF (Log Event Extended Format) message."""
        if not line.startswith('LEEF:'):
            return self._parse_text(line)
            
        parts = line.split('|', 4)
        if len(parts) < 4:
            return self._parse_text(line)
            
        version = parts[0][5:]  # Remove 'LEEF:' prefix
        device_vendor = parts[1]
        device_product = parts[2]
        device_version = parts[3]
        
        # Parse key-value pairs
        extensions = {}
        if len(parts) > 4:
            for pair in re.finditer(r'([^=]+)=([^\t\n\r\f\v]+)', parts[4]):
                key, value = pair.groups()
                extensions[key] = value
                
        return {
            'leef_version': version,
            'device': {
                'vendor': device_vendor,
                'product': device_product,
                'version': device_version
            },
            'event': {
                'kind': 'event',
                'category': ['network']
            },
            **extensions
        }

    def _get_file_handle(self, file_path: str):
        """Get a file handle, handling compression if needed."""
        if file_path in self._file_handles:
            return self._file_handles[file_path]
            
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext in self._compression_handlers:
            open_func, mode, encoding = self._compression_handlers[ext]
            f = open_func(file_path, mode, encoding=encoding, errors='replace')
        else:
            f = open(file_path, 'r', encoding=self.config['encoding'], errors='replace')
            
        self._file_handles[file_path] = f
        return f
        
    def _close_file_handles(self):
        """Close all open file handles."""
        for f in self._file_handles.values():
            try:
                f.close()
            except Exception as e:
                self.logger.error(f"Error closing file handle: {e}")
        self._file_handles = {}

    def _read_file_changes(self, file_path: str) -> Tuple[List[Dict[str, Any]], int]:
        """Read new lines from a file since last read position.
        
        Args:
            file_path: Path to the file to read from
            
        Returns:
            Tuple of (list of log entries, new file position)
        """
        entries = []
        current_pos = self.file_positions.get(file_path, 0)
        
        try:
            # Check if file was rotated
            file_size = os.path.getsize(file_path)
            if file_size < current_pos:
                self.logger.info(f"File {file_path} appears to have been rotated")
                current_pos = 0
                if file_path in self._file_handles:
                    self._file_handles[file_path].close()
                    del self._file_handles[file_path]
            
            # Read new lines
            try:
                f = self._get_file_handle(file_path)
                f.seek(current_pos)
                
                while True:
                    line = f.readline()
                    if not line:
                        break
                        
                    # Handle very long lines to prevent memory issues
                    if len(line) > self.config['max_line_length']:
                        self.logger.warning(f"Line in {file_path} exceeds maximum length, truncating")
                        line = line[:self.config['max_line_length']] + '... [TRUNCATED]'
                    
                    entry = self._parse_line(line.rstrip('\r\n'), file_path)
                    if entry:
                        entries.append(entry)
                        
            except (IOError, OSError) as e:
                self.logger.error(f"Error reading file {file_path}: {e}")
                if file_path in self._file_handles:
                    del self._file_handles[file_path]
                return [], current_pos
                
            new_pos = f.tell()
            return entries, new_pos
            
        except Exception as e:
            self.logger.error(f"Unexpected error processing {file_path}: {e}", exc_info=True)
            if file_path in self._file_handles:
                del self._file_handles[file_path]
            return [], current_pos
    
    def _detect_format(self, file_path: str, first_line: str) -> str:
        """Detect the format of the log file based on its extension and content.
        
        Args:
            file_path: Path to the log file
            first_line: First line of the file
                
        Returns:
            Detected format name (e.g., 'json', 'csv', 'syslog')
        """
        # Check by file extension first
        ext = os.path.splitext(file_path)[1].lower()
        if ext in ['.json', '.jsonl']:
            return 'json'
        elif ext == '.csv':
            return 'csv'
        elif ext == '.xml':
            return 'xml'
                
        # Check by content
        first_line = first_line.strip()
        if not first_line:
            return 'text'  # Default to text if empty
                
        if first_line.startswith('{') and first_line.endswith('}'):
            try:
                json.loads(first_line)
                return 'json'
            except json.JSONDecodeError:
                pass
                    
        if '|' in first_line and ('CEF:' in first_line or 'LEEF:' in first_line):
            return 'cef' if 'CEF:' in first_line else 'leef'
                
        # Check for syslog format (starts with <PRI>)
        if re.match(r'^<\d+>', first_line):
            return 'syslog'
                
        # Default to text
        return 'text'

    def _parse_line(self, line: str, file_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Parse a single log line into a structured format.
        
        Args:
            line: A single line from the log file
            file_path: Optional path to the source file for format detection
                
        Returns:
            Parsed log entry or None if parsing failed
        """
        if not line.strip():
            return None
                
        try:
            # Determine the parser to use
            format_ = self.config['format']
            if format_ == 'auto':
                format_ = self._detect_format(file_path or getattr(self, 'current_file', ''), line)
                    
            parser = self._file_parsers.get(format_, self._parse_text)
                
            # Parse the line using the appropriate parser
            entry = parser(line)
            if not entry:
                return None
                    
            # Add common fields
            if '@timestamp' not in entry:
                entry['@timestamp'] = datetime.utcnow().isoformat() + 'Z'
                    
            # Add file metadata
            if 'log' not in entry:
                entry['log'] = {}
            if 'file' not in entry['log']:
                entry['log']['file'] = {}
                    
            entry['log']['file'].update({
                'path': os.path.abspath(file_path or getattr(self, 'current_file', '')),
                'name': os.path.basename(file_path or getattr(self, 'current_file', ''))
            })
                
            return entry
                
        except Exception as e:
            self.logger.error(f"Error parsing line: {e}", exc_info=True)
            # Return a minimal entry with the raw message
            error_entry = {
                '@timestamp': datetime.utcnow().isoformat() + 'Z',
                'message': line,
                'event': {
                    'kind': 'event',
                    'category': ['file'],
                    'type': ['log']
                },
                'error': {
                    'message': str(e),
                    'type': type(e).__name__
                },
                'status': {
                    'running': getattr(self, '_running', False),
                    'files_monitored': len(getattr(self, 'active_files', []))
                },
                'config': {
                    'paths': self.config.get('paths', []),
                    'file_patterns': self.config.get('file_patterns', []),
                    'recursive': self.config.get('recursive', True),
                    'encoding': self.config.get('encoding', 'utf-8')
                }
            }
            return error_entry
