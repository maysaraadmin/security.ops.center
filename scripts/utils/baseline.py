"""
Baseline Manager Module

This module provides functionality for creating and managing file integrity baselines,
which are used to detect unauthorized changes to files and directories.
"""

import os
import json
import hashlib
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
import platform

logger = logging.getLogger('fim.baseline')

@dataclass
class FileInfo:
    """Represents the integrity information for a file."""
    path: str
    size: int
    mtime: float
    mode: int
    uid: int
    gid: int
    hash_algorithm: str = 'sha256'
    hash_value: Optional[str] = None
    acl: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the file info to a dictionary."""
        return {
            'path': self.path,
            'size': self.size,
            'mtime': self.mtime,
            'mode': self.mode,
            'uid': self.uid,
            'gid': self.gid,
            'hash_algorithm': self.hash_algorithm,
            'hash_value': self.hash_value,
            'acl': self.acl,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FileInfo':
        """Create a FileInfo from a dictionary."""
        return cls(
            path=data['path'],
            size=data['size'],
            mtime=data['mtime'],
            mode=data['mode'],
            uid=data['uid'],
            gid=data['gid'],
            hash_algorithm=data.get('hash_algorithm', 'sha256'),
            hash_value=data.get('hash_value'),
            acl=data.get('acl'),
            metadata=data.get('metadata', {})
        )
    
    def calculate_hash(self, chunk_size: int = 65536) -> str:
        """Calculate the hash of the file.
        
        Args:
            chunk_size: Number of bytes to read at a time
            
        Returns:
            The hexadecimal digest of the file's hash
        """
        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"File not found: {self.path}")
        
        hash_func = getattr(hashlib, self.hash_algorithm, hashlib.sha256)
        hasher = hash_func()
        
        try:
            with open(self.path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
            
            self.hash_value = hasher.hexdigest()
            return self.hash_value
            
        except Exception as e:
            logger.error(f"Error calculating hash for {self.path}: {e}")
            raise

class BaselineManager:
    """Manages file integrity baselines for FIM."""
    
    def __init__(self, baseline_file: Optional[str] = None):
        """Initialize the baseline manager.
        
        Args:
            baseline_file: Path to the baseline file (JSON)
        """
        self.baseline_file = baseline_file
        self.baseline: Dict[str, FileInfo] = {}
        self.ignore_patterns: Set[str] = set()
        self.hash_algorithm = 'sha256'
        
        # Load the baseline if a file is provided
        if self.baseline_file and os.path.isfile(self.baseline_file):
            self.load_baseline(self.baseline_file)
    
    def add_ignore_pattern(self, pattern: str) -> None:
        """Add a pattern to ignore when creating or updating the baseline."""
        self.ignore_patterns.add(pattern)
    
    def remove_ignore_pattern(self, pattern: str) -> bool:
        """Remove an ignore pattern."""
        if pattern in self.ignore_patterns:
            self.ignore_patterns.remove(pattern)
            return True
        return False
    
    def create_baseline(
        self, 
        paths: Union[str, List[str]], 
        recursive: bool = True,
        calculate_hashes: bool = True
    ) -> Dict[str, FileInfo]:
        """Create a new file integrity baseline.
        
        Args:
            paths: Directory or file path(s) to include in the baseline
            recursive: Whether to scan directories recursively
            calculate_hashes: Whether to calculate file hashes
            
        Returns:
            Dictionary mapping file paths to FileInfo objects
        """
        if isinstance(paths, str):
            paths = [paths]
        
        self.baseline = {}
        
        for path in paths:
            path = os.path.abspath(path)
            if os.path.isfile(path):
                self._process_file(path, calculate_hashes)
            elif os.path.isdir(path):
                self._scan_directory(path, recursive, calculate_hashes)
        
        return self.baseline
    
    def _should_ignore(self, path: str) -> bool:
        """Check if a path should be ignored based on ignore patterns."""
        path = os.path.normpath(path)
        for pattern in self.ignore_patterns:
            if pattern.startswith('*'):
                # Match file extension
                if path.endswith(pattern[1:]):
                    return True
            else:
                # Match full path
                if path == pattern:
                    return True
        return False
    
    def _process_file(self, file_path: str, calculate_hash: bool = True) -> Optional[FileInfo]:
        """Process a single file and add it to the baseline."""
        if self._should_ignore(file_path):
            return None
        
        try:
            stat = os.stat(file_path, follow_symlinks=False)
            
            file_info = FileInfo(
                path=file_path,
                size=stat.st_size,
                mtime=stat.st_mtime,
                mode=stat.st_mode,
                uid=stat.st_uid,
                gid=stat.st_gid,
                hash_algorithm=self.hash_algorithm
            )
            
            if calculate_hash and file_info.size > 0:  # Don't hash empty files
                try:
                    file_info.calculate_hash()
                except Exception as e:
                    logger.warning(f"Could not calculate hash for {file_path}: {e}")
            
            # Store file info in baseline
            self.baseline[file_path] = file_info
            return file_info
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            return None
    
    def _scan_directory(
        self, 
        directory: str, 
        recursive: bool = True, 
        calculate_hashes: bool = True
    ) -> None:
        """Scan a directory and add files to the baseline."""
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue  # Skip symlinks
                            
                        if entry.is_file():
                            self._process_file(entry.path, calculate_hashes)
                        elif entry.is_dir() and recursive:
                            self._scan_directory(entry.path, recursive, calculate_hashes)
                    except Exception as e:
                        logger.error(f"Error processing {entry.path}: {e}")
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
    
    def save_baseline(self, output_file: Optional[str] = None) -> str:
        """Save the current baseline to a file.
        
        Args:
            output_file: Path to save the baseline file (defaults to self.baseline_file)
            
        Returns:
            Path to the saved baseline file
        """
        if not output_file and not self.baseline_file:
            raise ValueError("No output file specified")
        
        output_file = output_file or self.baseline_file
        output_file = os.path.abspath(output_file)
        
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Prepare baseline data
        baseline_data = {
            'version': '1.0',
            'timestamp': time.time(),
            'hash_algorithm': self.hash_algorithm,
            'files': {}
        }
        
        # Convert FileInfo objects to dictionaries
        for path, file_info in self.baseline.items():
            baseline_data['files'][path] = file_info.to_dict()
        
        # Write to file
        try:
            with open(output_file, 'w') as f:
                json.dump(baseline_data, f, indent=2)
            
            logger.info(f"Baseline saved to {output_file} with {len(self.baseline)} files")
            self.baseline_file = output_file
            return output_file
            
        except Exception as e:
            logger.error(f"Error saving baseline to {output_file}: {e}")
            raise
    
    def load_baseline(self, input_file: str) -> Dict[str, FileInfo]:
        """Load a baseline from a file.
        
        Args:
            input_file: Path to the baseline file
            
        Returns:
            Dictionary mapping file paths to FileInfo objects
        """
        try:
            with open(input_file, 'r') as f:
                baseline_data = json.load(f)
            
            self.baseline = {}
            self.hash_algorithm = baseline_data.get('hash_algorithm', 'sha256')
            
            for path, file_data in baseline_data.get('files', {}).items():
                try:
                    self.baseline[path] = FileInfo.from_dict(file_data)
                except Exception as e:
                    logger.error(f"Error loading file info for {path}: {e}")
            
            logger.info(f"Loaded baseline from {input_file} with {len(self.baseline)} files")
            self.baseline_file = input_file
            return self.baseline
            
        except Exception as e:
            logger.error(f"Error loading baseline from {input_file}: {e}")
            raise
    
    def verify_baseline(
        self, 
        report_file: Optional[str] = None,
        alert_on_missing: bool = True,
        alert_on_modified: bool = True,
        alert_on_new: bool = True
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Verify the current system against the loaded baseline.
        
        Args:
            report_file: Path to save the verification report (optional)
            alert_on_missing: Whether to report missing files
            alert_on_modified: Whether to report modified files
            alert_on_new: Whether to report new files
            
        Returns:
            Dictionary containing verification results
        """
        if not self.baseline:
            raise ValueError("No baseline loaded")
        
        results = {
            'missing_files': [],
            'modified_files': [],
            'new_files': [],
            'verified_files': [],
            'summary': {
                'total_checked': 0,
                'missing': 0,
                'modified': 0,
                'new': 0,
                'verified': 0,
                'start_time': time.time(),
                'end_time': None,
                'success': False
            }
        }
        
        # Check files in baseline
        for path, baseline_info in self.baseline.items():
            results['summary']['total_checked'] += 1
            
            try:
                if not os.path.exists(path):
                    if alert_on_missing:
                        results['missing_files'].append({
                            'path': path,
                            'baseline': baseline_info.to_dict(),
                            'error': 'File not found'
                        })
                        results['summary']['missing'] += 1
                    continue
                
                if os.path.isdir(path):
                    continue  # Skip directories for now
                
                # Get current file info
                current_info = self._process_file(path, calculate_hash=True)
                if not current_info:
                    continue
                
                # Compare with baseline
                if baseline_info.hash_value and current_info.hash_value:
                    if baseline_info.hash_value != current_info.hash_value:
                        if alert_on_modified:
                            results['modified_files'].append({
                                'path': path,
                                'baseline': baseline_info.to_dict(),
                                'current': current_info.to_dict(),
                                'difference': {
                                    'size': current_info.size - baseline_info.size,
                                    'mtime': current_info.mtime - baseline_info.mtime,
                                    'hash_differs': True
                                }
                            })
                            results['summary']['modified'] += 1
                        continue
                
                # If we get here, the file is verified
                results['verified_files'].append({
                    'path': path,
                    'baseline': baseline_info.to_dict(),
                    'current': current_info.to_dict()
                })
                results['summary']['verified'] += 1
                
            except Exception as e:
                logger.error(f"Error verifying {path}: {e}")
        
        # Check for new files (optional)
        if alert_on_new:
            # This would require scanning the entire directory structure again
            # and comparing with the baseline. For large directories, this could
            # be expensive, so it's optional.
            pass
        
        # Update summary
        results['summary']['end_time'] = time.time()
        results['summary']['success'] = True
        
        # Save report if requested
        if report_file:
            try:
                with open(report_file, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                logger.info(f"Verification report saved to {report_file}")
            except Exception as e:
                logger.error(f"Error saving verification report: {e}")
        
        return results
