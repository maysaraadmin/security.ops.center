"""
Baseline Integrity Check Module

This module provides functionality for managing and verifying file integrity baselines.
It allows creating, loading, saving, and verifying baselines against the current
file system state.
"""
import os
import json
import time
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Callable
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class BaselineManager:
    """Manages file integrity baselines and verifications."""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the BaselineManager.
        
        Args:
            config: Configuration dictionary with the following keys:
                - baseline_file: Path to store/load the baseline (default: 'fim_baseline.json')
                - hash_algorithm: Hashing algorithm to use (default: 'sha256')
                - exclude_patterns: List of glob patterns to exclude from monitoring
                - include_patterns: List of glob patterns to include in monitoring
        """
        self.config = config or {}
        self.baseline: Dict[str, Dict] = {}
        self._baseline_loaded = False
        self.hash_algorithm = self.config.get('hash_algorithm', 'sha256')
        self.exclude_patterns = self.config.get('exclude_patterns', [])
        self.include_patterns = self.config.get('include_patterns', ['*'])
        
    def create_baseline(self, paths: List[str], recursive: bool = True, force: bool = False) -> bool:
        """
        Create a new baseline for the specified paths.
        
        Args:
            paths: List of file/directory paths to include in the baseline
            recursive: If True, scan directories recursively
            force: If True, overwrite existing baseline
            
        Returns:
            bool: True if baseline was created successfully, False otherwise
        """
        if not force and self._baseline_loaded:
            logger.warning("Baseline already exists. Use force=True to overwrite.")
            return False
            
        logger.info("Creating new baseline...")
        start_time = time.time()
        self.baseline.clear()
        
        # Process each path
        for path in paths:
            path = os.path.abspath(path)
            if not os.path.exists(path):
                logger.warning(f"Path does not exist: {path}")
                continue
                
            if os.path.isfile(path):
                self._add_file_to_baseline(path)
            elif os.path.isdir(path):
                self._scan_directory(path, recursive=recursive)
        
        self._baseline_loaded = True
        elapsed = time.time() - start_time
        logger.info(f"Baseline created with {len(self.baseline)} files in {elapsed:.2f} seconds")
        
        # Save the baseline if a file is configured
        if self.config.get('baseline_file'):
            return self.save_baseline()
            
        return True
    
    def verify_baseline(self) -> Dict[str, Any]:
        """
        Verify the current file system state against the baseline.
        
        Returns:
            Dict containing verification results with the following keys:
                - added: List of files added since baseline
                - modified: List of modified files
                - deleted: List of deleted files
                - permission_changes: List of files with permission changes
                - owner_changes: List of files with owner/group changes
                - errors: List of errors encountered during verification
        """
        if not self._baseline_loaded:
            logger.error("No baseline loaded. Create or load a baseline first.")
            return {
                'added': [],
                'modified': [],
                'deleted': [],
                'permission_changes': [],
                'owner_changes': [],
                'errors': ['No baseline loaded']
            }
            
        logger.info("Verifying baseline...")
        start_time = time.time()
        
        results = {
            'added': [],
            'modified': [],
            'deleted': [],
            'permission_changes': [],
            'owner_changes': [],
            'errors': []
        }
        
        # Track which files we've seen in the current scan
        current_files = set()
        
        # Check all files in the baseline
        for file_path, baseline_meta in self.baseline.items():
            try:
                # Check if file still exists
                if not os.path.exists(file_path):
                    results['deleted'].append({
                        'path': file_path,
                        'baseline': baseline_meta,
                        'timestamp': time.time()
                    })
                    continue
                
                # Get current file metadata
                current_meta = self._get_file_metadata(file_path)
                if current_meta is None:
                    results['errors'].append(f"Could not get metadata for {file_path}")
                    continue
                    
                current_files.add(file_path)
                
                # Check for changes
                changes = self._compare_metadata(baseline_meta, current_meta)
                if changes:
                    if 'permissions' in changes:
                        results['permission_changes'].append({
                            'path': file_path,
                            'baseline': baseline_meta['permissions'],
                            'current': current_meta['permissions'],
                            'timestamp': time.time()
                        })
                        
                    if 'ownership' in changes:
                        results['owner_changes'].append({
                            'path': file_path,
                            'baseline_owner': baseline_meta['owner'],
                            'current_owner': current_meta['owner'],
                            'baseline_group': baseline_meta['group'],
                            'current_group': current_meta['group'],
                            'timestamp': time.time()
                        })
                        
                    if 'content' in changes:
                        results['modified'].append({
                            'path': file_path,
                            'changes': changes['content'],
                            'baseline': baseline_meta,
                            'current': current_meta,
                            'timestamp': time.time()
                        })
                        
            except Exception as e:
                logger.error(f"Error verifying {file_path}: {e}")
                results['errors'].append(f"Error verifying {file_path}: {str(e)}")
        
        # Check for new files in monitored directories
        for file_path in self._find_new_files():
            if file_path not in current_files:
                current_meta = self._get_file_metadata(file_path)
                if current_meta:
                    results['added'].append({
                        'path': file_path,
                        'current': current_meta,
                        'timestamp': time.time()
                    })
        
        elapsed = time.time() - start_time
        logger.info(f"Baseline verification completed in {elapsed:.2f} seconds")
        
        # Log summary
        logger.info(f"Verification results: "
                   f"{len(results['added'])} added, "
                   f"{len(results['modified'])} modified, "
                   f"{len(results['deleted'])} deleted, "
                   f"{len(results['permission_changes'])} permission changes, "
                   f"{len(results['owner_changes'])} owner changes, "
                   f"{len(results['errors'])} errors")
        
        return results
    
    def save_baseline(self, file_path: Optional[str] = None) -> bool:
        """
        Save the current baseline to a file.
        
        Args:
            file_path: Path to save the baseline (default: from config)
            
        Returns:
            bool: True if save was successful, False otherwise
        """
        if not file_path:
            file_path = self.config.get('baseline_file')
            if not file_path:
                logger.error("No file path provided and none configured")
                return False
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            
            # Convert any non-serializable values to strings
            serializable_baseline = {}
            for path, meta in self.baseline.items():
                serializable_meta = {}
                for k, v in meta.items():
                    if isinstance(v, (int, float, str, bool, type(None))):
                        serializable_meta[k] = v
                    else:
                        serializable_meta[k] = str(v)
                serializable_baseline[path] = serializable_meta
            
            # Write to a temporary file first, then rename (atomic operation)
            temp_path = f"{file_path}.tmp"
            with open(temp_path, 'w') as f:
                json.dump(serializable_baseline, f, indent=2)
                
            # On Windows, we need to remove the destination file first
            if os.path.exists(file_path):
                os.remove(file_path)
            os.rename(temp_path, file_path)
            
            logger.info(f"Baseline saved to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving baseline to {file_path}: {e}")
            # Clean up temporary file if it exists
            if 'temp_path' in locals() and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
            return False
    
    def load_baseline(self, file_path: Optional[str] = None) -> bool:
        """
        Load a baseline from a file.
        
        Args:
            file_path: Path to load the baseline from (default: from config)
            
        Returns:
            bool: True if load was successful, False otherwise
        """
        if not file_path:
            file_path = self.config.get('baseline_file')
            if not file_path:
                logger.error("No file path provided and none configured")
                return False
        
        try:
            if not os.path.exists(file_path):
                logger.error(f"Baseline file not found: {file_path}")
                return False
                
            with open(file_path, 'r') as f:
                self.baseline = json.load(f)
                
            self._baseline_loaded = True
            logger.info(f"Loaded baseline from {file_path} with {len(self.baseline)} files")
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in baseline file {file_path}: {e}")
            return False
            
        except Exception as e:
            logger.error(f"Error loading baseline from {file_path}: {e}")
            return False
    
    def _add_file_to_baseline(self, file_path: str) -> None:
        """
        Add a file to the baseline.
        
        Args:
            file_path: Path to the file to add
        """
        if self._should_ignore(file_path):
            return
            
        meta = self._get_file_metadata(file_path)
        if meta:
            self.baseline[file_path] = meta
    
    def _scan_directory(self, directory: str, recursive: bool = True) -> None:
        """
        Scan a directory and add files to the baseline.
        
        Args:
            directory: Directory to scan
            recursive: If True, scan subdirectories
        """
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    try:
                        if entry.is_file():
                            self._add_file_to_baseline(entry.path)
                        elif entry.is_dir() and recursive:
                            self._scan_directory(entry.path, recursive)
                    except (OSError, PermissionError) as e:
                        logger.warning(f"Could not process {entry.path}: {e}")
        except (OSError, PermissionError) as e:
            logger.warning(f"Could not scan directory {directory}: {e}")
    
    def _get_file_metadata(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary containing file metadata, or None if the file cannot be accessed
        """
        try:
            stat = os.stat(file_path)
            
            return {
                'size': stat.st_size,
                'mtime': stat.st_mtime,
                'ctime': stat.st_ctime,
                'mode': stat.st_mode,
                'uid': stat.st_uid,
                'gid': stat.st_gid,
                'inode': stat.st_ino,
                'device': stat.st_dev,
                'permissions': oct(stat.st_mode & 0o777),
                'owner': stat.st_uid,
                'group': stat.st_gid,
                'checksum': self._calculate_checksum(file_path) if stat.st_size > 0 else None,
                'last_verified': time.time()
            }
        except (OSError, PermissionError) as e:
            logger.warning(f"Could not get metadata for {file_path}: {e}")
            return None
    
    def _calculate_checksum(self, file_path: str, chunk_size: int = 65536) -> Optional[str]:
        """
        Calculate the checksum of a file.
        
        Args:
            file_path: Path to the file
            chunk_size: Size of chunks to read (default: 64KB)
            
        Returns:
            Hex digest of the file's checksum, or None on error
        """
        try:
            hasher = hashlib.new(self.hash_algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(chunk_size), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, OSError) as e:
            logger.warning(f"Could not calculate checksum for {file_path}: {e}")
            return None
    
    def _compare_metadata(self, baseline_meta: Dict, current_meta: Dict) -> Dict[str, Any]:
        """
        Compare baseline metadata with current metadata.
        
        Args:
            baseline_meta: Baseline metadata
            current_meta: Current metadata
            
        Returns:
            Dictionary of changes, empty if no changes
        """
        changes = {}
        
        # Check size and mtime first (quick checks)
        if baseline_meta['size'] != current_meta['size']:
            changes['size'] = {
                'baseline': baseline_meta['size'],
                'current': current_meta['size']
            }
        
        if abs(baseline_meta['mtime'] - current_meta['mtime']) > 1.0:  # Allow for small time differences
            changes['mtime'] = {
                'baseline': baseline_meta['mtime'],
                'current': current_meta['mtime']
            }
        
        # If size or mtime changed, check content checksum
        if ('size' in changes or 'mtime' in changes) and 'checksum' in baseline_meta:
            if baseline_meta['checksum'] != current_meta['checksum']:
                changes['content'] = {
                    'checksum_changed': True,
                    'baseline_checksum': baseline_meta['checksum'],
                    'current_checksum': current_meta['checksum']
                }
        
        # Check permissions
        if baseline_meta['permissions'] != current_meta['permissions']:
            changes['permissions'] = {
                'baseline': baseline_meta['permissions'],
                'current': current_meta['permissions']
            }
        
        # Check ownership
        if (baseline_meta['owner'] != current_meta['owner'] or 
            baseline_meta['group'] != current_meta['group']):
            changes['ownership'] = {
                'baseline_owner': baseline_meta['owner'],
                'current_owner': current_meta['owner'],
                'baseline_group': baseline_meta['group'],
                'current_group': current_meta['group']
            }
        
        return changes
    
    def _find_new_files(self) -> Set[str]:
        """
        Find new files in monitored directories that aren't in the baseline.
        
        Returns:
            Set of file paths that are new (not in baseline)
        """
        new_files = set()
        
        for path in self.baseline.values():
            dir_path = os.path.dirname(path)
            if os.path.isdir(dir_path):
                for root, _, files in os.walk(dir_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if (file_path not in self.baseline and 
                            not self._should_ignore(file_path)):
                            new_files.add(file_path)
        
        return new_files
    
    def _should_ignore(self, path: str) -> bool:
        """
        Check if a path should be ignored based on include/exclude patterns.
        
        Args:
            path: Path to check
            
        Returns:
            bool: True if the path should be ignored, False otherwise
        """
        path = os.path.normpath(path).replace('\\', '/')
        
        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if Path(path).match(pattern):
                return True
        
        # Check include patterns (if not using default '*')
        if self.include_patterns != ['*']:
            for pattern in self.include_patterns:
                if Path(path).match(pattern):
                    return False
            return True  # Not in include patterns
            
        return False  # Not in exclude patterns and no specific includes
    
    def get_baseline_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the current baseline.
        
        Returns:
            Dictionary containing baseline statistics
        """
        if not self._baseline_loaded:
            return {
                'status': 'no_baseline',
                'file_count': 0,
                'total_size': 0,
                'oldest_file': None,
                'newest_file': None,
                'file_types': {},
                'last_verified': None
            }
        
        stats = {
            'status': 'loaded',
            'file_count': len(self.baseline),
            'total_size': 0,
            'oldest_file': None,
            'newest_file': None,
            'file_types': {},
            'last_verified': None
        }
        
        for path, meta in self.baseline.items():
            # Update total size
            stats['total_size'] += meta.get('size', 0)
            
            # Track file extensions
            _, ext = os.path.splitext(path)
            ext = ext.lower() or 'no_extension'
            stats['file_types'][ext] = stats['file_types'].get(ext, 0) + 1
            
            # Track oldest/newest files by mtime
            mtime = meta.get('mtime', 0)
            if stats['oldest_file'] is None or mtime < stats['oldest_file'][1]:
                stats['oldest_file'] = (path, mtime)
            if stats['newest_file'] is None or mtime > stats['newest_file'][1]:
                stats['newest_file'] = (path, mtime)
            
            # Track last verification time
            last_verified = meta.get('last_verified', 0)
            if (stats['last_verified'] is None or 
                (last_verified and last_verified < stats['last_verified'])):
                stats['last_verified'] = last_verified
        
        # Convert timestamps to human-readable format
        if stats['oldest_file']:
            stats['oldest_file'] = (stats['oldest_file'][0], 
                                  time.ctime(stats['oldest_file'][1]))
        if stats['newest_file']:
            stats['newest_file'] = (stats['newest_file'][0], 
                                  time.ctime(stats['newest_file'][1]))
        if stats['last_verified']:
            stats['last_verified'] = time.ctime(stats['last_verified'])
        
        # Add human-readable size
        stats['total_size_human'] = self._format_size(stats['total_size'])
        
        # Sort file types by count
        stats['file_types'] = dict(
            sorted(stats['file_types'].items(), 
                  key=lambda x: x[1], 
                  reverse=True)
        )
        
        return stats
    
    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """
        Format a size in bytes to a human-readable string.
        
        Args:
            size_bytes: Size in bytes
            
        Returns:
            Formatted size string with appropriate unit
        """
        if size_bytes == 0:
            return "0 B"
            
        units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
        i = 0
        while size_bytes >= 1024 and i < len(units) - 1:
            size_bytes /= 1024
            i += 1
            
        return f"{size_bytes:.2f} {units[i]}"
