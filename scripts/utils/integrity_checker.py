"""
File Integrity Checker - Handles file hashing and integrity verification.
"""
import os
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
import json
from dataclasses import dataclass, asdict, field

@dataclass
class FileIntegrityRecord:
    """Represents the integrity data for a single file."""
    file_path: str
    size: int
    created: float
    modified: float
    hash_md5: str
    hash_sha1: str
    hash_sha256: str
    last_checked: float = field(default_factory=lambda: time.time())
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert the record to a dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'FileIntegrityRecord':
        """Create a record from a dictionary."""
        return cls(**data)

class IntegrityChecker:
    """Handles file hashing and integrity verification."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256
        }
    
    def calculate_hashes(self, file_path: Union[str, Path], algorithms: List[str] = None) -> Dict[str, str]:
        """
        Calculate hashes for a file using the specified algorithms.
        
        Args:
            file_path: Path to the file
            algorithms: List of hash algorithms to use (e.g., ['md5', 'sha1', 'sha256'])
            
        Returns:
            Dictionary mapping algorithm names to hash values
        """
        if algorithms is None:
            algorithms = list(self.hash_algorithms.keys())
        
        hashes = {alg: self.hash_algorithms[alg]() for alg in algorithms if alg in self.hash_algorithms}
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    for h in hashes.values():
                        h.update(chunk)
            
            # Get hexdigest for each hash
            return {alg: h.hexdigest() for alg, h in hashes.items()}
            
        except (IOError, OSError) as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return {}
    
    def create_baseline(self, file_path: Union[str, Path], metadata: Dict = None) -> Optional[FileIntegrityRecord]:
        """
        Create a baseline integrity record for a file.
        
        Args:
            file_path: Path to the file
            metadata: Optional metadata to include with the record
            
        Returns:
            FileIntegrityRecord if successful, None otherwise
        """
        try:
            file_path = Path(file_path).resolve()
            stat = file_path.stat()
            
            # Calculate all available hashes
            hashes = self.calculate_hashes(file_path)
            
            if not hashes:
                return None
            
            return FileIntegrityRecord(
                file_path=str(file_path),
                size=stat.st_size,
                created=stat.st_ctime,
                modified=stat.st_mtime,
                hash_md5=hashes.get('md5', ''),
                hash_sha1=hashes.get('sha1', ''),
                hash_sha256=hashes.get('sha256', ''),
                last_checked=time.time(),
                metadata=metadata or {}
            )
            
        except Exception as e:
            self.logger.error(f"Error creating baseline for {file_path}: {e}")
            return None
    
    def verify_file(self, baseline: FileIntegrityRecord) -> Tuple[bool, Dict]:
        """
        Verify if a file's integrity matches its baseline.
        
        Args:
            baseline: The baseline integrity record to verify against
            
        Returns:
            Tuple of (is_integrity_ok, details_dict)
        """
        try:
            file_path = Path(baseline.file_path)
            
            # Check if file exists
            if not file_path.exists():
                return False, {"status": "deleted", "message": "File no longer exists"}
            
            # Get current file stats
            stat = file_path.stat()
            
            # Check basic attributes
            size_changed = stat.st_size != baseline.size
            mtime_changed = abs(stat.st_mtime - baseline.modified) > 1.0  # Allow 1s tolerance for timestamp precision
            
            # Check hashes if needed
            hashes_match = True
            hash_verification = {}
            
            if size_changed or mtime_changed:
                # Only calculate hashes if size or mtime changed (performance optimization)
                current_hashes = self.calculate_hashes(file_path)
                
                # Check each hash that exists in baseline
                for hash_type in ['md5', 'sha1', 'sha256']:
                    hash_attr = f'hash_{hash_type}'
                    baseline_hash = getattr(baseline, hash_attr, None)
                    
                    if baseline_hash and hash_type in current_hashes:
                        current_hash = current_hashes[hash_type]
                        hash_matches = (current_hash == baseline_hash)
                        hashes_match = hashes_match and hash_matches
                        hash_verification[hash_type] = {
                            'matches': hash_matches,
                            'baseline': baseline_hash,
                            'current': current_hash
                        }
            
            # Determine overall status
            integrity_ok = not (size_changed or mtime_changed) or hashes_match
            
            # Prepare result
            result = {
                'status': 'ok' if integrity_ok else 'modified',
                'size_changed': size_changed,
                'mtime_changed': mtime_changed,
                'hashes': hash_verification,
                'current_size': stat.st_size,
                'current_mtime': stat.st_mtime,
                'baseline_size': baseline.size,
                'baseline_mtime': baseline.modified,
                'last_checked': time.time()
            }
            
            return integrity_ok, result
            
        except Exception as e:
            self.logger.error(f"Error verifying file {baseline.file_path if baseline else 'unknown'}: {e}")
            return False, {"status": "error", "message": str(e)}
    
    def scan_directory(self, directory: Union[str, Path], 
                      file_patterns: List[str] = None,
                      exclude_dirs: List[str] = None) -> List[FileIntegrityRecord]:
        """
        Scan a directory and create baseline records for matching files.
        
        Args:
            directory: Directory to scan
            file_patterns: List of file patterns to include (e.g., ['*.exe', '*.dll'])
            exclude_dirs: List of directory names to exclude
            
        Returns:
            List of FileIntegrityRecord objects
        """
        directory = Path(directory).resolve()
        if not directory.is_dir():
            self.logger.error(f"Not a directory: {directory}")
            return []
        
        exclude_dirs = set(exclude_dirs or [])
        records = []
        
        try:
            for item in directory.rglob('*'):
                # Skip excluded directories
                if any(part in exclude_dirs for part in item.parts):
                    continue
                
                # Skip directories
                if not item.is_file():
                    continue
                
                # Check file patterns if specified
                if file_patterns and not any(item.match(pat) for pat in file_patterns):
                    continue
                
                # Create baseline record
                record = self.create_baseline(item)
                if record:
                    records.append(record)
            
            return records
            
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
            return []

# Example usage
if __name__ == "__main__":
    import time
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Create a test file
    test_file = "test_file.txt"
    with open(test_file, 'w') as f:
        f.write("This is a test file for FIM.")
    
    # Initialize checker
    checker = IntegrityChecker()
    
    # Create baseline
    print("Creating baseline...")
    baseline = checker.create_baseline(test_file, {"owner": "test", "purpose": "demo"})
    print(f"Baseline created: {baseline}")
    
    # Verify file (should match)
    print("\nVerifying file (should match)...")
    is_ok, result = checker.verify_file(baseline)
    print(f"Integrity OK: {is_ok}")
    print(f"Verification result: {result}")
    
    # Modify the file
    print("\nModifying file...")
    with open(test_file, 'a') as f:
        f.write(" Modified content.")
    
    # Verify again (should detect change)
    print("Verifying file (should detect changes)...")
    is_ok, result = checker.verify_file(baseline)
    print(f"Integrity OK: {is_ok}")
    print(f"Verification result: {result}")
    
    # Clean up
    os.remove(test_file)
