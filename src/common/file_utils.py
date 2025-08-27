""
File system utilities with proper path handling.
"""
import os
import shutil
import tempfile
from pathlib import Path
from typing import Union, List, Optional, Generator
import logging
from .config import config

logger = logging.getLogger(__name__)

class FileSystem:
    """File system operations with proper path handling."""
    
    def __init__(self, base_path: Optional[Union[str, Path]] = None):
        """Initialize with an optional base path.
        
        Args:
            base_path: Base path for all operations. If None, uses the configured base directory.
        """
        self.base_path = Path(base_path) if base_path else Path(config['paths.base'])
        
    def resolve_path(self, path: Union[str, Path]) -> Path:
        """Resolve a path relative to the base directory.
        
        Args:
            path: The path to resolve. Can be absolute or relative.
            
        Returns:
            Resolved absolute path.
            
        Raises:
            ValueError: If the resolved path is outside the base directory.
        """
        path = Path(path)
        if not path.is_absolute():
            path = self.base_path / path
            
        # Resolve any '..' or '.' in the path
        resolved = path.resolve()
        
        # Ensure the path is within the base directory for security
        try:
            resolved.relative_to(self.base_path.resolve())
        except ValueError:
            raise ValueError(f"Path {resolved} is outside the base directory {self.base_path}")
            
        return resolved
    
    def ensure_dir(self, path: Union[str, Path]) -> Path:
        """Ensure a directory exists, creating it if necessary.
        
        Args:
            path: Path to the directory.
            
        Returns:
            Path to the directory.
        """
        path = self.resolve_path(path)
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    def write_file(self, path: Union[str, Path], content: Union[str, bytes], 
                  mode: str = 'w', encoding: str = 'utf-8') -> Path:
        """Write content to a file.
        
        Args:
            path: Path to the file.
            content: Content to write.
            mode: File mode ('w' for text, 'wb' for binary).
            encoding: Encoding to use for text mode.
            
        Returns:
            Path to the written file.
        """
        path = self.resolve_path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        if 'b' in mode:
            with open(path, mode) as f:
                f.write(content)
        else:
            with open(path, mode, encoding=encoding) as f:
                f.write(content)
                
        return path
    
    def read_file(self, path: Union[str, Path], mode: str = 'r', 
                 encoding: str = 'utf-8') -> Union[str, bytes]:
        """Read content from a file.
        
        Args:
            path: Path to the file.
            mode: File mode ('r' for text, 'rb' for binary).
            encoding: Encoding to use for text mode.
            
        Returns:
            File content as string or bytes.
        """
        path = self.resolve_path(path)
        with open(path, mode, encoding=encoding if 'b' not in mode else None) as f:
            return f.read()
    
    def copy_file(self, src: Union[str, Path], dst: Union[str, Path], 
                 overwrite: bool = False) -> Path:
        """Copy a file.
        
        Args:
            src: Source file path.
            dst: Destination path.
            overwrite: Whether to overwrite if the destination exists.
            
        Returns:
            Path to the destination file.
        """
        src = self.resolve_path(src)
        dst = self.resolve_path(dst)
        
        if dst.exists() and not overwrite:
            raise FileExistsError(f"Destination file {dst} already exists")
            
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return dst
    
    def delete_file(self, path: Union[str, Path]) -> None:
        """Delete a file.
        
        Args:
            path: Path to the file to delete.
        """
        path = self.resolve_path(path)
        if path.exists():
            path.unlink()
    
    def list_files(self, path: Union[str, Path], pattern: str = '*', 
                  recursive: bool = False) -> List[Path]:
        """List files in a directory.
        
        Args:
            path: Directory path.
            pattern: Glob pattern to match files.
            recursive: Whether to search recursively.
            
        Returns:
            List of matching file paths.
        """
        path = self.resolve_path(path)
        if recursive:
            return list(path.rglob(pattern))
        return list(path.glob(pattern))
    
    def create_temp_file(self, suffix: str = '', prefix: str = 'tmp_', 
                        dir: Optional[Union[str, Path]] = None, 
                        text: bool = True) -> Path:
        """Create a temporary file.
        
        Args:
            suffix: File suffix.
            prefix: File prefix.
            dir: Directory to create the file in. If None, uses the system temp directory.
            text: Whether to open in text mode.
            
        Returns:
            Path to the created temporary file.
        """
        if dir is not None:
            dir = self.resolve_path(dir)
            dir.mkdir(parents=True, exist_ok=True)
            
        fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=str(dir) if dir else None, 
                                   text=text)
        os.close(fd)
        return Path(path)
    
    def create_temp_dir(self, suffix: str = '', prefix: str = 'tmp_', 
                       dir: Optional[Union[str, Path]] = None) -> Path:
        """Create a temporary directory.
        
        Args:
            suffix: Directory suffix.
            prefix: Directory prefix.
            dir: Parent directory. If None, uses the system temp directory.
            
        Returns:
            Path to the created temporary directory.
        """
        if dir is not None:
            dir = self.resolve_path(dir)
            dir.mkdir(parents=True, exist_ok=True)
            
        return Path(tempfile.mkdtemp(suffix=suffix, prefix=prefix, 
                                   dir=str(dir) if dir else None))

# Global file system instance
fs = FileSystem()

def get_file_system() -> FileSystem:
    """Get the global file system instance."""
    return fs
