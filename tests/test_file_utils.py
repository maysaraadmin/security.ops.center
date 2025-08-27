""
Tests for the file_utils module.
"""
import os
import shutil
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.common.file_utils import FileSystem, get_file_system

class TestFileSystem:
    """Tests for the FileSystem class."""
    
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test environment."""
        self.base_dir = tmp_path / "test_project"
        self.base_dir.mkdir()
        
        # Create test files and directories
        (self.base_dir / 'data').mkdir()
        (self.base_dir / 'logs').mkdir()
        (self.base_dir / 'config').mkdir()
        (self.base_dir / 'config' / 'rules').mkdir()
        
        # Create some test files
        (self.base_dir / 'data' / 'test.txt').write_text('test content')
        (self.base_dir / 'config' / 'config.yaml').write_text('key: value')
        
        self.fs = FileSystem(self.base_dir)
        
    def test_resolve_path_relative(self):
        ""Test resolving a relative path."""
        path = self.fs.resolve_path('data/test.txt')
        assert path == self.base_dir / 'data' / 'test.txt'
        
    def test_resolve_path_absolute(self):
        ""Test resolving an absolute path."""
        abs_path = self.base_dir / 'data' / 'test.txt'
        path = self.fs.resolve_path(str(abs_path))
        assert path == abs_path
        
    def test_resolve_path_outside_base(self):
        ""Test resolving a path outside the base directory raises an error."""
        with pytest.raises(ValueError):
            self.fs.resolve_path('/outside/path')
            
    def test_ensure_dir_exists(self):
        ""Test ensuring a directory that already exists."""
        dir_path = self.base_dir / 'existing_dir'
        dir_path.mkdir()
        
        result = self.fs.ensure_dir('existing_dir')
        assert result == dir_path
        assert dir_path.exists()
        
    def test_ensure_dir_creates(self):
        ""Test ensuring a directory that needs to be created."""
        dir_path = self.base_dir / 'new_dir'
        
        result = self.fs.ensure_dir('new_dir')
        assert result == dir_path
        assert dir_path.exists()
        
    def test_write_file_text(self):
        ""Test writing a text file."""
        file_path = self.base_dir / 'new_file.txt'
        content = 'test content'
        
        result = self.fs.write_file(file_path, content)
        assert result == file_path
        assert file_path.read_text() == content
        
    def test_write_file_binary(self):
        ""Test writing a binary file."""
        file_path = self.base_dir / 'binary_file.bin'
        content = b'\x00\x01\x02'
        
        result = self.fs.write_file(file_path, content, mode='wb')
        assert result == file_path
        assert file_path.read_bytes() == content
        
    def test_read_file_text(self):
        ""Test reading a text file."""
        file_path = self.base_dir / 'test_read.txt'
        content = 'test content'
        file_path.write_text(content)
        
        result = self.fs.read_file(file_path)
        assert result == content
        
    def test_read_file_binary(self):
        ""Test reading a binary file."""
        file_path = self.base_dir / 'test_read.bin'
        content = b'\x00\x01\x02'
        file_path.write_bytes(content)
        
        result = self.fs.read_file(file_path, mode='rb')
        assert result == content
        
    def test_copy_file(self):
        ""Test copying a file."""
        src = self.base_dir / 'data' / 'test.txt'
        dst = self.base_dir / 'data' / 'test_copy.txt'
        
        result = self.fs.copy_file(src, dst)
        assert result == dst
        assert dst.exists()
        assert dst.read_text() == 'test content'
        
    def test_copy_file_overwrite(self):
        ""Test copying a file with overwrite."""
        src = self.base_dir / 'data' / 'test.txt'
        dst = self.base_dir / 'data' / 'test_copy.txt'
        dst.write_text('old content')
        
        result = self.fs.copy_file(src, dst, overwrite=True)
        assert result == dst
        assert dst.read_text() == 'test content'
        
    def test_copy_file_no_overwrite(self):
        ""Test copying a file without overwrite raises an error."""
        src = self.base_dir / 'data' / 'test.txt'
        dst = self.base_dir / 'data' / 'test_copy.txt'
        dst.write_text('old content')
        
        with pytest.raises(FileExistsError):
            self.fs.copy_file(src, dst, overwrite=False)
            
    def test_delete_file(self):
        ""Test deleting a file."""
        file_path = self.base_dir / 'data' / 'test.txt'
        assert file_path.exists()
        
        self.fs.delete_file(file_path)
        assert not file_path.exists()
        
    def test_delete_nonexistent_file(self):
        ""Test deleting a non-existent file doesn't raise an error."""
        file_path = self.base_dir / 'nonexistent.txt'
        self.fs.delete_file(file_path)  # Should not raise
        
    def test_list_files(self):
        ""Test listing files in a directory."""
        # Create some test files
        (self.base_dir / 'data' / 'file1.txt').touch()
        (self.base_dir / 'data' / 'file2.txt').touch()
        (self.base_dir / 'data' / 'subdir').mkdir()
        
        files = self.fs.list_files('data', '*.txt')
        assert len(files) == 3  # test.txt, file1.txt, file2.txt
        assert all(f.name.endswith('.txt') for f in files)
        
    def test_list_files_recursive(self):
        ""Test listing files recursively."""
        # Create a nested directory structure
        (self.base_dir / 'data' / 'subdir').mkdir()
        (self.base_dir / 'data' / 'subdir' / 'nested.txt').touch()
        
        files = self.fs.list_files('data', '*.txt', recursive=True)
        assert len(files) == 2  # test.txt and nested.txt
        
    def test_create_temp_file(self):
        ""Test creating a temporary file."""
        with patch('tempfile.mkstemp') as mock_mkstemp:
            mock_mkstemp.return_value = (123, '/tmp/test123')
            
            result = self.fs.create_temp_file(suffix='.tmp', prefix='test_')
            assert str(result) == '/tmp/test123'
            
    def test_create_temp_dir(self):
        ""Test creating a temporary directory."""
        with patch('tempfile.mkdtemp') as mock_mkdtemp:
            mock_mkdtemp.return_value = '/tmp/testdir123'
            
            result = self.fs.create_temp_dir(prefix='test_')
            assert str(result) == '/tmp/testdir123'
            
    def test_get_file_system_singleton(self):
        ""Test that get_file_system returns a singleton instance."""
        fs1 = get_file_system()
        fs2 = get_file_system()
        assert fs1 is fs2
