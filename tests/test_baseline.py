"""
Tests for the BaselineManager class in fim.baseline
"""
import os
import sys
import time
import tempfile
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fim.baseline import BaselineManager

class TestBaselineManager(unittest.TestCase):
    """Test cases for the BaselineManager class."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.baseline_file = os.path.join(self.test_dir, 'test_baseline.json')
        self.config = {
            'baseline_file': self.baseline_file,
            'hash_algorithm': 'sha256',
            'exclude_patterns': ['*.tmp', '*.log'],
            'include_patterns': ['*']
        }
        self.manager = BaselineManager(self.config)
        
        # Create some test files
        self.test_files = {
            'file1.txt': 'This is a test file',
            'subdir/file2.txt': 'Another test file',
            'subdir/ignore.tmp': 'Temporary file to ignore',
            'subdir/subsubdir/file3.txt': 'Nested test file'
        }
        
        for rel_path, content in self.test_files.items():
            abs_path = os.path.join(self.test_dir, rel_path)
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            with open(abs_path, 'w') as f:
                f.write(content)
    
    def tearDown(self):
        """Clean up test environment."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_create_baseline(self):
        """Test creating a baseline."""
        # Create baseline for the test directory
        result = self.manager.create_baseline([self.test_dir])
        self.assertTrue(result)
        
        # Verify baseline contains expected files
        self.assertEqual(len(self.manager.baseline), 3)  # 3 files, 1 excluded by pattern
        
        # Check that excluded file is not in baseline
        excluded_file = os.path.join(self.test_dir, 'subdir/ignore.tmp')
        self.assertNotIn(excluded_file, self.manager.baseline)
        
        # Check that included files are in baseline
        for rel_path in ['file1.txt', 'subdir/file2.txt', 'subdir/subsubdir/file3.txt']:
            file_path = os.path.join(self.test_dir, rel_path)
            self.assertIn(file_path, self.manager.baseline)
    
    def test_save_and_load_baseline(self):
        """Test saving and loading a baseline."""
        # Create and save baseline
        self.manager.create_baseline([self.test_dir])
        self.assertTrue(self.manager.save_baseline())
        self.assertTrue(os.path.exists(self.baseline_file))
        
        # Create a new manager and load the baseline
        new_manager = BaselineManager(self.config)
        self.assertTrue(new_manager.load_baseline())
        
        # Verify loaded baseline matches original
        self.assertEqual(len(new_manager.baseline), 3)
        for path, meta in new_manager.baseline.items():
            self.assertIn(path, self.manager.baseline)
            self.assertEqual(meta['size'], self.manager.baseline[path]['size'])
    
    def test_verify_baseline_no_changes(self):
        """Test baseline verification with no changes."""
        # Create baseline
        self.manager.create_baseline([self.test_dir])
        
        # Verify baseline (no changes expected)
        results = self.manager.verify_baseline()
        
        # No changes should be detected
        self.assertEqual(len(results['added']), 0)
        self.assertEqual(len(results['modified']), 0)
        self.assertEqual(len(results['deleted']), 0)
        self.assertEqual(len(results['permission_changes']), 0)
        self.assertEqual(len(results['owner_changes']), 0)
    
    def test_detect_added_file(self):
        """Test detection of new files."""
        # Create baseline with initial files
        self.manager.create_baseline([self.test_dir])
        
        # Add a new file
        new_file = os.path.join(self.test_dir, 'new_file.txt')
        with open(new_file, 'w') as f:
            f.write('This is a new file')
        
        # Verify baseline should detect the new file
        results = self.manager.verify_baseline()
        self.assertEqual(len(results['added']), 1)
        self.assertEqual(os.path.normpath(results['added'][0]['path']), 
                        os.path.normpath(new_file))
    
    def test_detect_modified_file(self):
        """Test detection of modified files."""
        # Create baseline with initial files
        file_to_modify = os.path.join(self.test_dir, 'file1.txt')
        self.manager.create_baseline([self.test_dir])
        
        # Modify a file
        with open(file_to_modify, 'a') as f:
            f.write('\nModified content')
        
        # Verify baseline should detect the modification
        results = self.manager.verify_baseline()
        self.assertEqual(len(results['modified']), 1)
        self.assertEqual(os.path.normpath(results['modified'][0]['path']), 
                        os.path.normpath(file_to_modify))
    
    def test_detect_deleted_file(self):
        """Test detection of deleted files."""
        # Create baseline with initial files
        file_to_delete = os.path.join(self.test_dir, 'file1.txt')
        self.manager.create_baseline([self.test_dir])
        
        # Delete a file
        os.remove(file_to_delete)
        
        # Verify baseline should detect the deletion
        results = self.manager.verify_baseline()
        self.assertEqual(len(results['deleted']), 1)
        self.assertEqual(os.path.normpath(results['deleted'][0]['path']), 
                        os.path.normpath(file_to_delete))
    
    @patch('os.stat')
    def test_detect_permission_changes(self, mock_stat):
        """Test detection of permission changes."""
        # Create a mock for os.stat
        mock_stat.return_value = MagicMock(
            st_mode=0o100644,  # Original permissions
            st_size=123,
            st_mtime=time.time(),
            st_ctime=time.time(),
            st_uid=1000,
            st_gid=1000,
            st_ino=12345,
            st_dev=1
        )
        
        # Create baseline
        file_path = os.path.join(self.test_dir, 'file1.txt')
        self.manager.create_baseline([file_path])
        
        # Change permissions
        mock_stat.return_value = MagicMock(
            st_mode=0o100755,  # New permissions
            st_size=123,
            st_mtime=time.time(),
            st_ctime=time.time(),
            st_uid=1000,
            st_gid=1000,
            st_ino=12345,
            st_dev=1
        )
        
        # Verify baseline should detect the permission change
        results = self.manager.verify_baseline()
        self.assertEqual(len(results['permission_changes']), 1)
        self.assertEqual(os.path.normpath(results['permission_changes'][0]['path']), 
                        os.path.normpath(file_path))
    
    def test_ignore_patterns(self):
        """Test that ignore patterns are respected."""
        # Create a file that matches the exclude pattern
        excluded_file = os.path.join(self.test_dir, 'temp.tmp')
        with open(excluded_file, 'w') as f:
            f.write('This should be ignored')
        
        # Create baseline - should ignore the .tmp file
        self.manager.create_baseline([self.test_dir])
        self.assertNotIn(excluded_file, self.manager.baseline)
        
        # Create a new file with a different extension
        included_file = os.path.join(self.test_dir, 'included.txt')
        with open(included_file, 'w') as f:
            f.write('This should be included')
        
        # Verify baseline should detect the new file but not the excluded one
        results = self.manager.verify_baseline()
        self.assertEqual(len(results['added']), 1)
        self.assertEqual(os.path.normpath(results['added'][0]['path']), 
                        os.path.normpath(included_file))
    
    def test_get_baseline_stats(self):
        """Test getting baseline statistics."""
        # Create baseline
        self.manager.create_baseline([self.test_dir])
        
        # Get stats
        stats = self.manager.get_baseline_stats()
        
        # Verify stats
        self.assertEqual(stats['status'], 'loaded')
        self.assertEqual(stats['file_count'], 3)  # 3 files, 1 excluded
        self.assertGreater(stats['total_size'], 0)
        self.assertIn('.txt', stats['file_types'])
        self.assertEqual(stats['file_types']['.txt'], 3)
        self.assertIsNotNone(stats['oldest_file'])
        self.assertIsNotNone(stats['newest_file'])
        self.assertIsNotNone(stats['last_verified'])


if __name__ == '__main__':
    unittest.main()
