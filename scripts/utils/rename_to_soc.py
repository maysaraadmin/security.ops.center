#!/usr/bin/env python3
"""Script to rename SIEM project to Security Operation Center (SOC)."""
import os
import re
import shutil
from pathlib import Path

class ProjectRenamer:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir).resolve()
        self.soc_dir = self.base_dir.parent / 'soc'
        self.mapping = {
            'siem': 'soc',
            'SIEM': 'SOC',
            'Siem': 'SOC',
            'Security Information and Event Management': 'Security Operations Center',
            'security information and event management': 'security operations center',
        }
        
    def create_soc_structure(self):
        """Create the new SOC directory structure."""
        dirs = [
            # Core
            'soc/core',
            'soc/models',
            'soc/services',
            'soc/api',
            'soc/ui',
            
            # Security modules
            'soc/modules/edr',
            'soc/modules/dlp',
            'soc/modules/fim',
            'soc/modules/ndr',
            'soc/modules/nips',
            'soc/modules/hips',
            'soc/modules/ueba',
            
            # Infrastructure
            'soc/infrastructure/config',
            'soc/infrastructure/database',
            'soc/infrastructure/utils',
            
            # Testing & Development
            'soc/tests/unit',
            'soc/tests/integration',
            'soc/scripts',
            'soc/docs',
        ]
        
        for directory in dirs:
            path = self.base_dir.parent / directory
            path.mkdir(parents=True, exist_ok=True)
            (path / '__init__.py').touch(exist_ok=True)
    
    def copy_and_rename_files(self):
        """Copy files from SIEM to SOC with updated content."""
        # Create mapping of old paths to new paths
        path_mapping = {
            'siem/': 'soc/',
            'security_modules/': 'soc/modules/',
            'infrastructure/': 'soc/infrastructure/',
            'testing_development/tests/': 'soc/tests/',
            'testing_development/scripts/': 'soc/scripts/',
            'testing_development/docs/': 'soc/docs/',
        }
        
        # Copy and update files
        for src_pattern, dest_pattern in path_mapping.items():
            src_dir = self.base_dir / src_pattern.rstrip('/')
            if not src_dir.exists():
                continue
                
            for src_file in src_dir.rglob('*'):
                if src_file.is_dir() or '__pycache__' in str(src_file):
                    continue
                    
                # Calculate destination path
                rel_path = src_file.relative_to(self.base_dir / src_pattern.split('/')[0])
                dest_file = self.base_dir.parent / dest_pattern.rstrip('/') / rel_path
                
                # Create destination directory if it doesn't exist
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                
                # Update file content and copy
                if src_file.suffix in ('.py', '.md', '.txt', '.yaml', '.yml', '.conf'):
                    self._update_file_content(src_file, dest_file)
                else:
                    shutil.copy2(src_file, dest_file)
    
    def _update_file_content(self, src_file, dest_file):
        """Update file content with new naming."""
        with open(src_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace all occurrences of old names
        for old, new in self.mapping.items():
            content = content.replace(old, new)
        
        # Update import paths
        content = re.sub(
            r'(from\s+|import\s+)(siem|security_modules|infrastructure|testing_development\.tests|testing_development\.scripts|testing_development\.docs)',
            lambda m: f"{m.group(1)}{self._map_import_path(m.group(2))}",
            content
        )
        
        # Write updated content to destination
        with open(dest_file, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def _map_import_path(self, old_path):
        """Map old import paths to new ones."""
        mapping = {
            'siem': 'soc',
            'security_modules': 'soc.modules',
            'infrastructure': 'soc.infrastructure',
            'testing_development.tests': 'soc.tests',
            'testing_development.scripts': 'soc.scripts',
            'testing_development.docs': 'soc.docs',
        }
        return mapping.get(old_path, old_path)
    
    def update_package_metadata(self):
        """Update package metadata files."""
        # Update setup.py
        setup_py = self.base_dir.parent / 'soc' / 'setup.py'
        if setup_py.exists():
            with open(setup_py, 'r', encoding='utf-8') as f:
                content = f.read()
            
            content = re.sub(
                r'name=[\"\']siem[\"\']', 
                'name="security-operation-center"', 
                content
            )
            content = re.sub(
                r'description=[\"\'].*?[\"\']', 
                'description="Security Operation Center (SOC) - Advanced security monitoring and incident response system"', 
                content
            )
            
            with open(setup_py, 'w', encoding='utf-8') as f:
                f.write(content)
        
        # Update README.md
        readme = self.base_dir.parent / 'README.md'
        if readme.exists():
            with open(readme, 'r', encoding='utf-8') as f:
                content = f.read()
            
            content = re.sub('SIEM', 'SOC', content)
            content = re.sub('Security Information and Event Management', 'Security Operations Center', content)
            
            with open(readme, 'w', encoding='utf-8') as f:
                f.write(content)

def main():
    """Main function to execute the renaming process."""
    base_dir = Path(__file__).parent.parent
    renamer = ProjectRenamer(base_dir)
    
    print("Creating new SOC directory structure...")
    renamer.create_soc_structure()
    
    print("Copying and updating files...")
    renamer.copy_and_rename_files()
    
    print("Updating package metadata...")
    renamer.update_package_metadata()
    
    print("\nProject renamed to Security Operation Center (SOC) successfully!")
    print("Next steps:")
    print("1. Review the changes in the new 'soc' directory")
    print("2. Update any remaining hardcoded references")
    print("3. Run tests to ensure everything works")
    print("4. Remove the old 'siem' directory once you've verified everything works")

if __name__ == "__main__":
    main()
