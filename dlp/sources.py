"""
Data Source Scanners for DLP

Scanners for different data sources (filesystem, databases, email, etc.)
"""
import os
import re
from abc import ABC, abstractmethod
from typing import AsyncGenerator, Dict, Any, Optional, List, Union
import aiofiles
import aiofiles.os
from pathlib import Path
import logging

logger = logging.getLogger('dlp.sources')

class BaseScanner(ABC):
    """Base class for all data source scanners."""
    
    def __init__(self, **kwargs):
        self.scan_type = self.__class__.__name__.replace('Scanner', '').lower()
        self.config = kwargs
        self.max_file_size = self.config.get('max_file_size', 10 * 1024 * 1024)  # 10MB default
        self.supported_mime_types = self.config.get('supported_mime_types', [])
        self.exclude_dirs = self.config.get('exclude_dirs', [])
        self.exclude_files = self.config.get('exclude_files', [])
    
    @abstractmethod
    async def scan(self, target: str) -> AsyncGenerator[tuple[str, Dict[str, Any]], None]:
        """Scan the target and yield (content, metadata) tuples."""
        raise NotImplementedError
    
    def should_scan(self, path: str, is_dir: bool = False) -> bool:
        """Determine if a path should be scanned."""
        path_str = str(path).lower()
        
        # Check exclude patterns
        if is_dir:
            for pattern in self.exclude_dirs:
                if re.search(pattern, path_str, re.IGNORECASE):
                    return False
        else:
            for pattern in self.exclude_files:
                if re.search(pattern, path_str, re.IGNORECASE):
                    return False
        
        return True

class FileSystemScanner(BaseScanner):
    """Scans local file systems for sensitive data."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.file_extensions = self.config.get('file_extensions', ['.txt', '.csv', '.json', '.xml', '.doc', '.docx', '.pdf', '.xls', '.xlsx'])
        self.recursive = self.config.get('recursive', True)
    
    async def scan(self, target: str) -> AsyncGenerator[tuple[str, Dict[str, Any]], None]:
        """Scan files in the target directory."""
        target_path = Path(target).expanduser().resolve()
        
        if not await aiofiles.os.path.exists(target_path):
            logger.warning(f"Target path does not exist: {target_path}")
            return
            
        if await aiofiles.os.path.isfile(target_path):
            async for result in self._scan_file(target_path):
                yield result
        elif self.recursive:
            async for root, _, files in self._walk(target_path):
                for file in files:
                    file_path = Path(root) / file
                    async for result in self._scan_file(file_path):
                        yield result
    
    async def _scan_file(self, file_path: Path) -> AsyncGenerator[tuple[str, Dict[str, Any]], None]:
        """Scan a single file."""
        if not self.should_scan(file_path):
            return
            
        try:
            # Check file extension
            if self.file_extensions and file_path.suffix.lower() not in self.file_extensions:
                return
                
            # Check file size
            file_size = (await aiofiles.os.path.getsize(file_path))
            if file_size > self.max_file_size:
                logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
                return
                
            # Read file content
            try:
                async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = await f.read()
            except UnicodeDecodeError:
                # Skip binary files or files with encoding issues
                return
                
            metadata = {
                'source': 'filesystem',
                'path': str(file_path),
                'size': file_size,
                'mime_type': self._detect_mime_type(file_path),
                'last_modified': await self._get_file_mtime(file_path)
            }
            
            yield content, metadata
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
    
    async def _walk(self, path: Path):
        """Walk directory tree, respecting exclusions."""
        try:
            async for entry in await aiofiles.os.scandir(path):
                if not self.should_scan(entry.path, entry.is_dir()):
                    continue
                    
                if entry.is_dir():
                    async for item in self._walk(Path(entry.path)):
                        yield item
                else:
                    yield path, [], [entry.name]
        except Exception as e:
            logger.error(f"Error walking directory {path}: {e}")
    
    def _detect_mime_type(self, file_path: Path) -> str:
        """Detect MIME type based on file extension."""
        # This is a simplified implementation
        # In production, use python-magic or similar
        ext = file_path.suffix.lower()
        mime_types = {
            '.txt': 'text/plain',
            '.csv': 'text/csv',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        }
        return mime_types.get(ext, 'application/octet-stream')
    
    async def _get_file_mtime(self, file_path: Path) -> float:
        """Get file modification time."""
        try:
            stat = await aiofiles.os.stat(file_path)
            return stat.st_mtime
        except Exception:
            return 0

class DatabaseScanner(BaseScanner):
    """Scans databases for sensitive data."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.driver = self.config.get('driver', 'postgresql')
        self.tables_to_scan = self.config.get('tables', [])
        self.exclude_tables = self.config.get('exclude_tables', [])
        self.sample_size = self.config.get('sample_size', 1000)
    
    async def scan(self, target: str) -> AsyncGenerator[tuple[str, Dict[str, Any]], None]:
        """Scan a database for sensitive data."""
        # This is a simplified implementation
        # In practice, you'd use an async database driver
        import sqlalchemy
        from sqlalchemy import create_engine, MetaData, Table
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        
        try:
            # Create async engine
            engine = create_async_engine(target, echo=False)
            async with engine.connect() as conn:
                # Get metadata
                metadata = MetaData()
                await conn.run_sync(metadata.reflect)
                
                # Scan tables
                for table_name, table in metadata.tables.items():
                    if not self._should_scan_table(table_name):
                        continue
                        
                    # Get sample data
                    query = table.select().limit(self.sample_size)
                    result = await conn.execute(query)
                    
                    # Process rows
                    for row in result:
                        for column in table.columns:
                            content = str(row[column.name])
                            if not content.strip():
                                continue
                                
                            metadata = {
                                'source': 'database',
                                'database': self.driver,
                                'table': table_name,
                                'column': column.name,
                                'data_type': str(column.type),
                                'row_id': row.get('id') if hasattr(row, 'get') else None
                            }
                            
                            yield content, metadata
                            
        except Exception as e:
            logger.error(f"Error scanning database: {e}")
            raise
    
    def _should_scan_table(self, table_name: str) -> bool:
        """Determine if a table should be scanned."""
        if self.tables_to_scan and table_name not in self.tables_to_scan:
            return False
            
        if table_name in self.exclude_tables:
            return False
            
        return True

class EmailScanner(BaseScanner):
    """Scans email messages for sensitive data."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.protocol = self.config.get('protocol', 'imap')  # or 'pop3', 'ews', etc.
        self.mailbox = self.config.get('mailbox', 'INBOX')
        self.limit = self.config.get('limit', 100)  # Max emails to scan
    
    async def scan(self, target: str) -> AsyncGenerator[tuple[str, Dict[str, Any]], None]:
        """Scan emails for sensitive data."""
        # This is a simplified implementation
        # In practice, you'd use an async email client
        try:
            # Connect to email server
            # email_client = await self._connect_email(target)
            
            # Get emails
            # emails = await email_client.get_emails(limit=self.limit)
            
            # Process emails
            # for email in emails:
            #     content = self._extract_email_content(email)
            #     metadata = {
            #         'source': 'email',
            #         'message_id': email.message_id,
            #         'subject': email.subject,
            #         'from': email.from_,
            #         'to': email.to,
            #         'date': email.date,
            #         'attachments': len(email.attachments)
            #     }
            #     yield content, metadata
            
            # Dummy implementation for now
            yield "", {
                'source': 'email',
                'status': 'not_implemented',
                'message': 'Email scanning not yet implemented'
            }
            
        except Exception as e:
            logger.error(f"Error scanning emails: {e}")
            raise

class CloudStorageScanner(BaseScanner):
    """Scans cloud storage (S3, Google Cloud Storage, etc.) for sensitive data."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.provider = self.config.get('provider', 's3')
        self.buckets = self.config.get('buckets', [])
        self.prefix = self.config.get('prefix', '')
    
    async def scan(self, target: str) -> AsyncGenerator[tuple[str, Dict[str, Any]], None]:
        """Scan cloud storage for sensitive data."""
        # This is a simplified implementation
        # In practice, you'd use the appropriate cloud SDK
        try:
            # Connect to cloud storage
            # client = self._get_cloud_client()
            
            # Scan buckets
            # for bucket in self._get_buckets_to_scan(client):
            #     async for obj in self._list_objects(client, bucket):
            #         content = await self._download_object(client, bucket, obj.key)
            #         metadata = {
            #             'source': 'cloud_storage',
            #             'provider': self.provider,
            #             'bucket': bucket,
            #             'key': obj.key,
            #             'size': obj.size,
            #             'last_modified': obj.last_modified
            #         }
            #         yield content, metadata
            
            # Dummy implementation for now
            yield "", {
                'source': 'cloud_storage',
                'status': 'not_implemented',
                'message': 'Cloud storage scanning not yet implemented'
            }
            
        except Exception as e:
            logger.error(f"Error scanning cloud storage: {e}")
            raise
