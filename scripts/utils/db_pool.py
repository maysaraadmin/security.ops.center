"""Database connection pool implementation."""
import sqlite3
from queue import Queue
import logging
from pathlib import Path
import os

logger = logging.getLogger('siem.db_pool')

class DatabaseConnectionPool:
    """A simple database connection pool for SQLite."""
    
    def __init__(self, db_path=None, pool_size=5):
        """Initialize the connection pool.
        
        Args:
            db_path: Path to the SQLite database file
            pool_size: Maximum number of connections to keep in the pool
        """
        if db_path is None:
            # Default to database in the project root
            db_path = str(Path(__file__).parent.parent / 'siem.db')
            
        self.db_path = db_path
        self.pool_size = pool_size
        self._pool = Queue(maxsize=pool_size)
        self._active_connections = 0
        
        # Create database directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        
        # Initialize the pool with connections
        self._initialize_pool()
        
        logger.info(f"Initialized database connection pool with {pool_size} connections")
    
    def _create_connection(self):
        """Create a new database connection with optimal settings."""
        conn = sqlite3.connect(
            self.db_path,
            timeout=30.0,  # 30 second timeout
            isolation_level=None,  # Autocommit mode
            check_same_thread=False  # Allow connections from different threads
        )
        
        # Optimize SQLite settings for better performance
        conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
        conn.execute("PRAGMA synchronous=NORMAL")  # Faster writes, less safe
        conn.execute("PRAGMA cache_size=-2000")  # 2MB cache
        conn.execute("PRAGMA temp_store=MEMORY")  # Store temp tables in memory
        conn.execute("PRAGMA mmap_size=268435456")  # 256MB memory-mapped I/O
        
        # Enable foreign key constraints
        conn.execute("PRAGMA foreign_keys=ON")
        
        return conn
    
    def _initialize_pool(self):
        """Initialize the connection pool with connections."""
        for _ in range(min(2, self.pool_size)):  # Start with 2 connections
            self._pool.put(self._create_connection())
            self._active_connections += 1
    
    def get_connection(self):
        """Get a database connection from the pool."""
        try:
            # If we haven't reached max pool size and queue is empty, create a new connection
            if self._active_connections < self.pool_size and self._pool.empty():
                self._active_connections += 1
                return self._create_connection()
                
            # Wait for a connection with a timeout
            return self._pool.get(timeout=10.0)
            
        except Exception as e:
            logger.error(f"Failed to get database connection: {e}")
            raise
    
    def release_connection(self, conn):
        """Return a connection to the pool."""
        if conn is not None:
            try:
                # Reset the connection state
                conn.rollback()
                
                # Return to pool if we're not over capacity
                if self._pool.qsize() < self.pool_size:
                    self._pool.put(conn)
                else:
                    conn.close()
                    self._active_connections -= 1
                    
            except Exception as e:
                logger.error(f"Error releasing connection: {e}", exc_info=True)
                try:
                    if conn and not conn.closed:
                        conn.rollback()  # Ensure any pending transactions are rolled back
                        conn.close()
                except Exception as close_error:
                    logger.debug(f"Error closing connection: {close_error}")
                finally:
                    self._active_connections = max(0, self._active_connections - 1)
    
    def close_all(self):
        """Close all connections in the pool."""
        logger.info("Closing all database connections...")
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                if conn:
                    conn.close()
            except Exception as e:
                logger.error(f"Error closing connection: {e}")
        self._active_connections = 0

# Global connection pool instance
_db_pool = None

def get_db_pool():
    """Get the global database connection pool."""
    global _db_pool
    if _db_pool is None:
        _db_pool = DatabaseConnectionPool()
    return _db_pool

def close_db_pool():
    """Close the global database connection pool."""
    global _db_pool
    if _db_pool is not None:
        _db_pool.close_all()
        _db_pool = None
