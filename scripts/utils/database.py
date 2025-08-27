import sqlite3
import logging
import os
import time
import threading
from typing import Iterator, List, Dict, Any, Optional, Tuple, Union, ContextManager
from pathlib import Path
from contextlib import contextmanager

# Import the connection pool
from .db_pool import get_db_pool, close_db_pool

# Configure logging
logger = logging.getLogger('siem.database')

class Database:
    _instance = None
    _initialized = False
    
    def __new__(cls, *args, **kwargs):
        """Implement singleton pattern for Database class."""
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, db_name: str = None):
        """Initialize the database with connection pooling.
        
        Args:
            db_name: Optional database name (defaults to 'siem.db' in project root)
            
        Raises:
            sqlite3.Error: If database initialization fails
        """
        # Use a class-level lock for thread-safe singleton initialization
        with threading.RLock():
            if not self._initialized:
                try:
                    self.db_name = db_name or str(Path(__file__).parent.parent.parent / 'data' / 'siem.db')
                    logger.info(f"Initializing database connection to {self.db_name}")
                    
                    # Ensure database directory exists
                    db_dir = os.path.dirname(os.path.abspath(self.db_name))
                    if db_dir and not os.path.exists(db_dir):
                        os.makedirs(db_dir, exist_ok=True)
                    
                    # Initialize connection pool
                    self._pool = get_db_pool()
                    self._lock = threading.RLock()  # Instance-level lock for database operations
                    self._closed = False
                    
                    # Verify connection and initialize schema
                    self._verify_connection()
                    self._ensure_tables_exist()
                    
                    # Register cleanup on program exit
                    import atexit
                    atexit.register(self.close)
                    
                    self._initialized = True
                    logger.info("Database initialization completed successfully")
                    
                except Exception as e:
                    logger.critical(f"Failed to initialize database: {e}", exc_info=True)
                    raise
    
    def _verify_connection(self):
        """Verify that the database connection is working."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            if result[0] != 1:
                raise sqlite3.Error("Database connection test failed")
    
    @contextmanager
    def get_connection(self):
        """Get a database connection from the pool.
        
        Yields:
            sqlite3.Connection: A database connection from the pool
            
        Example:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
        """
        if self._closed:
            raise sqlite3.Error("Database connection is closed")
            
        conn = self._pool.get_connection()
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            raise
        else:
            conn.commit()
        finally:
            self._pool.release_connection(conn)
    
    def cursor(self):
        """Get a database cursor for direct database access.
        
        Returns:
            sqlite3.Cursor: A database cursor object
        """
        if self._closed:
            raise sqlite3.Error("Database connection is closed")
        return self.get_connection().cursor()
    
    def rollback(self):
        """Roll back any pending transactions in the current connection.
        
        This is primarily used for error handling to ensure data consistency.
        """
        if self._closed:
            logger.warning("Cannot rollback: Database connection is closed")
            return
            
        with self._lock:
            conn = self.get_connection()
            conn.rollback()
            logger.debug("Transaction rolled back")
    
    def _ensure_tables_exist(self):
        """Ensure all required tables exist in the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Create events table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                    description TEXT,
                    raw_data TEXT,
                    processed BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for better query performance
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)
            ''')
            
            # Create rules table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    condition TEXT NOT NULL,
                    action TEXT NOT NULL,
                    severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                    enabled BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create alerts table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER,
                    event_id INTEGER,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT DEFAULT 'OPEN' CHECK(status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE')),
                    severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    resolved_at DATETIME,
                    FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE SET NULL,
                    FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE SET NULL
                )
            ''')
            
            # Create indexes for alerts
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)
            ''')
            
            # Create settings table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL UNIQUE,
                    value TEXT,
                    description TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create users table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE,
                    full_name TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    is_admin BOOLEAN DEFAULT 0,
                    last_login DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create audit log table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    entity_type TEXT,
                    entity_id INTEGER,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
                )
            ''')
            
            # Create indexes for audit log
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)
            ''')
            
            # Commit the changes
            conn.commit()
    
    @contextmanager
    def get_connection(self, timeout: float = 30.0) -> ContextManager[sqlite3.Connection]:
        """Get a database connection from the pool with a context manager.
        
        Args:
            timeout: Maximum time to wait for a connection (in seconds)
            
        Yields:
            A database connection
            
        Raises:
            sqlite3.OperationalError: If a connection cannot be obtained within the timeout
        """
        if self._closed:
            raise sqlite3.ProgrammingError("Cannot get connection: Database is closed")
        
        start_time = time.time()
        last_error = None
        
        while time.time() - start_time < timeout:
            try:
                conn = self._pool.get_connection()
                conn.row_factory = sqlite3.Row
                # Set timeout and enable foreign keys
                conn.execute("PRAGMA busy_timeout = 5000")  # 5 second timeout
                conn.execute("PRAGMA foreign_keys = ON")
                
                # Test the connection
                conn.execute("SELECT 1").fetchone()
                
                try:
                    yield conn
                    return
                except sqlite3.Error as e:
                    last_error = e
                    logger.error(f"Database error: {e}", exc_info=True)
                    if conn:
                        conn.rollback()
                    raise
                finally:
                    if conn:
                        self._pool.release_connection(conn)
            except sqlite3.OperationalError as e:
                last_error = e
                if "database is locked" in str(e).lower():
                    time.sleep(0.1)  # Small delay before retry
                    continue
                logger.error(f"Database operational error: {e}", exc_info=True)
                raise
            
        # If we get here, we've timed out
        error_msg = f"Failed to get database connection after {timeout} seconds"
        raise sqlite3.OperationalError(error_msg) from last_error
    
    def rollback(self):
        """Roll back any pending transactions in the current connection.
        
        This is primarily used for error handling to ensure data consistency.
        """
        if self._closed:
            logger.warning("Cannot rollback: Database connection is closed")
            return
            
        with self._lock:
            try:
                with self.get_connection() as conn:
                    conn.rollback()
                    logger.debug("Transaction rolled back successfully")
            except Exception as e:
                logger.error(f"Error during rollback: {e}", exc_info=True)
                raise
    
    def close(self):
        """Close the database connection pool.
        
        This should be called when the application is shutting down.
        """
        if not self._closed:
            with self._lock:
                if not self._closed:  # Double-checked locking pattern
                    logger.info("Closing database connection pool...")
                    close_db_pool()
                    self._closed = True
                    logger.info("Database connection pool closed")
    
    def __del__(self):
        """Ensure the connection pool is closed when the object is destroyed."""
        try:
            self.close()
        except Exception:
            # Suppress any exceptions during garbage collection
            pass
