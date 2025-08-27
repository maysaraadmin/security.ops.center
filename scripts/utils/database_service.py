import sqlite3
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from ...models.database import Database
from ...models.db_pool import DatabasePool
from ..base_service import BaseService

class DatabaseService(BaseService):
    """Manages database connections and operations for the SIEM system."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("Database", config or {})
        self.db_path = self.config.get('db_path', 'siem.db')
        self.db_pool = None
        self.connection = None
        self._migrations_applied = False
    
    def start(self) -> bool:
        """Initialize the database service."""
        try:
            # Ensure the database directory exists
            db_path = Path(self.db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Initialize database pool
            self.db_pool = DatabasePool(
                db_path=str(db_path),
                max_connections=5,
                timeout=30.0
            )
            
            # Initialize database schema if needed
            self._initialize_database()
            
            # Apply migrations
            self._apply_migrations()
            
            self.is_running = True
            self.logger.info("Database service started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start database service: {str(e)}")
            self.is_running = False
            return False
    
    def stop(self) -> bool:
        """Clean up database connections."""
        try:
            if self.db_pool:
                self.db_pool.close_all()
                self.db_pool = None
            
            self.is_running = False
            self.logger.info("Database service stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping database service: {str(e)}")
            return False
    
    def status(self) -> Dict[str, Any]:
        """Get the current status of the database service."""
        return {
            'status': 'running' if self.is_running else 'stopped',
            'db_path': str(self.db_path),
            'connections': len(self.db_pool._connections) if self.db_pool else 0,
            'migrations_applied': self._migrations_applied
        }
    
    def _initialize_database(self) -> None:
        """Initialize the database with required tables."""
        try:
            with self.db_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create events table if it doesn't exist
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        source TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity INTEGER NOT NULL,
                        message TEXT NOT NULL,
                        raw_data TEXT,
                        processed BOOLEAN DEFAULT 0
                    )
                ''')
                
                # Create alerts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id INTEGER,
                        rule_id TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'open',
                        description TEXT,
                        FOREIGN KEY (event_id) REFERENCES events (id)
                    )
                ''')
                
                # Create service_status table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS service_status (
                        service_name TEXT PRIMARY KEY,
                        is_running BOOLEAN DEFAULT 0,
                        last_heartbeat DATETIME,
                        status_info TEXT
                    )
                ''')
                
                conn.commit()
                self.logger.info("Database schema initialized")
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {str(e)}")
            raise
    
    def _apply_migrations(self) -> None:
        """Apply any pending database migrations."""
        try:
            # Get a list of migration files in the migrations directory
            migrations_dir = Path(__file__).parent.parent.parent / 'migrations'
            if not migrations_dir.exists():
                self.logger.warning(f"Migrations directory not found: {migrations_dir}")
                return
                
            migration_files = sorted(migrations_dir.glob('*.py'))
            if not migration_files:
                self.logger.info("No migrations to apply")
                return
                
            # Create migrations table if it doesn't exist
            with self.db_pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS migrations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                conn.commit()
                
                # Get applied migrations
                cursor.execute('SELECT name FROM migrations')
                applied_migrations = {row[0] for row in cursor.fetchall()}
                
                # Apply pending migrations
                for migration_file in migration_files:
                    migration_name = migration_file.stem
                    if migration_name not in applied_migrations:
                        try:
                            self.logger.info(f"Applying migration: {migration_name}")
                            
                            # Import and run the migration
                            module_name = f"migrations.{migration_name}"
                            spec = importlib.util.spec_from_file_location(
                                module_name, str(migration_file)
                            )
                            migration = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(migration)
                            
                            # Run the migration
                            migration.apply(conn)
                            
                            # Record the migration
                            cursor.execute(
                                'INSERT INTO migrations (name) VALUES (?);',
                                (migration_name,)
                            )
                            conn.commit()
                            
                            self.logger.info(f"Successfully applied migration: {migration_name}")
                            
                        except Exception as e:
                            conn.rollback()
                            self.logger.error(f"Failed to apply migration {migration_name}: {str(e)}")
                            raise
                
                self._migrations_applied = True
                
        except Exception as e:
            self.logger.error(f"Error applying migrations: {str(e)}")
            raise
    
    def execute_query(self, query: str, params: tuple = ()) -> List[Tuple[Any, ...]]:
        """Execute a read-only query and return results."""
        if not self.is_running or not self.db_pool:
            raise RuntimeError("Database service is not running")
            
        with self.db_pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
    
    def execute_update(self, query: str, params: tuple = ()) -> int:
        """Execute an update/insert/delete query and return the number of affected rows."""
        if not self.is_running or not self.db_pool:
            raise RuntimeError("Database service is not running")
            
        with self.db_pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount
