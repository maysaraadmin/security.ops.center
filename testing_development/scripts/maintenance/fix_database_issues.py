import sqlite3
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('db_fix.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('siem.db_fix')

class DatabaseFixer:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.backup_path = f"{db_path}.backup"
        self.conn: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None
    
    def connect(self) -> bool:
        """Establish database connection with WAL mode."""
        try:
            # Create backup before making changes
            self._backup_database()
            
            self.conn = sqlite3.connect(
                str(self.db_path),
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
                isolation_level='IMMEDIATE',
                timeout=60.0
            )
            self.conn.row_factory = sqlite3.Row
            self.cursor = self.conn.cursor()
            
            # Enable WAL mode for better concurrency
            self.cursor.execute('PRAGMA journal_mode=WAL')
            self.cursor.execute('PRAGMA synchronous=NORMAL')
            self.cursor.execute('PRAGMA foreign_keys=ON')
            
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            return False
    
    def _backup_database(self):
        """Create a backup of the database before making changes."""
        import shutil
        import time
        
        backup_file = f"{self.db_path}.backup.{int(time.time())}"
        logger.info(f"Creating database backup at: {backup_file}")
        shutil.copy2(self.db_path, backup_file)
    
    def fix_missing_indexes(self) -> bool:
        """Add missing indexes to improve query performance."""
        if not self.conn or not self.cursor:
            logger.error("Database not connected")
            return False
        
        try:
            # List of indexes to create
            indexes = [
                ("events", "timestamp", "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)"),
                ("alerts", "created_at", "CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)"),
                ("events", "source", "CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)"),
                ("events", "event_type", "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)"),
                ("alerts", "status", "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)"),
                ("alerts", "event_id", "CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id)")
            ]
            
            for table, column, sql in indexes:
                try:
                    logger.info(f"Creating index on {table}.{column}")
                    self.cursor.execute(sql)
                    self.conn.commit()
                except sqlite3.Error as e:
                    logger.warning(f"Failed to create index on {table}.{column}: {e}")
                    self.conn.rollback()
            
            return True
            
        except Exception as e:
            logger.error(f"Error fixing indexes: {e}")
            if self.conn:
                self.conn.rollback()
            return False
    
    def cleanup_old_tables(self) -> bool:
        """Remove old temporary tables."""
        if not self.conn or not self.cursor:
            logger.error("Database not connected")
            return False
        
        try:
            tables_to_drop = ["events_old", "events_temp"]
            
            for table in tables_to_drop:
                # Check if table exists
                self.cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?", 
                    (table,)
                )
                if self.cursor.fetchone():
                    logger.info(f"Dropping old table: {table}")
                    self.cursor.execute(f"DROP TABLE {table}")
                    self.conn.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error cleaning up old tables: {e}")
            if self.conn:
                self.conn.rollback()
            return False
    
    def optimize_database(self) -> bool:
        """Run optimization commands on the database."""
        if not self.conn or not self.cursor:
            logger.error("Database not connected")
            return False
        
        try:
            logger.info("Running VACUUM to optimize database")
            self.cursor.execute("VACUUM")
            
            logger.info("Running ANALYZE to update statistics")
            self.cursor.execute("ANALYZE")
            
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error optimizing database: {e}")
            if self.conn:
                self.conn.rollback()
            return False
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Fix common database issues')
    parser.add_argument('--db', default='siem.db', help='Path to SQLite database file')
    parser.add_argument('--fix-indexes', action='store_true', help='Fix missing indexes')
    parser.add_argument('--cleanup', action='store_true', help='Clean up old tables')
    parser.add_argument('--optimize', action='store_true', help='Optimize database')
    parser.add_argument('--all', action='store_true', help='Run all fixes')
    
    args = parser.parse_args()
    
    if not any([args.fix_indexes, args.cleanup, args.optimize, args.all]):
        parser.print_help()
        return 1
    
    fixer = DatabaseFixer(args.db)
    
    if not fixer.connect():
        return 1
    
    try:
        success = True
        
        if args.fix_indexes or args.all:
            logger.info("Fixing missing indexes...")
            success &= fixer.fix_missing_indexes()
        
        if args.cleanup or args.all:
            logger.info("Cleaning up old tables...")
            success &= fixer.cleanup_old_tables()
        
        if args.optimize or args.all:
            logger.info("Optimizing database...")
            success &= fixer.optimize_database()
        
        if success:
            logger.info("Database maintenance completed successfully")
        else:
            logger.error("Some operations failed. Check the logs for details.")
        
        return 0 if success else 1
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1
    finally:
        fixer.close()

if __name__ == "__main__":
    import sys
    sys.exit(main())
