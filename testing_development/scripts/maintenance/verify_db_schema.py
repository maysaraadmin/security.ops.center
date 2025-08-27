"""Verify and fix SIEM database schema."""
import sqlite3
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('siem.db_check')

class DatabaseSchema:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = None
        
    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()
            
    def check_table_exists(self, table_name: str) -> bool:
        """Check if a table exists in the database."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,)
        )
        return cursor.fetchone() is not None
        
    def check_columns_exist(self, table_name: str, required_columns: list) -> tuple[bool, list]:
        """Check if required columns exist in the table."""
        cursor = self.conn.cursor()
        cursor.execute(f"PRAGMA table_info({table_name})")
        existing_columns = [row['name'] for row in cursor.fetchall()]
        missing_columns = [col for col in required_columns if col not in existing_columns]
        return len(missing_columns) == 0, missing_columns
        
    def add_columns(self, table_name: str, columns: list):
        """Add missing columns to a table."""
        cursor = self.conn.cursor()
        for column in columns:
            try:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column} TEXT")
                logger.info(f"Added column '{column}' to table '{table_name}'")
            except sqlite3.OperationalError as e:
                if "duplicate column name" not in str(e):
                    raise
                logger.debug(f"Column '{column}' already exists in table '{table_name}'")
        
    def create_indexes(self, table_name: str, indexes: list):
        """Create indexes on the specified table."""
        cursor = self.conn.cursor()
        for index in indexes:
            index_name = f"idx_{table_name}_{'_'.join(index['columns'])}"
            columns = ", ".join(index['columns'])
            try:
                cursor.execute(
                    f"CREATE INDEX IF NOT EXISTS {index_name} "
                    f"ON {table_name} ({columns})"
                )
                logger.info(f"Created index {index_name} on {table_name}({columns})")
            except sqlite3.Error as e:
                logger.error(f"Error creating index {index_name}: {e}")

def verify_database(db_path: str):
    """Verify and fix the SIEM database schema."""
    if not os.path.exists(db_path):
        logger.error(f"Database file not found: {db_path}")
        return False
        
    with DatabaseSchema(db_path) as db:
        # Check and fix events table
        if not db.check_table_exists('events'):
            logger.error("Events table does not exist in the database")
            return False
            
        # Define required columns for events table
        required_columns = [
            'id', 'timestamp', 'source', 'event_type', 'severity',
            'description', 'ip_address', 'status', 'raw_data', 'metadata',
            'fingerprint'
        ]
        
        # Check and add missing columns
        columns_ok, missing_columns = db.check_columns_exist('events', required_columns)
        if not columns_ok:
            logger.warning(f"Missing columns in events table: {', '.join(missing_columns)}")
            db.add_columns('events', missing_columns)
            
        # Define and create indexes
        indexes = [
            {'columns': ['timestamp']},
            {'columns': ['source', 'event_type']},
            {'columns': ['severity', 'status']},
            {'columns': ['fingerprint']}
        ]
        db.create_indexes('events', indexes)
        
        # Commit changes
        db.conn.commit()
        
    logger.info("Database verification and fixes completed successfully")
    return True

if __name__ == "__main__":
    import sys
    db_path = sys.argv[1] if len(sys.argv) > 1 else 'siem.db'
    print(f"Verifying database: {db_path}")
    
    try:
        if verify_database(db_path):
            print("✅ Database is valid and up-to-date")
            sys.exit(0)
        else:
            print("❌ Database verification failed")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error verifying database: {e}", exc_info=True)
        sys.exit(1)
