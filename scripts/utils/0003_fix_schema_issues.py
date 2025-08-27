"""
Migration script to fix database schema issues.

This migration:
1. Adds missing columns to the events table
2. Creates the missing alerts table
3. Adds required indexes
4. Fixes the timestamp column type
"""
import sqlite3
import logging
from datetime import datetime
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('migration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('siem.migration')

def run_migration(db_path: str = 'siem.db'):
    """Run the database migration."""
    # Check if database exists
    if not Path(db_path).exists():
        logger.error(f"Database file not found: {db_path}")
        return False
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Enable foreign keys
        cursor.execute('PRAGMA foreign_keys = ON')
        
        # Begin transaction
        cursor.execute('BEGIN TRANSACTION')
        
        # 1. Add missing columns to events table if they don't exist
        logger.info("Checking for missing columns in events table...")
        cursor.execute("PRAGMA table_info(events)")
        columns = [col[1].lower() for col in cursor.fetchall()]
        
        if 'category' not in columns:
            logger.info("Adding 'category' column to events table")
            cursor.execute('ALTER TABLE events ADD COLUMN category TEXT')
        
        if 'computer' not in columns:
            logger.info("Adding 'computer' column to events table")
            cursor.execute('ALTER TABLE events ADD COLUMN computer TEXT')
        
        if 'user' not in columns:
            logger.info("Adding 'user' column to events table")
            cursor.execute('ALTER TABLE events ADD COLUMN user TEXT')
        
        # 2. Create alerts table if it doesn't exist
        logger.info("Checking for alerts table...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                rule_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'New' CHECK(status IN ('New', 'In Progress', 'Resolved', 'False Positive')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE,
                FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE CASCADE
            )
        """)
        
        # 3. Create required indexes for alerts table
        logger.info("Creating indexes for alerts table...")
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_alerts_status 
            ON alerts(status)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_alerts_event_id 
            ON alerts(event_id)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_alerts_rule_id 
            ON alerts(rule_id)
        ''')
        
        # 4. Fix timestamp column type if needed
        cursor.execute('PRAGMA table_info(events)')
        timestamp_col = next((col for col in cursor.fetchall() if col[1].lower() == 'timestamp'), None)
        
        if timestamp_col and timestamp_col[2].upper() != 'TIMESTAMP':
            logger.info("Converting timestamp column from DATETIME to TIMESTAMP")
            # SQLite doesn't support ALTER COLUMN, so we need to recreate the table
            
            # Create a temporary table with the new schema
            cursor.execute('''
                CREATE TABLE events_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity INTEGER CHECK(severity BETWEEN 1 AND 5) NOT NULL,
                    description TEXT NOT NULL,
                    ip_address TEXT,
                    status TEXT DEFAULT 'New' CHECK(status IN ('New', 'In Progress', 'Resolved', 'False Positive')),
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    fingerprint TEXT,
                    category TEXT,
                    computer TEXT,
                    user TEXT
                )
            ''')
            
            # Copy data from old table to new table
            cursor.execute('''
                INSERT INTO events_new 
                SELECT * FROM events
            ''')
            
            # Drop old table and rename new one
            cursor.execute('DROP TABLE events')
            cursor.execute('ALTER TABLE events_new RENAME TO events')
            
            # Recreate indexes
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_timestamp 
                ON events(timestamp)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_source_type 
                ON events(source, event_type)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_severity_status 
                ON events(severity, status)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_fingerprint 
                ON events(fingerprint)
            ''')
        
        # Commit changes
        conn.commit()
        logger.info("Migration completed successfully")
        return True
        
    except sqlite3.Error as e:
        logger.error(f"Database error during migration: {e}")
        if 'conn' in locals():
            conn.rollback()
        return False
    except Exception as e:
        logger.error(f"Unexpected error during migration: {e}")
        if 'conn' in locals():
            conn.rollback()
        return False
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    import sys
    db_path = sys.argv[1] if len(sys.argv) > 1 else 'siem.db'
    success = run_migration(db_path)
    sys.exit(0 if success else 1)
