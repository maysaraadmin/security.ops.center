"""Initialize the SIEM database with proper schema."""
import os
import sqlite3
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('siem.db_init')

def init_database(db_path: str) -> None:
    """Initialize the database with required tables and indexes.
    
    Args:
        db_path: Path to the SQLite database file
    """
    try:
        # Ensure directory exists
        db_dir = os.path.dirname(os.path.abspath(db_path))
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"Created database directory: {db_dir}")
        
        # Connect to SQLite database (creates it if it doesn't exist)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Enable WAL mode for better concurrency
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=-2000")
        cursor.execute("PRAGMA temp_store=MEMORY")
        
        # Create events table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            description TEXT,
            ip_address TEXT,
            status TEXT DEFAULT 'New',
            raw_data TEXT,
            metadata TEXT,
            fingerprint TEXT,
            computer TEXT,
            user TEXT,
            category TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)')
        
        # Create rules table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            pattern TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            is_active BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create event_metadata table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS event_metadata (
            event_id INTEGER NOT NULL,
            key TEXT NOT NULL,
            value TEXT,
            PRIMARY KEY (event_id, key),
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        )
        ''')
        
        # Create event_tags table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS event_tags (
            event_id INTEGER NOT NULL,
            tag TEXT NOT NULL,
            PRIMARY KEY (event_id, tag),
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        )
        ''')
        
        # Create indexes for event_metadata and event_tags
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_metadata_key ON event_metadata(key)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_tags_tag ON event_tags(tag)')
        
        # Create settings table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            description TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Insert default settings if they don't exist
        default_settings = [
            ('retention_days', '90', 'Number of days to keep events before archiving'),
            ('log_level', 'INFO', 'Default logging level'),
            ('max_event_size', '1048576', 'Maximum size of an event in bytes'),
            ('alert_threshold', '100', 'Number of similar events to trigger an alert')
        ]
        
        cursor.executemany('''
        INSERT OR IGNORE INTO settings (key, value, description)
        VALUES (?, ?, ?)
        ''', default_settings)
        
        # Commit changes and close connection
        conn.commit()
        logger.info(f"Successfully initialized database at {db_path}")
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)
        raise
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    # Default database path (in the project root)
    db_path = str(Path(__file__).parent / 'siem.db')
    print(f"Initializing database at: {db_path}")
    init_database(db_path)
    print("Database initialization complete.")
