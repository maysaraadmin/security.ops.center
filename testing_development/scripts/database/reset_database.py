import os
import sqlite3
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/reset_database.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def backup_database():
    """Backup the current database."""
    if not os.path.exists('data/siem.db'):
        logger.info("No existing database found to backup")
        return True
        
    backup_dir = 'db_backups'
    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = os.path.join(backup_dir, f'siem_backup_{timestamp}.db')
    
    try:
        import shutil
        shutil.copy2('data/siem.db', backup_file)
        logger.info(f"Database backed up to {backup_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to backup database: {e}")
        return False

def create_database():
    """Create a new database with the correct schema."""
    os.makedirs('data', exist_ok=True)
    
    # Delete existing database if it exists
    if os.path.exists('data/siem.db'):
        try:
            os.remove('data/siem.db')
            logger.info("Removed existing database")
        except Exception as e:
            logger.error(f"Failed to remove existing database: {e}")
            return False
    
    try:
        conn = sqlite3.connect('data/siem.db')
        cursor = conn.cursor()
        
        # Enable WAL mode for better concurrency
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        
        # Create events table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity INTEGER NOT NULL,
            description TEXT,
            raw_data TEXT,
            category TEXT,
            status TEXT DEFAULT 'new',
            source_ip TEXT,
            destination_ip TEXT,
            user_agent TEXT,
            hostname TEXT,
            process_name TEXT,
            process_id INTEGER,
            parent_process_id INTEGER,
            command_line TEXT,
            file_path TEXT,
            file_hash TEXT,
            registry_key TEXT,
            registry_value TEXT,
            registry_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create indexes
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        ''')
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
        ''')
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
        ''')
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        ''')
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
        ''')
        
        # Create other necessary tables
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            rule_id INTEGER,
            description TEXT,
            severity INTEGER,
            status TEXT DEFAULT 'open',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events(id)
        )
        ''')
        
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        ''')
        
        # Create settings table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            is_active INTEGER DEFAULT 1,
            is_admin INTEGER DEFAULT 0,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create rules table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            condition TEXT NOT NULL,
            action TEXT,
            severity INTEGER,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Commit changes
        conn.commit()
        logger.info("Database schema created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create database: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    logger.info("Starting database reset...")
    
    # Backup existing database
    if not backup_database():
        logger.warning("Continuing without backup")
    
    # Create new database
    if create_database():
        logger.info("Database reset completed successfully")
    else:
        logger.error("Failed to reset database")
        exit(1)
