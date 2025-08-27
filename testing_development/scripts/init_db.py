"""Initialize the SIEM database with required tables and indexes."""
import os
import sys
import sqlite3
from datetime import datetime, timedelta
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('init_db.log')
    ]
)
logger = logging.getLogger('siem.init_db')

# Database schema
SCHEMA = """
-- Events table
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity INTEGER NOT NULL,
    description TEXT,
    ip_address TEXT,
    status TEXT DEFAULT 'New',
    raw_data TEXT,
    metadata TEXT,
    category TEXT,
    computer TEXT,
    user TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_processed BOOLEAN DEFAULT 0
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

-- Event statistics table
CREATE TABLE IF NOT EXISTS event_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stat_date DATE NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stat_date, source, event_type, severity)
);
"""

def init_database(db_path: str = 'siem.db'):
    """Initialize the database with required schema and indexes."""
    try:
        # Convert to absolute path
        db_path = str(Path(db_path).absolute())
        logger.info(f"Initializing database at: {db_path}")
        
        # Create database directory if it doesn't exist
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        # Connect to SQLite database (creates it if it doesn't exist)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Enable WAL mode for better concurrency
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        
        # Execute schema creation
        cursor.executescript(SCHEMA)
        
        # Commit changes and close connection
        conn.commit()
        conn.close()
        
        logger.info("Database initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False

def generate_sample_data(db_path: str = 'siem.db', num_events: int = 1000):
    """Generate sample event data for testing."""
    import random
    from datetime import datetime, timedelta
    
    sources = ['Windows Security', 'Firewall', 'IDS', 'Web Server', 'Database']
    event_types = ['Login', 'Logout', 'Access Denied', 'File Access', 'Malware Detected', 'Policy Violation']
    severities = [1, 2, 3, 4, 5]
    statuses = ['New', 'In Progress', 'Resolved', 'False Positive']
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Clear existing data
        cursor.execute("DELETE FROM events;")
        cursor.execute("DELETE FROM event_stats;")
        
        # Generate sample events
        base_time = datetime.utcnow()
        for i in range(num_events):
            event_time = base_time - timedelta(minutes=random.randint(0, 60*24*7))  # Last 7 days
            source = random.choice(sources)
            event_type = random.choice(event_types)
            severity = random.choices(severities, weights=[0.4, 0.3, 0.15, 0.1, 0.05])[0]
            
            cursor.execute(
                """
                INSERT INTO events 
                (timestamp, source, event_type, severity, description, ip_address, status, category, computer, user)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_time.isoformat(),
                    source,
                    event_type,
                    severity,
                    f"Sample event {i+1} from {source} - {event_type}",
                    f"192.168.1.{random.randint(1, 254)}",
                    random.choice(statuses),
                    source.split()[0],
                    f"COMPUTER-{random.randint(1, 10)}",
                    f"user{random.randint(1, 20)}"
                )
            )
        
        # Generate sample stats
        for day in range(7):
            stat_date = (base_time - timedelta(days=day)).date()
            for source in sources:
                for event_type in event_types:
                    for severity in severities:
                        if random.random() > 0.7:  # Only include some combinations
                            cursor.execute(
                                """
                                INSERT INTO event_stats 
                                (stat_date, source, event_type, severity, count)
                                VALUES (?, ?, ?, ?, ?)
                                """,
                                (
                                    stat_date.isoformat(),
                                    source,
                                    event_type,
                                    severity,
                                    random.randint(1, 100)
                                )
                            )
        
        conn.commit()
        logger.info(f"Generated {num_events} sample events and statistics")
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate sample data: {e}", exc_info=True)
        if 'conn' in locals():
            conn.rollback()
        return False
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Initialize SIEM database')
    parser.add_argument('--db', default='siem.db', help='Path to SQLite database file')
    parser.add_argument('--sample-data', action='store_true', help='Generate sample data')
    parser.add_argument('--num-events', type=int, default=1000, help='Number of sample events to generate')
    
    args = parser.parse_args()
    
    if init_database(args.db):
        print(f"Database initialized successfully at {os.path.abspath(args.db)}")
        
        if args.sample_data:
            if generate_sample_data(args.db, args.num_events):
                print(f"Generated {args.num_events} sample events")
            else:
                print("Failed to generate sample data")
                sys.exit(1)
    else:
        print("Failed to initialize database")
        sys.exit(1)
