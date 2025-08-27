import sys
import os
from pathlib import Path
from sqlite3 import Connection, Cursor
from typing import Optional, List, Dict, Any, Union, Tuple
import logging
from datetime import datetime, timedelta
import random
import json

# Add project root to Python path
project_root = str(Path(__file__).parent.parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(project_root, 'logs', 'db_init.log'))
    ]
)
logger = logging.getLogger('db_init')

# Sample data
EVENT_SOURCES = [
    'Windows Security', 'Firewall', 'Web Server', 'IDS', 'IPS',
    'Endpoint Protection', 'VPN', 'Authentication', 'Database'
]

EVENT_TYPES = [
    'Login Attempt', 'File Access', 'Network Connection', 'Policy Change',
    'User Account', 'System Event', 'Threat Detected', 'Configuration Change'
]

SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

def get_db_connection() -> Tuple[Connection, Cursor]:
    """Create a new database connection and cursor."""
    db_path = os.path.join(project_root, 'siem.db')
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        # Enable foreign key support
        conn.execute('PRAGMA foreign_keys = ON')
        # Set busy timeout
        conn.execute('PRAGMA busy_timeout = 30000')  # 30 seconds
        return conn, conn.cursor()
    except sqlite3.Error as e:
        logger.error(f"Error connecting to database: {e}")
        if conn:
            conn.close()
        raise

def create_tables() -> None:
    """Create all required database tables."""
    conn, cursor = get_db_connection()
    
    try:
        # Create events table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
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
        
        # Create alerts table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            rule_id INTEGER,
            status TEXT DEFAULT 'OPEN' CHECK(status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE')),
            assigned_to TEXT,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events(id),
            FOREIGN KEY (rule_id) REFERENCES rules(id)
        )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
        
        conn.commit()
        logger.info("Database tables created successfully")
        
    except sqlite3.Error as e:
        logger.error(f"Error creating tables: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()

def insert_sample_data() -> None:
    """Insert sample data into the database."""
    conn, cursor = get_db_connection()
    
    try:
        # Insert sample rules if none exist
        cursor.execute("SELECT COUNT(*) FROM rules")
        if cursor.fetchone()[0] == 0:
            sample_rules = [
                ('Failed Login Attempt', 'Multiple failed login attempts', '.*failed.*login.*', 'HIGH'),
                ('Port Scan Detected', 'Possible port scanning activity', 'port.*scan', 'HIGH'),
                ('Unauthorized Access', 'Unauthorized access attempt', 'unauthorized.*access', 'CRITICAL'),
                ('Policy Violation', 'Security policy violation', 'policy.*violation', 'MEDIUM'),
                ('Malware Detected', 'Malware detection alert', 'malware|virus|trojan', 'CRITICAL')
            ]
            
            cursor.executemany(
                """
                INSERT INTO rules (name, description, pattern, severity, is_active)
                VALUES (?, ?, ?, ?, 1)
                """,
                sample_rules
            )
            logger.info(f"Inserted {len(sample_rules)} sample rules")
        
        # Insert sample events if none exist
        cursor.execute("SELECT COUNT(*) FROM events")
        if cursor.fetchone()[0] == 0:
            sample_events = []
            now = datetime.utcnow()
            
            for i in range(1000):
                timestamp = now - timedelta(minutes=random.randint(0, 10080))  # Up to 1 week old
                source = random.choice(EVENT_SOURCES)
                event_type = random.choice(EVENT_TYPES)
                severity = random.choice(SEVERITIES)
                
                sample_events.append((
                    timestamp,
                    source,
                    event_type,
                    severity,
                    f"Sample event {i+1} - {event_type} from {source}",
                    json.dumps({"sample": True, "iteration": i+1})
                ))
            
            cursor.executemany(
                """
                INSERT INTO events (timestamp, source, event_type, severity, description, raw_data)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                sample_events
            )
            logger.info(f"Inserted {len(sample_events)} sample events")
            
            # Create some alerts for critical events
            cursor.execute("""
                INSERT INTO alerts (event_id, rule_id, status)
                SELECT e.id, r.id, 'OPEN'
                FROM events e
                CROSS JOIN rules r
                WHERE e.severity = 'CRITICAL'
                AND r.severity = 'CRITICAL'
                ORDER BY RANDOM()
                LIMIT 10
            """)
            
            logger.info("Created sample alerts for critical events")
        
        conn.commit()
        logger.info("Sample data inserted successfully")
        
    except sqlite3.Error as e:
        logger.error(f"Error inserting sample data: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()

def main():
    """Main function to initialize the database."""
    try:
        logger.info("Starting database initialization...")
        
        # Create database directory if it doesn't exist
        db_dir = os.path.dirname(os.path.join(project_root, 'siem.db'))
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        # Create logs directory if it doesn't exist
        logs_dir = os.path.join(project_root, 'logs')
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir, exist_ok=True)
        
        # Create tables
        create_tables()
        
        # Insert sample data
        insert_sample_data()
        
        logger.info("Database initialization completed successfully")
        return 0
        
    except Exception as e:
        logger.critical(f"Database initialization failed: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    import sqlite3
    sys.exit(main())
