import sqlite3
import os

def create_database():
    db_path = 'D:\\siem\\data\\siem.db'
    
    # Remove existing database if it exists
    if os.path.exists(db_path):
        os.remove(db_path)
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    # Connect to the database (this will create it)
    conn = sqlite3.connect(db_path)
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
    
    # Create alerts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'open',
        severity INTEGER DEFAULT 1,
        source TEXT,
        category TEXT,
        assigned_to TEXT,
        resolution TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        resolved_at DATETIME,
        FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE SET NULL
    )
    ''')
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        email TEXT UNIQUE,
        role TEXT DEFAULT 'analyst',
        is_active BOOLEAN DEFAULT 1,
        last_login DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create settings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        value TEXT,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
    
    # Insert default admin user if users table is empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
        INSERT INTO users (username, password_hash, full_name, email, role, is_active)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', 'hashed_password_here', 'Administrator', 'admin@example.com', 'admin', 1))
    
    # Insert default settings if settings table is empty
    cursor.execute("SELECT COUNT(*) FROM settings")
    if cursor.fetchone()[0] == 0:
        default_settings = [
            ('system_name', 'SIEM System', 'Name of the SIEM system'),
            ('retention_days', '90', 'Number of days to retain events'),
            ('alert_threshold', '5', 'Number of similar events before creating an alert'),
            ('email_notifications', '0', 'Enable email notifications (0/1)')
        ]
        cursor.executemany('''
        INSERT INTO settings (key, value, description)
        VALUES (?, ?, ?)
        ''', default_settings)
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print(f"Database created successfully at {db_path}")
    print("Tables created: events, alerts, users, settings")
    print("Default admin user created: username=admin, password=hashed_password_here")
    print("IMPORTANT: Change the default admin password after first login!")

if __name__ == "__main__":
    create_database()
