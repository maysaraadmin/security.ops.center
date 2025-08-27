"""
Pytest configuration and fixtures for testing the SIEM system.
"""
import os
import sys
from pathlib import Path
import pytest
import tempfile
import sqlite3
from typing import Generator, Dict, Any

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Test data directory
TEST_DATA_DIR = Path(__file__).parent / "data"


@pytest.fixture(scope="session")
def test_data_dir() -> Path:
    """Return the path to the test data directory."""
    TEST_DATA_DIR.mkdir(exist_ok=True)
    return TEST_DATA_DIR


@pytest.fixture(scope="function")
def temp_db() -> Generator[sqlite3.Connection, None, None]:
    """
    Create a temporary SQLite database for testing.
    
    Yields:
        sqlite3.Connection: A connection to the temporary database
    """
    # Create a temporary file for the database
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
        db_path = tmp.name
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        # Enable dictionary-style access to rows
        conn.row_factory = sqlite3.Row
        
        # Enable foreign key constraints
        conn.execute("PRAGMA foreign_keys = ON")
        
        # Create necessary tables
        with conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity INTEGER DEFAULT 1,
                    description TEXT,
                    raw_data TEXT,
                    status TEXT DEFAULT 'new',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
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
                );
            """)
        
        yield conn
    finally:
        # Clean up
        if 'conn' in locals():
            conn.close()
        try:
            os.unlink(db_path)
        except OSError:
            pass


@pytest.fixture(scope="function")
def db_cursor(temp_db: sqlite3.Connection) -> sqlite3.Cursor:
    """Return a database cursor for testing."""
    return temp_db.cursor()


@pytest.fixture(scope="function")
def sample_event_data() -> Dict[str, Any]:
    """Return sample event data for testing."""
    return {
        "source": "test_source",
        "event_type": "test_event",
        "severity": 2,
        "description": "Test event description",
        "raw_data": '{"key": "value"}',
        "status": "new"
    }
