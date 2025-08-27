import sqlite3
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('db_repair.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('siem.db_repair')

class DatabaseRepair:
    REQUIRED_TABLES = {
        'events': [
            ('id', 'INTEGER PRIMARY KEY AUTOINCREMENT'),
            ('timestamp', 'TIMESTAMP NOT NULL'),
            ('source', 'TEXT NOT NULL'),
            ('event_type', 'TEXT NOT NULL'),
            ('severity', 'INTEGER NOT NULL'),
            ('message', 'TEXT'),
            ('raw_data', 'TEXT')
        ],
        'alerts': [
            ('id', 'INTEGER PRIMARY KEY AUTOINCREMENT'),
            ('event_ids', 'TEXT NOT NULL'),
            ('alert_type', 'TEXT NOT NULL'),
            ('severity', 'INTEGER NOT NULL'),
            ('status', 'TEXT NOT NULL'),
            ('created_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'),
            ('resolved_at', 'TIMESTAMP'),
            ('description', 'TEXT')
        ]
    }
    
    REQUIRED_INDEXES = [
        'CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)',
        'CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)',
        'CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)',
        'CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)',
        'CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)'
    ]
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.conn: Optional[sqlite3.Connection] = None
    
    def connect(self) -> bool:
        """Establish database connection."""
        try:
            self.conn = sqlite3.connect(
                str(self.db_path),
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
                isolation_level='IMMEDIATE',
                timeout=30.0
            )
            self.conn.row_factory = sqlite3.Row
            self.conn.execute('PRAGMA foreign_keys = ON')
            self.conn.execute('PRAGMA journal_mode = WAL')
            self.conn.execute('PRAGMA synchronous = NORMAL')
            return True
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            return False
    
    def check_tables(self) -> Dict[str, List[str]]:
        """Check for missing tables and columns."""
        if not self.conn:
            raise RuntimeError("Database not connected")
            
        cursor = self.conn.cursor()
        issues = {'missing_tables': [], 'missing_columns': {}}
        
        # Check for missing tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = {row[0] for row in cursor.fetchall()}
        
        for table, columns in self.REQUIRED_TABLES.items():
            if table not in existing_tables:
                issues['missing_tables'].append(table)
                continue
                
            # Check for missing columns
            cursor.execute(f"PRAGMA table_info({table})")
            existing_columns = {row[1] for row in cursor.fetchall()}
            required_columns = {col[0] for col in columns}
            
            missing = required_columns - existing_columns
            if missing:
                issues['missing_columns'][table] = list(missing)
        
        # Check for missing indexes
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        existing_indexes = {row[0] for row in cursor.fetchall()}
        
        required_indexes = {
            idx.split()[-2].split('(')[0].split('.')[-1]: idx 
            for idx in self.REQUIRED_INDEXES
        }
        
        issues['missing_indexes'] = [
            name for name in required_indexes 
            if name not in existing_indexes
        ]
        
        return issues
    
    def repair_database(self) -> bool:
        """Repair database schema issues."""
        if not self.conn:
            raise RuntimeError("Database not connected")
            
        try:
            cursor = self.conn.cursor()
            issues = self.check_tables()
            
            # Create missing tables
            for table in issues.get('missing_tables', []):
                logger.info(f"Creating missing table: {table}")
                columns = ', '.join(f"{name} {type_}" for name, type_ in self.REQUIRED_TABLES[table])
                cursor.execute(f"CREATE TABLE {table} ({columns})")
            
            # Add missing columns
            for table, columns in issues.get('missing_columns', {}).items():
                for column in columns:
                    # Find the column definition
                    col_def = next(
                        (col for col in self.REQUIRED_TABLES[table] if col[0] == column),
                        None
                    )
                    if col_def:
                        logger.info(f"Adding column {table}.{column}")
                        try:
                            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_def[0]} {col_def[1]}")
                        except sqlite3.OperationalError as e:
                            if "duplicate column name" not in str(e):
                                raise
                            logger.warning(f"Column {table}.{column} already exists")
            
            # Create missing indexes
            for index_name in issues.get('missing_indexes', []):
                logger.info(f"Creating index: {index_name}")
                idx_sql = next(
                    sql for sql in self.REQUIRED_INDEXES 
                    if index_name in sql
                )
                cursor.execute(idx_sql)
            
            self.conn.commit()
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Failed to repair database: {e}")
            if self.conn:
                self.conn.rollback()
            return False
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Verify and repair SIEM database schema')
    parser.add_argument('--db', default='siem.db', help='Path to SQLite database file')
    parser.add_argument('--repair', action='store_true', help='Automatically repair issues')
    
    args = parser.parse_args()
    
    db_repair = DatabaseRepair(args.db)
    
    if not db_repair.connect():
        logger.error("Failed to connect to database")
        return 1
    
    try:
        issues = db_repair.check_tables()
        
        if any(issues.values()):
            logger.warning("Database issues found:")
            if issues['missing_tables']:
                logger.warning(f"  Missing tables: {', '.join(issues['missing_tables'])}")
            for table, columns in issues.get('missing_columns', {}).items():
                logger.warning(f"  Missing columns in {table}: {', '.join(columns)}")
            if issues.get('missing_indexes'):
                logger.warning(f"  Missing indexes: {', '.join(issues['missing_indexes'])}")
            
            if args.repair:
                logger.info("Attempting to repair database...")
                if db_repair.repair_database():
                    logger.info("Database repair completed successfully")
                else:
                    logger.error("Failed to repair database")
                    return 1
            else:
                logger.info("\nRun with --repair to fix these issues")
                return 1
        else:
            logger.info("No database issues found")
            
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1
    finally:
        db_repair.close()
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
