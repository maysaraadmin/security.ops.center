import sqlite3
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('db_integrity_check.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('siem.db_integrity')

class DatabaseIntegrityChecker:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.conn: Optional[sqlite3.Connection] = None
        self.issues: List[Dict[str, Any]] = []
    
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
            return True
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            return False
    
    def check_integrity(self) -> bool:
        """Run database integrity checks."""
        if not self.conn:
            logger.error("Database not connected")
            return False
        
        try:
            cursor = self.conn.cursor()
            
            # 1. Check database integrity
            cursor.execute("PRAGMA integrity_check")
            integrity = cursor.fetchone()
            if integrity and integrity[0] != 'ok':
                self.issues.append({
                    'type': 'database_integrity',
                    'severity': 'critical',
                    'message': f"Database integrity check failed: {integrity}"
                })
            
            # 2. Check foreign key constraints
            cursor.execute("PRAGMA foreign_key_check")
            fk_issues = cursor.fetchall()
            if fk_issues:
                for issue in fk_issues:
                    self.issues.append({
                        'type': 'foreign_key',
                        'severity': 'high',
                        'message': f"Foreign key constraint failed: {dict(issue)}"
                    })
            
            # 3. Check for orphaned records
            self._check_orphaned_records()
            
            # 4. Check for missing indexes
            self._check_missing_indexes()
            
            # 5. Check for table consistency
            self._check_table_consistency()
            
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error during integrity check: {e}")
            return False
    
    def _check_orphaned_records(self):
        """Check for orphaned records in related tables."""
        if not self.conn:
            return
            
        cursor = self.conn.cursor()
        
        # Check for alerts referencing non-existent events
        cursor.execute("""
            SELECT a.id, a.event_id 
            FROM alerts a
            LEFT JOIN events e ON a.event_id = e.id
            WHERE e.id IS NULL AND a.event_id IS NOT NULL
        """)
        orphaned_alerts = cursor.fetchall()
        
        if orphaned_alerts:
            self.issues.append({
                'type': 'orphaned_records',
                'severity': 'high',
                'message': f"Found {len(orphaned_alerts)} alerts referencing non-existent events",
                'details': [dict(alert) for alert in orphaned_alerts]
            })
    
    def _check_missing_indexes(self):
        """Check for missing indexes on frequently queried columns."""
        if not self.conn:
            return
            
        cursor = self.conn.cursor()
        
        # List of columns that should be indexed
        index_candidates = [
            ('events', 'timestamp'),
            ('events', 'source'),
            ('events', 'event_type'),
            ('events', 'severity'),
            ('alerts', 'status'),
            ('alerts', 'created_at'),
            ('alerts', 'event_id')
        ]
        
        for table, column in index_candidates:
            cursor.execute(f"""
                SELECT name FROM sqlite_master 
                WHERE type='index' AND tbl_name='{table}'
                AND sql LIKE '%{column}%'
            """)
            if not cursor.fetchone():
                self.issues.append({
                    'type': 'missing_index',
                    'severity': 'medium',
                    'message': f"Missing index on {table}.{column}",
                    'recommendation': f"CREATE INDEX idx_{table}_{column} ON {table}({column});"
                })
    
    def _check_table_consistency(self):
        """Check for table consistency issues."""
        if not self.conn:
            return
            
        cursor = self.conn.cursor()
        
        # Check for tables with no primary key
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' 
            AND name NOT LIKE 'sqlite_%'
            AND sql NOT LIKE '%PRIMARY KEY%'
        """)
        tables_without_pk = cursor.fetchall()
        
        for table in tables_without_pk:
            self.issues.append({
                'type': 'table_design',
                'severity': 'high',
                'message': f"Table {table['name']} has no primary key",
                'recommendation': "Add a primary key to the table"
            })
    
    def report_issues(self) -> bool:
        """Print a report of all found issues."""
        if not self.issues:
            logger.info("No issues found in the database.")
            return True
        
        logger.warning(f"Found {len(self.issues)} potential issues:")
        
        for i, issue in enumerate(self.issues, 1):
            print(f"\n{i}. [{issue['severity'].upper()}] {issue['type']}")
            print(f"   Message: {issue['message']}")
            
            if 'details' in issue:
                print(f"   Details: {issue['details']}")
            if 'recommendation' in issue:
                print(f"   Recommendation: {issue['recommendation']}")
        
        return False
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Check database integrity')
    parser.add_argument('--db', default='siem.db', help='Path to SQLite database file')
    
    args = parser.parse_args()
    
    checker = DatabaseIntegrityChecker(args.db)
    
    if not checker.connect():
        return 1
    
    try:
        if not checker.check_integrity():
            return 1
        
        has_issues = not checker.report_issues()
        return 0 if not has_issues else 1
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1
    finally:
        checker.close()

if __name__ == "__main__":
    import sys
    sys.exit(main())
