#!/usr/bin/env python3
"""
Database Verification Script for SIEM System

This script verifies the database file and its contents.
"""
import os
import sys
import sqlite3

# Database path
db_path = os.path.abspath('data/siem.db')

def check_database():
    """Check if the database file exists and is accessible."""
    print(f"Checking database at: {db_path}")
    
    # Check if file exists
    if not os.path.exists(db_path):
        print("Error: Database file does not exist")
        print(f"Expected path: {db_path}")
        print("\nTrying to create the database file...")
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            # Create an empty database file
            with sqlite3.connect(db_path) as conn:
                conn.execute('CREATE TABLE test (id INTEGER PRIMARY KEY)')
                conn.execute('DROP TABLE test')
                
            print("Successfully created an empty database file")
            return True
            
        except Exception as e:
            print(f"Failed to create database file: {e}")
            return False
    
    # Check if file is readable/writable
    try:
        with open(db_path, 'a'):
            pass
        print("Database file is readable and writable")
    except IOError as e:
        print(f"Error accessing database file: {e}")
        return False
    
    # Check if it's a valid SQLite database
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            print("\nFound tables:")
            for table in tables:
                print(f"- {table[0]}")
                
                # Show columns for each table
                cursor.execute(f"PRAGMA table_info({table[0]})")
                columns = cursor.fetchall()
                for col in columns:
                    print(f"  - {col[1]} ({col[2]})")
            
            # Check WAL mode
            cursor.execute("PRAGMA journal_mode")
            print(f"\nJournal mode: {cursor.fetchone()[0]}")
            
            # Check foreign key constraints
            cursor.execute("PRAGMA foreign_keys")
            print(f"Foreign keys: {'ON' if cursor.fetchone()[0] else 'OFF'}")
            
            return True
            
    except sqlite3.Error as e:
        print(f"Error reading database: {e}")
        return False

def main():
    """Main function."""
    print("SIEM Database Verification Tool")
    print("=" * 80)
    
    if not check_database():
        print("\nDatabase verification failed!")
        sys.exit(1)
    
    print("\nDatabase verification completed successfully!")
    sys.exit(0)

if __name__ == "__main__":
    main()
