"""
EDR Server - Endpoint Detection and Response Server

Core server component for the EDR system that receives and processes
security events from endpoints.
"""

import os
import json
import time
import logging
import sqlite3
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import hashlib
import hmac
import secrets
import jwt
from typing import Dict, List, Optional, Any, Tuple, Callable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('edr_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('edr.server')

class EDRServerConfig:
    """Configuration for the EDR server."""
    def __init__(self, config_path: Optional[str] = None):
        # Default configuration
        self.host = '0.0.0.0'
        self.port = 8000
        self.database = 'edr_server.db'
        self.jwt_secret = secrets.token_hex(32)
        self.token_expiry = 86400  # 24 hours
        self.rate_limit = 1000  # Max requests per minute per IP
        self.max_event_batch = 1000
        
        # Load from config file if provided
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
    
    def _load_config(self, config_path: str) -> None:
        """Load configuration from a JSON file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                for key, value in config.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")

class EDRDatabase:
    """Handles database operations for the EDR server."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize the database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Endpoints table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS endpoints (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    os TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    is_online INTEGER DEFAULT 0
                )
            ''')
            
            # Events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    endpoint_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    data TEXT NOT NULL,
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints (id)
                )
            ''')
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    endpoint_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_updated TEXT NOT NULL,
                    event_count INTEGER DEFAULT 1,
                    events TEXT DEFAULT '[]',
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints (id)
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_endpoint_id ON events(endpoint_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
            
            conn.commit()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

class EDRRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the EDR server API."""
    
    def __init__(self, *args, **kwargs):
        self.server_config = kwargs.pop('server_config')
        self.db = kwargs.pop('database')
        super().__init__(*args, **kwargs)
    
    def do_POST(self) -> None:
        """Handle POST requests."""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/api/events':
            self._handle_events()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Not found'}).encode())
    
    def _handle_events(self) -> None:
        """Handle incoming events from endpoints."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'No content'}).encode())
            return
        
        try:
            # Read and parse request body
            body = self.rfile.read(content_length)
            data = json.loads(body)
            
            # Validate required fields
            if 'endpoint_id' not in data or 'events' not in data:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Missing required fields'}).encode())
                return
            
            # Save events to database
            saved_count = self.db.save_events(data['endpoint_id'], data['events'])
            
            # Update endpoint info if provided
            if 'endpoint_info' in data:
                self.db.update_endpoint(data['endpoint_info'])
            
            # Return success response
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'status': 'success',
                'saved_events': saved_count
            }).encode())
            
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Invalid JSON'}).encode())
        except Exception as e:
            logger.error(f"Error processing events: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Internal server error'}).encode())
    
    def log_message(self, format: str, *args) -> None:
        """Override to use our logger instead of stderr."""
        logger.info("%s - - [%s] %s",
                   self.address_string(),
                   self.log_date_time_string(),
                   format%args)

class EDRServer:
    """Main EDR server class."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the EDR server."""
        self.config = EDRServerConfig(config_path)
        self.db = EDRDatabase(self.config.database)
        self.server = None
        self.cleanup_thread = None
        self.running = False
    
    def start(self) -> None:
        """Start the EDR server."""
        if self.running:
            return
        
        # Start the HTTP server
        def handler(*args):
            return EDRRequestHandler(
                *args, 
                server_config=self.config,
                database=self.db
            )
        
        self.server = HTTPServer((self.config.host, self.config.port), handler)
        self.running = True
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_old_events,
            daemon=True
        )
        self.cleanup_thread.start()
        
        logger.info(f"Starting EDR server on {self.config.host}:{self.config.port}")
        self.server.serve_forever()
    
    def stop(self) -> None:
        """Stop the EDR server."""
        if not self.running:
            return
            
        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        
        logger.info("EDR server stopped")
    
    def _cleanup_old_events(self) -> None:
        """Background thread to clean up old events."""
        while self.running:
            try:
                # Clean up events older than 30 days
                cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()
                with self.db._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'DELETE FROM events WHERE timestamp < ?',
                        (cutoff,)
                    )
                    deleted = cursor.rowcount
                    if deleted > 0:
                        logger.info(f"Cleaned up {deleted} old events")
                    conn.commit()
            except Exception as e:
                logger.error(f"Error in cleanup thread: {e}")
            
            # Run cleanup once per hour
            time.sleep(3600)

def main():
    """Entry point for the EDR server."""
    import argparse
    
    parser = argparse.ArgumentParser(description='EDR Server')
    parser.add_argument('--config', type=str, help='Path to config file')
    parser.add_argument('--host', type=str, help='Host to bind to')
    parser.add_argument('--port', type=int, help='Port to listen on')
    
    args = parser.parse_args()
    
    # Create and configure server
    server = EDRServer(args.config)
    
    # Override config from command line
    if args.host:
        server.config.host = args.host
    if args.port:
        server.config.port = args.port
    
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.stop()
    except Exception as e:
        logger.error(f"Server error: {e}")
        server.stop()
        sys.exit(1)

class EDRAgentServer(EDRServer):
    """EDR Agent Server that extends the base EDRServer with agent-specific functionality."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the EDR Agent Server."""
        super().__init__(config_path)
        self.agents = {}  # Track connected agents
        self.agent_heartbeats = {}  # Track agent heartbeats
        
    def handle_agent_heartbeat(self, agent_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle agent heartbeat and return response."""
        try:
            self.agent_heartbeats[agent_id] = time.time()
            
            # Update agent info if it exists, otherwise add it
            if agent_id not in self.agents:
                self.agents[agent_id] = {
                    'first_seen': time.time(),
                    'last_seen': time.time(),
                    'status': 'online',
                    'version': data.get('version', 'unknown'),
                    'system_info': data.get('system_info', {})
                }
            else:
                self.agents[agent_id].update({
                    'last_seen': time.time(),
                    'status': 'online',
                    'version': data.get('version', self.agents[agent_id].get('version', 'unknown')),
                    'system_info': {**self.agents[agent_id].get('system_info', {}), 
                                  **data.get('system_info', {})}
                })
            
            return {
                'status': 'success',
                'timestamp': datetime.utcnow().isoformat(),
                'config': {
                    'collect_interval': 60,  # seconds
                    'enabled_modules': ['process', 'network', 'file']
                }
            }
            
        except Exception as e:
            logger.error(f"Error handling agent heartbeat: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def get_agent_status(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a specific agent."""
        if agent_id in self.agents:
            agent = self.agents[agent_id].copy()
            agent['last_seen'] = self.agent_heartbeats.get(agent_id, 0)
            agent['status'] = 'online' if (time.time() - agent['last_seen']) < 300 else 'offline'
            return agent
        return None
    
    def get_all_agents(self) -> List[Dict[str, Any]]:
        """
        Get status of all agents.
        
        Returns:
            List of agent status dictionaries
        """
        return [
            self.get_agent_status(agent_id) 
            for agent_id in self.agents
        ]


if __name__ == '__main__':
    main()
