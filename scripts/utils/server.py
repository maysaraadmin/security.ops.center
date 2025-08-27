"""
EDR (Endpoint Detection and Response) Server

This module implements the EDR server that manages EDR agents, processes events,
and provides a web interface for monitoring and response.
"""
import os
import json
import time
import uuid
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from flask import Flask, request, jsonify, Response, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import psutil

# Add the project root to the Python path
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

# Import SIEM integration
from src.siem.services.siem_service import get_siem_service, SIEMEvent

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

class EDRServer:
    """EDR Server for managing agents and processing security events"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the EDR server with configuration"""
        self.config = config
        self.agents: Dict[str, Dict[str, Any]] = {}  # agent_id -> agent_info
        self.events: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.commands: Dict[str, Dict[str, Any]] = {}  # command_id -> command
        self.running = False
        self.app = None
        self.socketio = None
        self.port = config.get('port', 5000)
        self.host = config.get('host', '0.0.0.0')
        self.secret_key = config.get('secret_key', os.urandom(24).hex())
        self.agent_timeout = config.get('agent_timeout', 300)  # seconds
        
        # Initialize SIEM service
        siem_config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'config',
            'siem_integration.yaml'
        )
        self.siem_service = get_siem_service(siem_config_path)
        
        # Initialize Flask app
        self._initialize_flask()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
    
    def _initialize_flask(self) -> None:
        """Initialize Flask application and routes"""
        self.app = Flask(__name__, template_folder='../web/templates')
        self.app.secret_key = self.secret_key
        
        # Enable CORS
        CORS(self.app)
        
        # Initialize Socket.IO
        self.socketio = SocketIO(
            self.app,
            cors_allowed_origins="*",
            async_mode='threading',
            logger=True,
            engineio_logger=True
        )
        
        # Register API routes
        self._register_routes()
        
        # Register Socket.IO events
        self._register_socketio_events()
    
    def _register_routes(self) -> None:
        """Register API routes"""
        
        # Health check
        @self.app.route('/api/health', methods=['GET'])
        def health():
            return jsonify({
                'status': 'ok',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0.0',
                'agents_connected': len([a for a in self.agents.values() if a.get('online')])
            })
        
        # Agent endpoints
        @self.app.route('/api/v1/agents', methods=['GET'])
        def list_agents():
            return jsonify({
                'agents': [
                    {k: v for k, v in agent.items() if k != 'last_heartbeat'}
                    for agent in self.agents.values()
                ]
            })
        
        @self.app.route('/api/v1/agents/<agent_id>', methods=['GET'])
        def get_agent(agent_id: str):
            agent = self.agents.get(agent_id)
            if not agent:
                return jsonify({'error': 'Agent not found'}), 404
            return jsonify(agent)
        
        @self.app.route('/api/v1/agents/<agent_id>/command', methods=['POST'])
        def send_command(agent_id: str):
            if agent_id not in self.agents:
                return jsonify({'error': 'Agent not found'}), 404
            
            data = request.get_json()
            command_type = data.get('type')
            command_args = data.get('args', {})
            
            if not command_type:
                return jsonify({'error': 'Missing command type'}), 400
            
            command_id = str(uuid.uuid4())
            command = {
                'id': command_id,
                'type': command_type,
                'args': command_args,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat(),
                'agent_id': agent_id
            }
            
            self.commands[command_id] = command
            self._broadcast('command_created', command)
            
            # Forward command to SIEM
            self._forward_to_siem('command_issued', command)
            
            return jsonify({
                'command_id': command_id,
                'status': 'queued'
            })
        
        @self.app.route('/api/v1/commands/<command_id>', methods=['GET'])
        def get_command_status(command_id: str):
            command = self.commands.get(command_id)
            if not command:
                return jsonify({'error': 'Command not found'}), 404
            return jsonify(command)
        
        # Event endpoints
        @self.app.route('/api/v1/events', methods=['GET'])
        def list_events():
            limit = min(int(request.args.get('limit', 100)), 1000)
            return jsonify({
                'events': self.events[-limit:]
            })
        
        @self.app.route('/api/v1/events', methods=['POST'])
        def create_event():
            event = request.get_json()
            event['id'] = str(uuid.uuid4())
            event['timestamp'] = datetime.utcnow().isoformat()
            
            self.events.append(event)
            self._broadcast('event_received', event)
            
            # Forward event to SIEM
            self._forward_to_siem('security_event', event)
            
            # Check for alerts
            self._check_for_alerts(event)
            
            return jsonify({'status': 'received', 'id': event['id']})
        
        # Alert endpoints
        @self.app.route('/api/v1/alerts', methods=['GET'])
        def list_alerts():
            limit = min(int(request.args.get('limit', 100)), 1000)
            return jsonify({
                'alerts': self.alerts[-limit:]
            })
        
        @self.app.route('/api/v1/alerts/<alert_id>', methods=['GET'])
        def get_alert(alert_id: str):
            for alert in reversed(self.alerts):
                if alert['id'] == alert_id:
                    return jsonify(alert)
            return jsonify({'error': 'Alert not found'}), 404
        
        # Web interface
        @self.app.route('/')
        def dashboard():
            return render_template('edr_dashboard.html', 
                                 agents_count=len(self.agents),
                                 alerts_count=len(self.alerts))
    
    def _register_socketio_events(self) -> None:
        """Register Socket.IO event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            logger.info("Client connected")
            
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info("Client disconnected")
    
    def _broadcast(self, event: str, data: Any) -> None:
        """Broadcast an event to all connected clients"""
        if self.socketio:
            self.socketio.emit(event, data)
    
    def _check_for_alerts(self, event: Dict[str, Any]) -> None:
        """Check if an event should trigger an alert"""
        # In a real implementation, this would use the correlation engine
        # to detect security incidents
        
        # Example: Alert on failed logins
        if event.get('event_type') == 'authentication_failure':
            alert = {
                'id': str(uuid.uuid4()),
                'title': 'Failed Login Attempt',
                'description': f"Failed login for user {event.get('username', 'unknown')} from {event.get('source_ip', 'unknown')}",
                'severity': 'medium',
                'status': 'open',
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'edr',
                'details': event
            }
            
            self.alerts.append(alert)
            self._broadcast('alert_created', alert)
            
            # Forward alert to SIEM
            self._forward_to_siem('alert', alert)
    
    def _forward_to_siem(self, event_type: str, data: Dict[str, Any]) -> None:
        """Forward an event to the configured SIEM systems"""
        if not hasattr(self, 'siem_service') or not self.siem_service:
            return
        
        try:
            # Create a SIEM event
            siem_event = SIEMEvent(
                event_type=event_type,
                timestamp=datetime.utcnow(),
                source="edr_server",
                severity=data.get('severity', 'info'),
                details=data
            )
            
            # Send the event to SIEM
            self.siem_service.send_event(siem_event)
            logger.debug(f"Forwarded {event_type} event to SIEM")
            
        except Exception as e:
            logger.error(f"Failed to forward event to SIEM: {str(e)}")
    
    def _cleanup_loop(self) -> None:
        """Background thread for cleaning up old data"""
        while self.running:
            try:
                self._cleanup_old_data()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {str(e)}")
            
            # Run cleanup every 5 minutes
            time.sleep(300)
    
    def _cleanup_old_data(self) -> None:
        """Clean up old events, alerts, and commands"""
        now = datetime.utcnow()
        
        # Mark offline agents
        for agent_id, agent in list(self.agents.items()):
            last_seen = datetime.fromisoformat(agent['last_heartbeat'])
            if (now - last_seen).total_seconds() > self.agent_timeout:
                if agent.get('online', False):
                    agent['online'] = False
                    logger.info(f"Agent {agent_id} marked as offline")
                    self._broadcast('agent_offline', {'agent_id': agent_id})
        
        # Keep only recent events (last 24 hours by default)
        max_events_age = self.config.get('max_events_age_hours', 24)
        cutoff = now - timedelta(hours=max_events_age)
        self.events = [
            e for e in self.events 
            if datetime.fromisoformat(e['timestamp']) > cutoff
        ]
        
        # Keep only recent alerts (last 7 days by default)
        max_alerts_age = self.config.get('max_alerts_age_days', 7)
        cutoff = now - timedelta(days=max_alerts_age)
        self.alerts = [
            a for a in self.alerts 
            if datetime.fromisoformat(a['timestamp']) > cutoff
        ]
        
        # Clean up old completed commands (older than 1 day)
        cutoff = now - timedelta(days=1)
        for cmd_id, cmd in list(self.commands.items()):
            if cmd['status'] == 'completed' and datetime.fromisoformat(cmd.get('completed_at', now.isoformat())) < cutoff:
                del self.commands[cmd_id]
    
    def start(self) -> None:
        """Start the EDR server"""
        if self.running:
            logger.warning("EDR server is already running")
            return
        
        self.running = True
        
        # Start cleanup thread
        self.cleanup_thread.start()
        
        # Start SIEM service
        self.siem_service.start()
        logger.info("SIEM service started")
        
        logger.info(f"Starting EDR server on {self.host}:{self.port}")
        
        try:
            # Start Flask development server
            self.socketio.run(
                self.app,
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False
            )
        except Exception as e:
            logger.error(f"Failed to start EDR server: {str(e)}")
            self.stop()
            raise
    
    def stop(self) -> None:
        """Stop the EDR server"""
        if not self.running:
            return
        
        logger.info("Stopping EDR server...")
        self.running = False
        
        # Stop SIEM service
        self.siem_service.stop()
        logger.info("SIEM service stopped")
        
        # Wait for cleanup thread to finish
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        
        logger.info("EDR server stopped")

# API Endpoints for Agent Communication

def create_edr_server(config: Dict[str, Any]) -> Flask:
    """Create a Flask application with EDR server endpoints"""
    server = EDRServer(config)
    app = server.app
    
    # Register agent API endpoints
    @app.route('/api/v1/heartbeat', methods=['POST'])
    def handle_heartbeat():
        data = request.get_json()
        agent_id = data.get('agent_id')
        
        if not agent_id:
            return jsonify({'error': 'Missing agent_id'}), 400
        
        # Update agent status
        now = datetime.utcnow().isoformat()
        
        if agent_id not in server.agents:
            # New agent
            server.agents[agent_id] = {
                'id': agent_id,
                'hostname': data.get('hostname', 'unknown'),
                'os_info': data.get('os_info', {}),
                'first_seen': now,
                'online': True,
                'last_heartbeat': now,
                'metrics': data.get('metrics', {})
            }
            logger.info(f"New agent connected: {agent_id} ({data.get('hostname', 'unknown')})")
            server._broadcast('agent_connected', server.agents[agent_id])
            
            # Forward agent connection to SIEM
            server._forward_to_siem('agent_connected', {
                'agent_id': agent_id,
                'hostname': data.get('hostname', 'unknown'),
                'os_info': data.get('os_info', {})
            })
        else:
            # Existing agent
            agent = server.agents[agent_id]
            was_offline = not agent.get('online', False)
            agent['last_heartbeat'] = now
            agent['online'] = True
            agent['metrics'] = data.get('metrics', {})
            
            # Check if this is a reconnection
            if was_offline:
                logger.info(f"Agent reconnected: {agent_id} ({agent.get('hostname', 'unknown')})")
                server._broadcast('agent_reconnected', agent)
                
                # Forward agent reconnection to SIEM
                server._forward_to_siem('agent_reconnected', {
                    'agent_id': agent_id,
                    'hostname': agent.get('hostname', 'unknown'),
                    'downtime_seconds': (datetime.fromisoformat(now) - 
                                       datetime.fromisoformat(agent.get('last_heartbeat', now))).total_seconds()
                })
        
        # Check for pending commands
        pending_commands = [
            cmd for cmd in server.commands.values() 
            if cmd.get('agent_id') == agent_id and cmd.get('status') == 'pending'
        ]
        
        # Update command status to delivered
        for cmd in pending_commands:
            cmd['status'] = 'delivered'
            cmd['delivered_at'] = now
        
        return jsonify({
            'status': 'ok',
            'commands': [{
                'id': cmd['id'],
                'type': cmd['type'],
                'args': cmd.get('args', {})
            } for cmd in pending_commands]
        })
    
    @app.route('/api/v1/command_results', methods=['POST'])
    def handle_command_results():
        data = request.get_json()
        agent_id = data.get('agent_id')
        results = data.get('results', [])
        
        if not agent_id:
            return jsonify({'error': 'Missing agent_id'}), 400
        
        if agent_id not in server.agents:
            return jsonify({'error': 'Agent not found'}), 404
        
        now = datetime.utcnow().isoformat()
        
        for result in results:
            command_id = result.get('command_id')
            if not command_id or command_id not in server.commands:
                continue
            
            command = server.commands[command_id]
            command['status'] = result.get('status', 'completed')
            command['completed_at'] = now
            command['result'] = result.get('result', {})
            
            if 'error' in result:
                command['error'] = result['error']
            
            server._broadcast('command_completed', command)
            
            # Forward command result to SIEM
            server._forward_to_siem('command_result', command)
        
        return jsonify({'status': 'ok'})
    
    @app.route('/api/v1/commands/<agent_id>', methods=['GET'])
    def get_agent_commands(agent_id: str):
        if agent_id not in server.agents:
            return jsonify({'error': 'Agent not found'}), 404
        
        pending_commands = [
            cmd for cmd in server.commands.values() 
            if cmd.get('agent_id') == agent_id and cmd.get('status') == 'pending'
        ]
        
        # Mark commands as delivered
        now = datetime.utcnow().isoformat()
        for cmd in pending_commands:
            cmd['status'] = 'delivered'
            cmd['delivered_at'] = now
        
        return jsonify({
            'commands': [{
                'id': cmd['id'],
                'type': cmd['type'],
                'args': cmd.get('args', {})
            } for cmd in pending_commands]
        })
    
    return server

def main():
    """Main entry point for the EDR server"""
    # Default configuration
    config = {
        'host': '0.0.0.0',
        'port': 5000,
        'secret_key': os.getenv('EDR_SECRET_KEY', os.urandom(24).hex()),
        'agent_timeout': 300,  # 5 minutes
        'max_events_age_hours': 24,
        'max_alerts_age_days': 7
    }
    
    # Create and start the server
    server = EDRServer(config)
    
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Shutting down EDR server...")
        server.stop()
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
        server.stop()
        sys.exit(1)

if __name__ == "__main__":
    import sys
    main()
