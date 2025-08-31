"""
Syslog Listener for SIEM

This module implements a syslog listener that can receive logs via UDP and TCP.
"""
import asyncio
import socket
import logging
from typing import Dict, List, Optional, Callable, Any, Union
from dataclasses import dataclass
from datetime import datetime
import re

logger = logging.getLogger('siem.listener.syslog')

@dataclass
class SyslogMessage:
    """Represents a parsed syslog message."""
    priority: int
    facility: int
    severity: int
    timestamp: datetime
    hostname: str
    app_name: str
    proc_id: str
    msg_id: str
    structured_data: Dict[str, Dict[str, str]]
    message: str
    raw: str

class SyslogListener:
    """A syslog listener that can receive logs via UDP and TCP."""
    
    def __init__(self, 
                 host: str = '0.0.0.0', 
                 port: int = 514,
                 protocols: List[str] = ['udp', 'tcp'],
                 message_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        """Initialize the syslog listener.
        
        Args:
            host: Host to bind to (default: 0.0.0.0)
            port: Port to listen on (default: 514)
            protocols: List of protocols to support ('udp', 'tcp')
            message_callback: Callback function for processed messages
        """
        self.host = host
        self.port = port
        self.protocols = protocols
        self.message_callback = message_callback
        self.running = False
        self.servers = []
        
        # Statistics
        self.stats = {
            'start_time': datetime.utcnow(),
            'messages_received': 0,
            'messages_processed': 0,
            'errors': 0,
            'last_error': None,
            'sources': {}
        }
    
    async def start(self):
        """Start the syslog listener."""
        self.running = True
        
        if 'udp' in self.protocols:
            server = await asyncio.start_server(
                self._handle_tcp_connection,
                host=self.host,
                port=self.port,
                reuse_address=True
            )
            self.servers.append(server)
            logger.info(f"Started TCP syslog listener on {self.host}:{self.port}")
            
        if 'udp' in self.protocols:
            loop = asyncio.get_running_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: SyslogUDPProtocol(self._handle_syslog_message),
                local_addr=(self.host, self.port)
            )
            self.servers.append((transport, protocol))
            logger.info(f"Started UDP syslog listener on {self.host}:{self.port}")
    
    async def stop(self):
        """Stop the syslog listener."""
        self.running = False
        for server in self.servers:
            if hasattr(server, 'close'):  # TCP server
                server.close()
                await server.wait_closed()
            else:  # UDP transport
                transport, _ = server
                transport.close()
        self.servers = []
        logger.info("Stopped syslog listener")
    
    async def _handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming TCP connections."""
        client_addr = writer.get_extra_info('peername')
        logger.debug(f"New TCP connection from {client_addr}")
        
        try:
            while self.running:
                try:
                    data = await asyncio.wait_for(reader.readline(), timeout=5.0)
                    if not data:
                        break
                    await self._handle_syslog_message(data.decode().strip(), client_addr[0])
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    break
        except Exception as e:
            self.stats['errors'] += 1
            self.stats['last_error'] = str(e)
            logger.error(f"Error handling TCP connection from {client_addr}: {e}", exc_info=True)
        finally:
            writer.close()
            await writer.wait_closed()
            logger.debug(f"Closed TCP connection from {client_addr}")
    
    async def _handle_syslog_message(self, message: str, source_ip: str):
        """Process a received syslog message."""
        self.stats['messages_received'] += 1
        
        # Update source statistics
        if source_ip not in self.stats['sources']:
            self.stats['sources'][source_ip] = 0
        self.stats['sources'][source_ip] += 1
        
        try:
            # Parse the syslog message
            parsed = self._parse_syslog(message)
            if not parsed:
                logger.warning(f"Failed to parse syslog message from {source_ip}: {message}")
                return
            
            # Add source IP and timestamp
            parsed['source'] = {
                'ip': source_ip,
                'received_at': datetime.utcnow().isoformat() + 'Z'
            }
            
            # Call the message callback if provided
            if self.message_callback:
                self.message_callback(parsed)
                
            self.stats['messages_processed'] += 1
            
        except Exception as e:
            self.stats['errors'] += 1
            self.stats['last_error'] = str(e)
            logger.error(f"Error processing syslog message from {source_ip}: {e}", exc_info=True)
    
    def _parse_syslog(self, message: str) -> Optional[Dict[str, Any]]:
        """Parse a syslog message into a structured format."""
        if not message:
            return None
            
        # Try to parse RFC 5424 format first
        rfc5424_pattern = r"^<(?P<pri>\d{1,3})>(?P<version>\d) (?P<timestamp>[^ ]+) (?P<hostname>[^ ]+) " \
                         r"(?P<app_name>[^ ]+) (?P<proc_id>[^ ]+) (?P<msg_id>[^ ]+) (?P<structured_data>\[.*?\])\s*(?P<message>.*)$"
        
        match = re.match(rfc5424_pattern, message)
        if match:
            return self._parse_rfc5424(match.groupdict())
            
        # Fall back to RFC 3164 format
        rfc3164_pattern = r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) " \
                         r"(?P<hostname>[^ ]+) (?P<message>.*)$"
        
        match = re.match(rfc3164_pattern, message)
        if match:
            return self._parse_rfc3164(match.groupdict())
            
        # If we get here, try to parse as a simple message
        return {
            'raw_message': message,
            'parsed': False,
            'message': message
        }
    
    def _parse_rfc5424(self, match_dict: Dict[str, str]) -> Dict[str, Any]:
        """Parse a message in RFC 5424 format."""
        pri = int(match_dict['pri'])
        facility = pri // 8
        severity = pri % 8
        
        # Parse structured data
        structured_data = {}
        if match_dict['structured_data'] and match_dict['structured_data'] != '-':
            # Simple structured data parser (doesn't handle all cases)
            sd_parts = re.findall(r'\[(.*?)\]', match_dict['structured_data'])
            for part in sd_parts:
                if '=' in part:
                    sd_id, *sd_params = part.split(' ')
                    params = {}
                    for param in sd_params:
                        if '=' in param:
                            k, v = param.split('=', 1)
                            params[k] = v.strip('"')
                    structured_data[sd_id] = params
        
        return {
            'protocol': 'rfc5424',
            'priority': pri,
            'facility': facility,
            'severity': severity,
            'version': int(match_dict['version']),
            'timestamp': self._parse_timestamp(match_dict['timestamp']),
            'hostname': match_dict['hostname'],
            'app_name': match_dict['app_name'],
            'proc_id': match_dict['proc_id'],
            'msg_id': match_dict['msg_id'],
            'structured_data': structured_data,
            'message': match_dict['message'],
            'raw_message': match_dict[0] if match_dict else None,
            'parsed': True
        }
    
    def _parse_rfc3164(self, match_dict: Dict[str, str]) -> Dict[str, Any]:
        """Parse a message in RFC 3164 format."""
        pri = int(match_dict['pri'])
        facility = pri // 8
        severity = pri % 8
        
        # Try to extract app name and process ID if present
        app_name = None
        proc_id = None
        msg = match_dict['message']
        
        # Look for app name and process ID in the message
        app_match = re.match(r'^([a-zA-Z0-9_/.-]+)(?:\[(\d+)\])?:\s*(.*)$', msg)
        if app_match:
            app_name = app_match.group(1)
            proc_id = app_match.group(2)
            msg = app_match.group(3)
        
        return {
            'protocol': 'rfc3164',
            'priority': pri,
            'facility': facility,
            'severity': severity,
            'timestamp': self._parse_timestamp(match_dict['timestamp']),
            'hostname': match_dict['hostname'],
            'app_name': app_name,
            'proc_id': proc_id,
            'message': msg,
            'raw_message': match_dict[0] if match_dict else None,
            'parsed': True
        }
    
    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse a syslog timestamp into ISO format."""
        if not timestamp_str or timestamp_str == '-':
            return datetime.utcnow().isoformat() + 'Z'
            
        try:
            # Try ISO 8601 format
            if 'T' in timestamp_str:
                if timestamp_str.endswith('Z'):
                    return timestamp_str
                if '+' in timestamp_str or '-' in timestamp_str[-6:]:
                    return timestamp_str
                return timestamp_str + 'Z'
                
            # Try common syslog formats
            for fmt in [
                '%b %d %H:%M:%S',  # Oct 31 12:34:56
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S'
            ]:
                try:
                    dt = datetime.strptime(timestamp_str, fmt)
                    # If year isn't in the format, use current year
                    if '%Y' not in fmt:
                        dt = dt.replace(year=datetime.utcnow().year)
                    return dt.isoformat() + 'Z'
                except ValueError:
                    continue
                    
            # If we get here, just return the current time
            return datetime.utcnow().isoformat() + 'Z'
            
        except Exception:
            return datetime.utcnow().isoformat() + 'Z'
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the syslog listener."""
        return {
            **self.stats,
            'uptime': str(datetime.utcnow() - self.stats['start_time']),
            'active_sources': len(self.stats['sources']),
            'current_time': datetime.utcnow().isoformat() + 'Z'
        }

class SyslogUDPProtocol:
    """UDP protocol handler for syslog messages."""
    
    def __init__(self, message_handler: Callable[[str, str], None]):
        self.message_handler = message_handler
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data: bytes, addr: tuple):
        try:
            message = data.decode('utf-8', errors='replace').strip()
            if message:
                asyncio.create_task(self.message_handler(message, addr[0]))
        except Exception as e:
            logger.error(f"Error processing UDP datagram: {e}", exc_info=True)
    
    def error_received(self, exc: Exception):
        logger.error(f"UDP error: {exc}", exc_info=True)
    
    def connection_lost(self, exc: Optional[Exception]):
        if exc:
            logger.error(f"UDP connection lost: {exc}", exc_info=True)
        else:
            logger.debug("UDP connection closed")

# Example usage
async def example_callback(message: Dict[str, Any]):
    """Example callback function for processing messages."""
    print(f"Received message: {message}")

async def main():
    # Create and start the syslog listener
    listener = SyslogListener(
        host='0.0.0.0',
        port=514,
        protocols=['udp', 'tcp'],
        message_callback=example_callback
    )
    
    try:
        await listener.start()
        
        # Keep the listener running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        print("Shutting down...")
        await listener.stop()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
