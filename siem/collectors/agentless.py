"""
Agentless Collection Module

Provides agentless collection capabilities using protocols like Syslog.
"""
import asyncio
import logging
import socket
from typing import Optional, Callable, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Union
import pysnmp.hlapi as snmp
from pysnmp.smi import builder, view, compiler
import pysnmp.proto.api as snmp_api

# Import WEF collector
from .wef_collector import WEFCollector

logger = logging.getLogger('siem.collector.agentless')

@dataclass
class SyslogMessage:
    """Represents a parsed Syslog message."""
    priority: int
    facility: int
    severity: int
    timestamp: datetime
    hostname: str
    appname: str
    procid: str
    msgid: str
    msg: str
    raw: bytes

@dataclass
class SNMPTrapMessage:
    """Represents a parsed SNMP trap message."""
    version: str
    community: str
    source_ip: str
    source_port: int
    timestamp: datetime
    trap_oid: str
    var_binds: List[tuple]
    raw_pdu: Any = None

class AgentlessCollector:
    """Collects logs and events using agentless methods like Syslog and SNMP."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the agentless collector."""
        self.config = config
        self.running = False
        self.servers: List[asyncio.Server] = []
        self.snmp_engine = None
        self.snmp_transport = None
        self.snmp_transport_dispatcher = None
        self.wef_collector = None
        
        # Track connected devices
        # Format: {
        #   "ip:port": {
        #       "ip": str,
        #       "port": int,
        #       "type": str,  # 'syslog', 'snmp', 'wef'
        #       "first_seen": datetime,
        #       "last_seen": datetime,
        #       "message_count": int,
        #       "last_message": str,
        #       "status": str  # 'connected', 'disconnected', 'blocked'
        #   }
        # }
        self.connected_devices = {}
        self.devices_lock = asyncio.Lock()
        self.blocked_ips = set()  # Track blocked IPs to prevent connection
        
    async def _cleanup_stale_devices(self):
        """Periodically clean up devices that haven't been seen in a while."""
        while self.running:
            try:
                now = datetime.now()
                stale_timeout = 300  # 5 minutes before marking as disconnected
                remove_timeout = 3600  # 1 hour before removing completely
                
                async with self.devices_lock:
                    for device_id, device in list(self.connected_devices.items()):
                        time_since_seen = (now - device['last_seen']).total_seconds()
                        
                        # Mark as disconnected if not seen in a while
                        if time_since_seen > stale_timeout and device['status'] == 'connected':
                            self.connected_devices[device_id]['status'] = 'disconnected'
                            logger.info(f"Marked device as disconnected: {device_id}")
                        
                        # Remove if not seen for a long time and not blocked
                        elif (time_since_seen > remove_timeout and 
                              device['status'] != 'blocked' and 
                              device['ip'] not in self.blocked_ips):
                            del self.connected_devices[device_id]
                            logger.info(f"Removed stale device: {device_id}")
                
                # Check every 30 seconds
                await asyncio.sleep(30)
                
            except Exception as e:
                logger.error(f"Error in device cleanup task: {e}", exc_info=True)
                await asyncio.sleep(30)  # Wait before retrying
    
    async def get_connected_devices(self) -> Dict[str, Dict]:
        """Get a copy of the current connected devices."""
        async with self.devices_lock:
            return self.connected_devices.copy()
    
    async def _register_device(self, ip: str, port: int, device_type: str, initial_message: str = None):
        """Register a new device or update an existing one.
        
        Args:
            ip: The IP address of the device
            port: The port number the device is connecting from
            device_type: Type of connection ('syslog', 'snmp', 'wef')
            initial_message: Optional initial message from the device
        """
        if ip in self.blocked_ips:
            logger.warning(f"Connection attempt from blocked IP: {ip}")
            return False
            
        device_id = f"{ip}:{port}"
        now = datetime.now()
        
        async with self.devices_lock:
            if device_id not in self.connected_devices:
                # New device
                self.connected_devices[device_id] = {
                    'ip': ip,
                    'port': port,
                    'type': device_type,
                    'first_seen': now,
                    'last_seen': now,
                    'message_count': 1 if initial_message else 0,
                    'last_message': initial_message,
                    'status': 'connected'
                }
                logger.info(f"New {device_type.upper()} device connected: {ip}:{port}")
                return True
            else:
                # Update existing device
                device = self.connected_devices[device_id]
                device['last_seen'] = now
                device['status'] = 'connected'
                if initial_message:
                    device['message_count'] += 1
                    device['last_message'] = initial_message
                return True
    
    async def update_device_message(self, ip: str, port: int, message: str = None):
        """Update the last seen timestamp and message for a device.
        
        Args:
            ip: The IP address of the device
            port: The port number the device is connecting from
            message: Optional message to store as the last message
        """
        if ip in self.blocked_ips:
            return False
            
        device_id = f"{ip}:{port}"
        now = datetime.now()
        
        async with self.devices_lock:
            if device_id in self.connected_devices:
                device = self.connected_devices[device_id]
                device['last_seen'] = now
                device['status'] = 'connected'
                device['message_count'] += 1
                if message:
                    device['last_message'] = message
                return True
            return False
    
    async def block_device(self, ip: str, block: bool = True):
        """Block or unblock a device by IP.
        
        Args:
            ip: The IP address to block/unblock
            block: If True, block the IP. If False, unblock it.
        """
        if block:
            self.blocked_ips.add(ip)
            # Mark all devices with this IP as blocked
            async with self.devices_lock:
                for device_id, device in list(self.connected_devices.items()):
                    if device['ip'] == ip:
                        device['status'] = 'blocked'
            logger.warning(f"Blocked IP: {ip}")
        else:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                # Mark all devices with this IP as disconnected
                async with self.devices_lock:
                    for device_id, device in list(self.connected_devices.items()):
                        if device['ip'] == ip:
                            device['status'] = 'disconnected'
                logger.info(f"Unblocked IP: {ip}")
    
    async def start(self):
        """Start all configured agentless collection services."""
        if self.running:
            logger.warning("Agentless collector already running")
            return
            
        self.running = True
        
        try:
            # Start Syslog server if enabled
            if self.config.get('syslog', {}).get('enabled', False):
                await self._start_syslog_server()
                
            # Start SNMP trap receiver if enabled
            if self.config.get('snmp_trap', {}).get('enabled', False):
                await self._start_snmp_trap_receiver()
                
            # Start WEF collector if enabled
            if self.config.get('windows_event_forwarding', {}).get('enabled', False):
                await self._start_wef_collector()
            
            # Start device cleanup task
            asyncio.create_task(self._cleanup_stale_devices())
                
            logger.info("Agentless collector started")
            
        except Exception as e:
            logger.error(f"Failed to start agentless collector: {e}", exc_info=True)
            await self.stop()
            raise
    
    async def stop(self):
        """Stop all agentless collection services."""
        if not self.running:
            return
            
        self.running = False
        
        try:
            # Stop WEF collector if running
            if self.wef_collector:
                await self.wef_collector.stop()
                self.wef_collector = None
                
            # Stop all running servers
            for server in self.servers:
                if hasattr(server, 'close'):
                    server.close()
                    if hasattr(server, 'wait_closed'):
                        await server.wait_closed()
            
            # Stop SNMP transport if running
            if self.snmp_transport_dispatcher is not None:
                self.snmp_transport_dispatcher.jobFinished(1)
                self.snmp_transport_dispatcher = None
                
            self.servers.clear()
            logger.info("Agentless collector stopped")
            
        except Exception as e:
            logger.error(f"Error stopping agentless collector: {e}", exc_info=True)
            raise
    
    async def _start_syslog_server(self):
        """Start the Syslog server."""
        syslog_config = self.config.get('syslog', {})
        host = syslog_config.get('host', '0.0.0.0')
        port = syslog_config.get('port', 514)
        
        try:
            # Create a new event loop for this server
            loop = asyncio.get_event_loop()
            
            # Start the Syslog server
            server = await asyncio.start_server(
                self._handle_syslog_connection,
                host=host,
                port=port,
                reuse_address=True
            )
            
            self.servers.append(server)
            logger.info(f"Syslog server started on {host}:{port}")
            
            # Keep the server running
            async with server:
                await server.serve_forever()
                
        except Exception as e:
            logger.error(f"Failed to start Syslog server: {e}", exc_info=True)
            raise
    
    async def _handle_syslog_connection(self, reader, writer):
        """Handle an incoming Syslog connection."""
        addr = writer.get_extra_info('peername')
        ip, port = addr[0], addr[1]
        logger.debug(f"New Syslog connection from {ip}:{port}")
        
        # Register the device
        await self._register_device(ip, port, 'syslog')
        
        try:
            while self.running:
                try:
                    # Read data with a timeout
                    data = await asyncio.wait_for(reader.read(4096), timeout=30.0)
                    if not data:
                        break
                        
                    # Process the Syslog message
                    message = data.decode('utf-8', errors='replace').strip()
                    await self.update_device_message(ip, port, message)
                    await self._process_syslog_data(data, ip)
                    
                except asyncio.TimeoutError:
                    logger.debug(f"Connection timeout from {ip}:{port}")
                    break
                except ConnectionResetError:
                    logger.debug(f"Connection reset by peer: {ip}:{port}")
                    break
                except Exception as e:
                    logger.error(f"Error handling Syslog data from {ip}:{port}: {e}", exc_info=True)
                    break
                    
        except Exception as e:
            logger.error(f"Unexpected error in Syslog handler for {ip}:{port}: {e}", exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
                logger.debug(f"Closed connection from {ip}:{port}")
            except Exception as e:
                logger.error(f"Error closing connection from {ip}:{port}: {e}")
    
    async def _process_syslog_data(self, data: bytes, source_ip: str):
        """Process incoming Syslog data."""
        try:
            # Parse the Syslog message
            message = self._parse_syslog_message(data, source_ip)
            if not message:
                return
                
            # Create an event from the message
            event = {
                'timestamp': message.timestamp,
                'source': f"syslog://{source_ip}",
                'event_type': 'syslog',
                'severity': self._syslog_severity_to_level(message.severity),
                'description': f"Syslog message from {message.hostname or source_ip}",
                'raw_data': {
                    'priority': message.priority,
                    'facility': message.facility,
                    'severity': message.severity,
                    'hostname': message.hostname,
                    'appname': message.appname,
                    'procid': message.procid,
                    'msgid': message.msgid,
                    'message': message.msg,
                    'raw': message.raw.decode('utf-8', errors='replace')
                }
            }
            
            # Add the event to the queue
            if hasattr(self, 'event_queue'):
                await self.event_queue.put(event)
                
        except Exception as e:
            logger.error(f"Error processing Syslog data from {source_ip}: {e}", exc_info=True)
    
    async def _handle_snmp_trap(self, transport_dispatcher, transport_domain, transport_address, whole_msg):
        """Handle incoming SNMP traps."""
        ip = transport_address[0]
        port = transport_address[1] if len(transport_address) > 1 else 0
        
        # Register/update the device
        await self._register_device(ip, port, 'snmp')
        
        try:
            while whole_msg:
                msg_ver = int(api.decodeMessageVersion(whole_msg))
                if msg_ver in api.protoModules:
                    p_mod = api.protoModules[msg_ver]
                else:
                    logger.error(f"Unsupported SNMP version: {msg_ver}")
                    return None
                    
                req_msg, whole_msg = decoder.decode(whole_msg, asn1Spec=p_mod.Message(),)
                req_pdu = p_mod.apiMessage.getPDU(req_msg)
                
                if req_pdu.isSameTypeWith(p_mod.TrapPDU()):
                    trap_oid = ".".join([str(x) for x in p_mod.apiTrapPDU.getEnterprise(req_pdu).asNumbers()])
                    var_binds = p_mod.apiTrapPDU.getVarBinds(req_pdu)
                    
                    # Format the trap message for logging
                    trap_summary = f"Trap OID: {trap_oid}, Vars: {len(var_binds)}"
                    
                    # Update device with the trap message
                    await self.update_device_message(ip, port, trap_summary)
                    
                    # Create and process the trap message
                    trap_msg = SNMPTrapMessage(
                        version="v1",
                        community=p_mod.apiMessage.getCommunity(req_msg).prettyPrint(),
                        source_ip=ip,
                        source_port=port,
                        timestamp=datetime.now(),
                        trap_oid=trap_oid,
                        var_binds=var_binds,
                        raw_pdu=req_pdu
                    )
                    
                    await self._process_snmp_trap(trap_msg)
                    
            return whole_msg
            
        except Exception as e:
            logger.error(f"Error processing SNMP trap from {ip}:{port}: {e}", exc_info=True)
            return None
    
    async def _process_snmp_trap(self, trap_msg: SNMPTrapMessage):
        """Process an incoming SNMP trap."""
        try:
            # Create an event from the trap
            event = {
                'timestamp': trap_msg.timestamp,
                'source': f"snmp://{trap_msg.source_ip}",
                'event_type': 'snmp_trap',
                'severity': 'medium',  # Default severity for SNMP traps
                'description': f"SNMP trap from {trap_msg.source_ip}: {trap_msg.trap_oid}",
                'raw_data': {
                    'version': trap_msg.version,
                    'community': trap_msg.community,
                    'trap_oid': trap_msg.trap_oid,
                    'var_binds': [
                        {
                            'oid': str(var_bind[0]),
                            'value': str(var_bind[1])
                        }
                        for var_bind in trap_msg.var_binds
                    ]
                }
            }
            
            # Add the event to the queue
            if hasattr(self, 'event_queue'):
                await self.event_queue.put(event)
                
        except Exception as e:
            logger.error(f"Error processing SNMP trap from {trap_msg.source_ip}: {e}", exc_info=True)
    
    async def _start_wef_collector(self):
        """Start the Windows Event Forwarding collector."""
        wef_config = self.config.get('windows_event_forwarding', {})
        
        try:
            self.wef_collector = WEFCollector(wef_config)
            
            # Register callback for WEF events
            async def wef_event_callback(event_data, source_ip):
                # Register/update the device
                port = 0  # WEF doesn't have a port in this context
                await self._register_device(source_ip, port, 'wef')
                
                # Update the device with the latest event
                event_summary = f"Event ID: {event_data.get('EventID', 'N/A')} - {event_data.get('Channel', 'Unknown')}"
                await self.update_device_message(source_ip, port, event_summary)
                
                # Forward to the original processing
                await self._process_wef_event(event_data, source_ip)
            
            # Set the callback
            self.wef_collector.set_event_callback(wef_event_callback)
            
            # Start the collector
            await self.wef_collector.start()
            logger.info("Windows Event Forwarding collector started")
            
        except Exception as e:
            logger.error(f"Failed to start WEF collector: {e}", exc_info=True)
            raise
    
    async def _process_wef_event(self, event_data: Dict[str, Any], source_ip: str):
        """Process an incoming Windows Event Forwarding event."""
        try:
            # Create an event from the WEF data
            event = {
                'timestamp': event_data.get('TimeCreated', datetime.now()),
                'source': f"wef://{source_ip}",
                'event_type': 'windows_event',
                'severity': self._wef_level_to_severity(event_data.get('Level', 4)),  # Default to Information
                'description': f"Windows Event {event_data.get('EventID', 'N/A')} from {source_ip}",
                'raw_data': event_data
            }
            
            # Add the event to the queue
            if hasattr(self, 'event_queue'):
                await self.event_queue.put(event)
                
        except Exception as e:
            logger.error(f"Error processing WEF event from {source_ip}: {e}", exc_info=True)
    
    def _wef_level_to_severity(self, level: int) -> str:
        """Convert Windows Event Log level to SIEM severity."""
        if level <= 2:  # Critical, Error
            return 'high'
        elif level <= 3:  # Warning
            return 'medium'
        else:  # Information, Verbose, etc.
            return 'low'
    
    async def _start_snmp_trap_receiver(self):
        """Start the SNMP trap receiver."""
        snmp_config = self.config.get('snmp_trap', {})
        host = snmp_config.get('host', '0.0.0.0')
        port = snmp_config.get('port', 162)
        community = snmp_config.get('community', 'public')
        
        try:
            # Set up SNMP engine
            self.snmp_engine = snmp.SnmpEngine()
            
            # Transport setup
            transport = snmp.UdpTransportTarget((host, port))
            
            # SNMP version
            if snmp_config.get('version') == '3':
                # SNMPv3 setup
                auth_protocol = snmp.usmHMACSHAAuthProtocol
                priv_protocol = snmp.usmAesCfb128Protocol
                
                snmp.USM_USER_BASED_AUTH_PROTOCOL.update({
                    'usmHMACSHAAuth': auth_protocol
                })
                
                snmp.USM_USER_BASED_PRIV_PROTOCOL.update({
                    'usmAesCfb128Protocol': priv_protocol
                })
                
                # Add user (in a real app, this would come from config)
                snmp.UsmUserData(
                    self.snmp_engine,
                    userName=snmp_config.get('username', 'trapuser'),
                    authKey=snmp_config.get('auth_key', 'authpass'),
                    privKey=snmp_config.get('priv_key', 'privpass'),
                    authProtocol=auth_protocol,
                    privProtocol=priv_protocol
                )
                
                snmp_ver = snmp_api.protoVersion3
            else:
                # SNMPv1/v2c
                snmp_ver = snmp_api.protoVersion1 if snmp_config.get('version') == '1' else snmp_api.protoVersion2c
                
                # Add community string for v1/v2c
                snmp.CommunityData(
                    self.snmp_engine,
                    community,
                    mpModel=0 if snmp_ver == snmp_api.protoVersion1 else 1
                )
            
            # Set up transport dispatcher
            self.snmp_transport_dispatcher = snmp.AsyncoreDispatcher()
            
            # Register a callback for received traps
            def cb_fun(snmp_engine, state_reference, context_engine_id, context_name, 
                      var_binds, cb_ctx):
                try:
                    # Get the PDU
                    pdu = snmp_engine.msgAndPduDsp.getPdu(snmp_engine, state_reference)
                    
                    # Get source address
                    transport_domain, transport_address = snmp_engine.msgAndPduDsp.getTransportInfo(
                        snmp_engine, state_reference)
                    
                    # Create trap message
                    trap_msg = SNMPTrapMessage(
                        version='SNMPv3' if snmp_ver == snmp_api.protoVersion3 else 
                               'SNMPv2c' if snmp_ver == snmp_api.protoVersion2c else 'SNMPv1',
                        community=community,
                        source_ip=transport_address[0],
                        source_port=transport_address[1],
                        timestamp=datetime.now(),
                        trap_oid=str(pdu.get('var-binds')[0][1]) if pdu.get('var-binds') else 'unknown',
                        var_binds=[(str(oid), str(val)) for oid, val in var_binds],
                        raw_pdu=pdu
                    )
                    
                    # Process the trap asynchronously
                    asyncio.create_task(self._handle_snmp_trap(snmp_engine, transport_domain, transport_address, state_reference))
                    
                except Exception as e:
                    logger.error(f"Error processing SNMP trap: {e}", exc_info=True)
            
            # Register the callback
            snmp.CommandResponder(
                self.snmp_engine,
                snmp.CommunityData(community, mpModel=0 if snmp_ver == snmp_api.protoVersion1 else 1),
                cb_fun
            )
            
            # Start the dispatcher
            self.snmp_transport_dispatcher.registerTransport(
                snmp.domain.DOMAIN_NAME,
                transport.openClientMode()
            )
            
            self.snmp_transport_dispatcher.jobStarted(1)
            
            # Start the dispatcher in a separate thread
            def run_dispatcher():
                try:
                    self.snmp_transport_dispatcher.runDispatcher()
                except Exception as e:
                    logger.error(f"SNMP dispatcher error: {e}")
                finally:
                    if self.snmp_transport_dispatcher is not None:
                        self.snmp_transport_dispatcher.closeDispatcher()
            
            import threading
            snmp_thread = threading.Thread(target=run_dispatcher, daemon=True)
            snmp_thread.start()
            
            logger.info(f"SNMP trap receiver started on {host}:{port}")
            
        except Exception as e:
            logger.error(f"Failed to start SNMP trap receiver: {e}", exc_info=True)
            raise
    
    @staticmethod
    async def example_usage():
        """Example of how to use the AgentlessCollector."""
        config = {
            'syslog': {
                'enabled': True,
                'host': '0.0.0.0',
                'port': 514
            },
            'snmp_trap': {
                'enabled': True,
                'host': '0.0.0.0',
                'port': 162,
                'community': 'public'
            },
            'windows_event_forwarding': {
                'enabled': True
            }
        }
        
        collector = AgentlessCollector(config)
        try:
            await collector.start()
            logger.info("Agentless collector started successfully")
            
            # Keep the collector running until interrupted
            while True:
                await asyncio.sleep(1)
                
        except asyncio.CancelledError:
            logger.info("Shutting down agentless collector...")
            await collector.stop()
        except Exception as e:
            logger.error(f"Error in agentless collector: {e}", exc_info=True)
            await collector.stop()


def main():
    """Main entry point for the agentless collector example."""
    logging.basicConfig(level=logging.INFO)
    
    try:
        asyncio.run(AgentlessCollector.example_usage())
    except KeyboardInterrupt:
        logger.info("Shutdown requested, exiting...")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
