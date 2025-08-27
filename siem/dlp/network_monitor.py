"""
Network DLP Monitor

Monitors and controls data in motion across network protocols.
"""
import asyncio
import logging
import ssl
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum, auto
import aiohttp
from aiohttp import web
import json

class ProtocolType(Enum):
    HTTP = auto()
    HTTPS = auto()
    SMTP = auto()
    FTP = auto()
    WEBSOCKET = auto()

@dataclass
class NetworkEvent:
    """Represents a network event that may contain sensitive data."""
    event_id: str
    source_ip: str
    dest_ip: str
    dest_port: int
    protocol: ProtocolType
    method: str = ""
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    content_type: str = ""
    is_encrypted: bool = False

class NetworkMonitor:
    """Monitors network traffic for sensitive data in motion."""
    
    def __init__(self, policy_enforcer=None, listen_address='0.0.0.0', 
                 http_port=8080, https_port=8443):
        self.logger = logging.getLogger(__name__)
        self.policy_enforcer = policy_enforcer
        self.listen_address = listen_address
        self.http_port = http_port
        self.https_port = https_port
        self.ssl_context = self._create_ssl_context()
        self.app = web.Application()
        self.routes = web.RouteTableDef()
        self.setup_routes()
    
    def _create_ssl_context(self):
        """Create a basic SSL context for HTTPS."""
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    
    def setup_routes(self):
        """Setup HTTP/HTTPS routes for monitoring."""
        @self.routes.route('/{path:.*}', ['GET', 'POST', 'PUT', 'DELETE'])
        async def handle_all(request):
            return await self._handle_http_request(request)
        
        self.app.add_routes(self.routes)
    
    async def _handle_http_request(self, request):
        """Process HTTP requests and check for sensitive data."""
        try:
            # Read request data
            content = await request.read() if request.can_read_body else b''
            
            # Create network event
            event = NetworkEvent(
                event_id=str(hash(request)),
                source_ip=request.remote,
                dest_ip=request.host,
                dest_port=request.url.port or (443 if request.url.scheme == 'https' else 80),
                protocol=ProtocolType.HTTPS if request.url.scheme == 'https' else ProtocolType.HTTP,
                method=request.method,
                url=str(request.url),
                headers=dict(request.headers),
                content=content,
                content_type=request.content_type,
                is_encrypted=request.url.scheme == 'https'
            )
            
            # Check for policy violations
            if await self._check_policy(event):
                return web.Response(
                    status=403,
                    text="Access Denied: Request blocked by security policy"
                )
            
            # Forward request if allowed
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=request.method,
                    url=str(request.url),
                    headers=dict(request.headers),
                    data=content
                ) as response:
                    # Get response content
                    resp_content = await response.read()
                    
                    # Create response
                    return web.Response(
                        status=response.status,
                        headers=dict(response.headers),
                        body=resp_content
                    )
                    
        except Exception as e:
            self.logger.error(f"Error processing request: {str(e)}")
            return web.Response(status=500, text="Internal Server Error")
    
    async def _check_policy(self, event: NetworkEvent) -> bool:
        """Check if the event violates any DLP policies."""
        if not self.policy_enforcer:
            return False
            
        try:
            # Convert event to context for policy evaluation
            context = {
                'source': 'network',
                'protocol': event.protocol.name,
                'source_ip': event.source_ip,
                'dest_ip': event.dest_ip,
                'dest_port': event.dest_port,
                'method': event.method,
                'url': event.url,
                'headers': event.headers,
                'content_type': event.content_type,
                'is_encrypted': event.is_encrypted
            }
            
            # Evaluate policies
            results = self.policy_enforcer.evaluate_content(
                content=event.content.decode('utf-8', errors='ignore'),
                scope='network',
                context=context
            )
            
            # Check if any actions indicate blocking
            for result in results:
                for action in result.get('actions_executed', []):
                    if action.get('type') == 'block' and action.get('success', False):
                        self.logger.warning(
                            f"Blocked request to {event.url} "
                            f"from {event.source_ip}: {action.get('message', 'Policy violation')}"
                        )
                        return True
                        
        except Exception as e:
            self.logger.error(f"Error checking policy: {str(e)}")
            
        return False
    
    async def start(self):
        """Start the network monitor."""
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        # Start HTTP server
        http_site = web.TCPSite(
            runner, 
            host=self.listen_address, 
            port=self.http_port
        )
        
        # Start HTTPS server
        https_site = web.TCPSite(
            runner,
            host=self.listen_address,
            port=self.https_port,
            ssl_context=self.ssl_context
        )
        
        await http_site.start()
        await https_site.start()
        
        self.logger.info(f"HTTP server running on http://{self.listen_address}:{self.http_port}")
        self.logger.info(f"HTTPS server running on https://{self.listen_address}:{self.https_port}")
        
        return runner
    
    async def stop(self, runner):
        """Stop the network monitor."""
        await runner.cleanup()
        self.logger.info("Network monitor stopped")
