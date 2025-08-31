"""
Windows Event Forwarding (WEF) Collector

This module implements a Windows Event Forwarding client that can subscribe to
Windows Event Collector (WEC) servers and process forwarded Windows events.
"""
import asyncio
import logging
import ssl
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable, Union
from urllib.parse import urlparse
import aiohttp
from defusedxml import ElementTree as DefusedET
from requests_ntlm import HttpNtlmAuth
from requests_kerberos import HTTPKerberosAuth, DISABLED

logger = logging.getLogger('siem.collector.wef')

# Constants
WEC_HEADERS = {
    'Content-Type': 'application/soap+xml; charset=utf-8',
    'User-Agent': 'SIEM-WEF-Collector/1.0'
}

# SOAP envelope template for WEF subscription
WEF_SUBSCRIBE_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
            xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe</a:Action>
    <a:MessageID>uuid:{message_id}</a:MessageID>
    <a:To s:mustUnderstand="1">{wec_url}</a:To>
    <SubscriptionId>uuid:{subscription_id}</SubscriptionId>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
  </s:Header>
  <s:Body>
    <Subscribe xmlns="http://schemas.xmlsoap.org/ws/2004/08/eventing">
      <Delivery Mode="Push">
        <PushSettings>
          <Heartbeats>
            <Heartbeat Interval="PT60S"/>
          </Heartbeats>
        </PushSettings>
      </Delivery>
      <Expires>PT{expiry_time}M</Expires>
      <Filter xmlns:q1="http://schemas.microsoft.com/windows/2004/02/events" 
              Dialect="http://schemas.microsoft.com/wbem/wsman/1/WQL">
        {query}
      </Filter>
    </Subscribe>
  </s:Body>
</s:Envelope>"""

class WEFCollector:
    """Windows Event Forwarding (WEF) collector for receiving Windows events."""
    
    def __init__(self, config: Dict[str, Any], callback: Callable[[Dict[str, Any]], None]):
        """Initialize the WEF collector.
        
        Args:
            config: Configuration dictionary with WEF settings
            callback: Callback function to process received events
        """
        self.config = config
        self.callback = callback
        self.running = False
        self.session = None
        self.subscription_id = None
        self.subscription_url = None
        self.heartbeat_task = None
        self.ssl_context = None
        
    async def start(self):
        """Start the WEF collector and establish subscriptions."""
        if self.running:
            logger.warning("WEF collector is already running")
            return
            
        self.running = True
        
        # Set up SSL context if using HTTPS
        if self.config.get('use_https', True):
            self.ssl_context = ssl.create_default_context()
            if not self.config.get('verify_ssl', True):
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE
            
            # Load client certificate if provided
            if self.config.get('cert_file') and self.config.get('key_file'):
                self.ssl_context.load_cert_chain(
                    certfile=self.config['cert_file'],
                    keyfile=self.config['key_file']
                )
        
        # Set up authentication
        auth = None
        if self.config.get('auth_type', 'ntlm').lower() == 'kerberos':
            auth = HTTPKerberosAuth(
                mutual_authentication=DISABLED if not self.config.get('force_mutual_auth', False) else 1,
                delegate=self.config.get('delegate_credentials', False)
            )
        else:  # Default to NTLM
            auth = HttpNtlmAuth(
                f"{self.config.get('domain', '')}\\{self.config['username']}",
                self.config['password']
            )
        
        # Create aiohttp session
        self.session = aiohttp.ClientSession(
            auth=auth,
            headers=WEC_HEADERS,
            connector=aiohttp.TCPConnector(ssl=self.ssl_context)
        )
        
        # Subscribe to WEF
        await self._subscribe()
        
        # Start heartbeat monitor
        self.heartbeat_task = asyncio.create_task(self._heartbeat_monitor())
        
        logger.info("WEF collector started")
    
    async def stop(self):
        """Stop the WEF collector and clean up resources."""
        if not self.running:
            return
            
        self.running = False
        
        # Cancel heartbeat task
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
            self.heartbeat_task = None
        
        # Unsubscribe if we have an active subscription
        if self.subscription_id and self.session:
            try:
                await self._unsubscribe()
            except Exception as e:
                logger.error(f"Error unsubscribing from WEF: {e}")
        
        # Close the session
        if self.session:
            await self.session.close()
            self.session = None
        
        logger.info("WEF collector stopped")
    
    async def _subscribe(self):
        """Subscribe to Windows Event Collector."""
        wec_url = self.config.get('wec_url')
        if not wec_url:
            raise ValueError("WEC URL not configured")
        
        # Generate subscription ID
        import uuid
        subscription_id = str(uuid.uuid4())
        
        # Build the subscription request
        query = self.config.get('query', "<QueryList><Query Id='0'><Select Path='Security'>*</Select></Query></QueryList>")
        expiry_minutes = self.config.get('subscription_expiry', 60)
        
        # Format the SOAP request
        request_body = WEF_SUBSCRIBE_TEMPLATE.format(
            message_id=str(uuid.uuid4()),
            wec_url=wec_url,
            subscription_id=subscription_id,
            expiry_time=expiry_minutes,
            query=query
        )
        
        try:
            # Send subscription request
            async with self.session.post(
                wec_url,
                data=request_body,
                headers={"Content-Type": "application/soap+xml; charset=utf-8"},
                timeout=30
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"WEF subscription failed: {response.status} - {error_text}")
                
                # Parse the response to get subscription details
                response_xml = await response.text()
                root = DefusedET.fromstring(response_xml)
                
                # Extract subscription identifier
                ns = {'wsa': 'http://www.w3.org/2005/08/addressing'}
                sub_elem = root.find('.//wsa:Address', namespaces=ns)
                if sub_elem is None:
                    raise Exception("Invalid subscription response: missing subscription address")
                
                self.subscription_url = sub_elem.text
                self.subscription_id = subscription_id
                
                logger.info(f"Subscribed to WEF at {wec_url} with ID {subscription_id}")
                
        except Exception as e:
            logger.error(f"Failed to subscribe to WEF: {e}")
            raise
    
    async def _unsubscribe(self):
        """Unsubscribe from Windows Event Collector."""
        if not self.subscription_url:
            return
            
        # Build the unsubscribe request
        unsubscribe_template = """<?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
                    xmlns:a="http://www.w3.org/2005/08/addressing">
          <s:Header>
            <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/08/eventing/Unsubscribe</a:Action>
            <a:MessageID>uuid:{message_id}</a:MessageID>
            <a:To s:mustUnderstand="1">{wec_url}</a:To>
            <a:ReplyTo>
              <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
            </a:ReplyTo>
          </s:Header>
          <s:Body>
            <Unsubscribe xmlns="http://schemas.xmlsoap.org/ws/2004/08/eventing"/>
          </s:Body>
        </s:Envelope>"""
        
        try:
            request_body = unsubscribe_template.format(
                message_id=str(uuid.uuid4()),
                wec_url=self.subscription_url
            )
            
            async with self.session.post(
                self.subscription_url,
                data=request_body,
                headers={"Content-Type": "application/soap+xml; charset=utf-8"},
                timeout=30
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.warning(f"WEF unsubscribe failed: {response.status} - {error_text}")
                else:
                    logger.info(f"Unsubscribed from WEF subscription {self.subscription_id}")
                    
        except Exception as e:
            logger.error(f"Error unsubscribing from WEF: {e}")
        finally:
            self.subscription_id = None
            self.subscription_url = None
    
    async def _heartbeat_monitor(self):
        """Monitor the WEF subscription and handle heartbeats."""
        while self.running:
            try:
                # Check subscription status periodically
                await asyncio.sleep(30)  # Check every 30 seconds
                
                if not self.subscription_url or not self.session:
                    logger.warning("No active WEF subscription, attempting to resubscribe...")
                    await self._subscribe()
                    continue
                
                # Send a simple request to check if the subscription is still active
                async with self.session.get(
                    self.subscription_url,
                    headers={"Accept": "application/soap+xml"},
                    timeout=10
                ) as response:
                    if response.status != 200:
                        logger.warning(f"WEF subscription check failed: {response.status}")
                        await self._subscribe()  # Try to resubscribe
                        
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in WEF heartbeat monitor: {e}")
                await asyncio.sleep(10)  # Wait before retrying
    
    async def handle_event(self, event_xml: str):
        """Process a received Windows event.
        
        Args:
            event_xml: The raw XML event data
        """
        try:
            # Parse the XML event
            root = DefusedET.fromstring(event_xml)
            
            # Extract event data
            event_data = {
                'event_id': None,
                'level': None,
                'time_created': None,
                'source': 'wef',
                'raw': event_xml,
                'data': {}
            }
            
            # Extract basic event information
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            # Get system data
            system = root.find('.//e:System', namespaces=ns)
            if system is not None:
                event_data.update({
                    'event_id': system.findtext('e:EventID', namespaces=ns),
                    'level': system.findtext('e:Level', namespaces=ns),
                    'time_created': system.findtext('e:TimeCreated', namespaces=ns, attrib={'SystemTime': None}),
                    'computer': system.findtext('e:Computer', namespaces=ns),
                    'channel': system.findtext('e:Channel', namespaces=ns),
                    'provider': {
                        'name': system.findtext('e:Provider', namespaces=ns, attrib={'Name': None}),
                        'guid': system.findtext('e:Provider', namespaces=ns, attrib={'Guid': None})
                    },
                    'security': {
                        'user_id': system.findtext('e:Security', namespaces=ns, attrib={'UserID': None})
                    }
                })
            
            # Get event data
            event_data_node = root.find('.//e:EventData', namespaces=ns)
            if event_data_node is not None:
                for data_item in event_data_node.findall('e:Data', namespaces=ns):
                    name = data_item.get('Name')
                    value = data_item.text
                    if name:
                        event_data['data'][name] = value
                    else:
                        # For unnamed data items, use numeric index
                        idx = len([k for k in event_data['data'].keys() if k.isdigit()]) + 1
                        event_data['data'][str(idx)] = value
            
            # Get user data if present
            user_data = root.find('.//e:UserData', namespaces=ns)
            if user_data is not None:
                event_data['user_data'] = DefusedET.tostring(user_data, encoding='unicode')
            
            # Call the callback with the processed event
            self.callback(event_data)
            
        except Exception as e:
            logger.error(f"Error processing WEF event: {e}", exc_info=True)
            # Log the raw XML for debugging
            logger.debug(f"Raw event XML: {event_xml}")

# Example usage
async def example_callback(event: Dict[str, Any]):
    """Example callback function for processing WEF events."""
    print(f"Received WEF event: {event.get('event_id')} - {event.get('computer')}")
    print(f"Event data: {event}")

async def example_usage():
    """Example of how to use the WEF collector."""
    config = {
        'wec_url': 'https://wec-server.example.com:5985/wsman',
        'auth_type': 'ntlm',  # or 'kerberos'
        'username': 'domain\\user',
        'password': 'password',
        'use_https': True,
        'verify_ssl': False,  # Set to True in production with valid certificates
        'query': """
        <QueryList>
          <Query Id="0" Path="Security">
            <Select Path="Security">*[System[(Level=1  or Level=2 or Level=3 or Level=4)]]</Select>
          </Query>
        </QueryList>
        """
    }
    
    collector = WEFCollector(config, example_callback)
    
    try:
        await collector.start()
        
        # Keep the collector running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        await collector.stop()

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Run the example
    asyncio.run(example_usage())
