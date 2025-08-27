"""
Network DLP Demo

Demonstrates the Network DLP monitoring capabilities.
"""
import asyncio
import logging
import json
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from siem.dlp import NetworkMonitor, PolicyEnforcer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('network_dlp_demo.log')
    ]
)
logger = logging.getLogger(__name__)

# Sample DLP policy
SAMPLE_POLICY = {
    "id": "block_sensitive_data",
    "name": "Block Sensitive Data in Transit",
    "description": "Block network traffic containing sensitive information",
    "scope": ["network"],
    "rules": [
        {
            "id": "block_credit_cards",
            "name": "Block Credit Card Numbers",
            "conditions": [
                {
                    "type": "pattern_match",
                    "field": "content",
                    "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
                    "sensitivity": "high"
                }
            ],
            "actions": [
                {
                    "type": "block",
                    "params": {
                        "message": "Credit card number detected in network traffic"
                    }
                },
                {
                    "type": "log",
                    "params": {
                        "message": "Blocked credit card number in network traffic"
                    }
                }
            ]
        },
        {
            "id": "block_ssn",
            "name": "Block Social Security Numbers",
            "conditions": [
                {
                    "type": "pattern_match",
                    "field": "content",
                    "pattern": r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b",
                    "sensitivity": "high"
                }
            ],
            "actions": [
                {
                    "type": "block",
                    "params": {
                        "message": "Social Security Number detected in network traffic"
                    }
                }
            ]
        }
    ]
}

async def test_http_traffic(proxy_url):
    """Test HTTP traffic through the proxy."""
    logger.info("Testing HTTP traffic...")
    
    # Configure the session to use our proxy
    connector = aiohttp.TCPConnector(ssl=False)
    session = aiohttp.ClientSession(connector=connector)
    
    try:
        # Test 1: Regular HTTP request (should pass)
        logger.info("Sending test request to httpbin.org/get")
        async with session.get("http://httpbin.org/get") as response:
            logger.info(f"Response status: {response.status}")
            data = await response.json()
            logger.info(f"Response data: {json.dumps(data, indent=2)[:200]}...")
        
        # Test 2: Request with credit card (should be blocked)
        logger.info("Sending request with credit card number")
        try:
            async with session.post(
                "http://httpbin.org/post",
                json={"card_number": "4111111111111111"}  # Test credit card number
            ) as response:
                logger.info(f"Unexpected response status: {response.status}")
                data = await response.text()
                logger.info(f"Response data: {data[:200]}...")
        except Exception as e:
            logger.info(f"Expected error (request blocked): {str(e)}")
            
    finally:
        await session.close()

async def main():
    """Run the Network DLP demo."""
    logger.info("Starting Network DLP Demo")
    
    # Initialize policy enforcer with sample policy
    policy_enforcer = PolicyEnforcer()
    policy_enforcer.load_policy_from_dict(SAMPLE_POLICY)
    
    # Create and start the network monitor
    monitor = NetworkMonitor(
        policy_enforcer=policy_enforcer,
        listen_address='127.0.0.1',
        http_port=8080,
        https_port=8443
    )
    
    try:
        # Start the monitor
        runner = await monitor.start()
        
        # Test the monitor
        await test_http_traffic("http://127.0.0.1:8080")
        
        # Keep the server running
        logger.info("Network DLP proxy is running. Press Ctrl+C to stop...")
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Stopping Network DLP proxy...")
    
    finally:
        # Clean up
        await monitor.stop(runner)
        logger.info("Network DLP Demo completed")

if __name__ == "__main__":
    try:
        import aiohttp
        asyncio.run(main())
    except ImportError:
        logger.error("Required packages not found. Please install with:")
        logger.error("pip install aiohttp")
        sys.exit(1)
