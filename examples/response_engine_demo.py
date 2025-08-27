"""
Example usage of the NDR Response Engine
"""
import asyncio
import logging
from datetime import datetime

from ndr.models.alert import NetworkAlert, AlertSeverity, AlertType
from ndr.response_engine import ResponseEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ndr.example')

async def main():
    # Initialize the response engine
    engine = ResponseEngine({
        'playbooks_dir': 'config/response_playbooks'
    })
    
    try:
        # Start the engine
        await engine.start()
        
        # Create a test alert
        alert = NetworkAlert(
            id="alert-123",
            title="Malware C2 Communication Detected",
            description="Established connection to known C2 server",
            alert_type=AlertType.MALWARE,
            severity=AlertSeverity.HIGH,
            source_ip="192.168.1.100",
            destination_ip="45.227.253.108",  # Example C2 IP
            timestamp=datetime.utcnow(),
            tags=["malware", "c2", "emotet"],
            metadata={
                "malware_family": "Emotet",
                "confidence": 0.95,
                "protocol": "tcp",
                "port": 443
            }
        )
        
        # Process the alert
        logger.info("Processing alert...")
        await engine.process_alert(alert)
        
        # Keep the engine running to process async operations
        await asyncio.sleep(5)
        
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await engine.stop()

if __name__ == "__main__":
    asyncio.run(main())
