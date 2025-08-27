"""
SIEM Correlation Engine Demo

This script demonstrates the usage of the correlation engine with sample rules and events.
"""

import os
import sys
import time
import random
import logging
import yaml
from datetime import datetime, timedelta
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.correlation_engine import CorrelationEngine, Severity

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('correlation_demo.log')
    ]
)
logger = logging.getLogger('siem.demo')

def load_rules(rules_file: str) -> list:
    """Load correlation rules from a YAML file."""
    try:
        with open(rules_file, 'r') as f:
            config = yaml.safe_load(f)
        return config.get('rules', [])
    except Exception as e:
        logger.error(f"Failed to load rules from {rules_file}: {e}")
        return []

def generate_sample_events() -> list:
    """Generate sample security events for demonstration."""
    events = []
    now = datetime.utcnow()
    
    # Sample users and IPs
    users = ['alice', 'bob', 'charlie', 'dave', 'eve', 'admin']
    source_ips = [f'192.168.1.{i}' for i in range(1, 11)]
    dest_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3']
    
    # 1. Generate failed login attempts
    for _ in range(20):
        user = random.choice(users)
        ip = random.choice(source_ips)
        events.append({
            '@timestamp': (now - timedelta(seconds=random.randint(0, 300))).isoformat(),
            'message': f"Failed password for {user} from {ip} port 22 ssh2",
            'source_ip': ip,
            'user': user,
            'event_type': 'authentication',
            'status': 'failed',
            'source': 'sshd',
            'destination_port': 22,
            'protocol': 'tcp'
        })
    
    # 2. Generate successful logins (some after failures)
    for _ in range(5):
        user = random.choice(users)
        ip = random.choice(source_ips[:3])  # Focus on first few IPs
        events.append({
            '@timestamp': (now - timedelta(seconds=random.randint(10, 60))).isoformat(),
            'message': f"Accepted password for {user} from {ip} port 22 ssh2",
            'source_ip': ip,
            'user': user,
            'event_type': 'authentication',
            'status': 'success',
            'source': 'sshd',
            'destination_port': 22,
            'protocol': 'tcp'
        })
    
    # 3. Generate port scan events
    for i in range(1, 5):
        ip = f'10.1.1.{i}'
        for port in range(1, 30):  # Scan first 30 ports
            events.append({
                '@timestamp': (now - timedelta(seconds=random.randint(0, 60))).isoformat(),
                'event_type': 'connection_attempt',
                'source_ip': ip,
                'destination_ip': random.choice(dest_ips),
                'destination_port': port,
                'protocol': 'tcp',
                'status': 'success' if random.random() > 0.3 else 'failed',
                'bytes_sent': random.randint(100, 5000),
                'bytes_received': random.randint(0, 1000),
                'source': 'firewall'
            })
    
    # 4. Generate web attack attempts
    web_attacks = [
        "/admin/..%2f..%2f..%2fetc/passwd",
        "/index.php?id=1' OR '1'='1",
        "/wp-login.php",
        "/.git/HEAD",
        "/.env",
        "/api/v1/users?admin=true"
    ]
    
    for _ in range(10):
        ip = random.choice(source_ips)
        attack = random.choice(web_attacks)
        events.append({
            '@timestamp': (now - timedelta(seconds=random.randint(0, 300))).isoformat(),
            'event_type': 'http_request',
            'source_ip': ip,
            'destination_ip': random.choice(dest_ips),
            'destination_port': 80,
            'http_method': random.choice(['GET', 'POST']),
            'http_uri': attack,
            'http_status': random.choice([200, 302, 403, 404, 500]),
            'http_user_agent': random.choice([
                'Mozilla/5.0',
                'sqlmap/1.5.2',
                'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
                'w3af.org'
            ]),
            'bytes_sent': random.randint(100, 5000),
            'bytes_received': random.randint(1000, 10000),
            'source': 'web_server'
        })
    
    # 5. Generate data exfiltration events
    for _ in range(3):
        ip = random.choice(source_ips[5:8])  # Specific IPs for this pattern
        events.append({
            '@timestamp': (now - timedelta(seconds=random.randint(0, 60))).isoformat(),
            'event_type': 'data_transfer',
            'source_ip': ip,
            'destination_ip': random.choice(['45.33.2.79', '185.199.109.154']),  # Example external IPs
            'destination_port': 443,
            'protocol': 'tcp',
            'bytes_sent': random.randint(15000000, 50000000),  # 15-50 MB
            'bytes_received': random.randint(1000, 5000),
            'source': 'firewall'
        })
    
    return events

def alert_callback(alert):
    """Handle correlation alerts."""
    print("\n" + "="*80)
    print(f"🚨 ALERT: {alert['rule_name']} (Severity: {alert['severity'].upper()})")
    print("="*80)
    print(f"Description: {alert['description']}")
    print(f"First seen: {alert['first_seen']}")
    print(f"Last seen: {alert['last_seen']}")
    print(f"Event count: {alert['event_count']}")
    
    if 'group' in alert and alert['group']:
        print("\nGroup details:")
        for k, v in alert['group'].items():
            if v:  # Only show non-empty values
                print(f"  {k}: {v}")
    
    if 'common_values' in alert and alert['common_values']:
        print("\nCommon values:")
        for k, v in alert['common_values'].items():
            if v and k not in alert.get('group', {}):  # Don't repeat group fields
                print(f"  {k}: {v}")
    
    if 'events' in alert and alert['events']:
        sample = alert['events'][0]  # Show first event as sample
        print("\nSample event:")
        for k, v in sample.items():
            if k not in ['@timestamp', 'message']:  # Skip already shown fields
                print(f"  {k}: {v}")
    
    print("\nActions:")
    for action in alert.get('actions', []):
        print(f"  - {action.get('type', 'unknown')}: {action.get('message', 'No message')}")
    
    print("\n" + "="*80 + "\n")

def main():
    # Load correlation rules
    rules_file = os.path.join(project_root, 'config', 'correlation_rules.yaml')
    if not os.path.exists(rules_file):
        logger.error(f"Rules file not found: {rules_file}")
        return 1
    
    rules = load_rules(rules_file)
    if not rules:
        logger.error("No rules loaded. Exiting.")
        return 1
    
    logger.info(f"Loaded {len(rules)} correlation rules")
    
    # Create and configure the correlation engine
    engine = CorrelationEngine(rules)
    engine.add_callback(alert_callback)
    
    # Generate sample events
    logger.info("Generating sample events...")
    events = generate_sample_events()
    
    # Process events
    logger.info(f"Processing {len(events)} events...")
    start_time = time.time()
    
    # Start the correlation engine
    engine.start()
    
    # Process events with small delays to simulate real-time processing
    for i, event in enumerate(events, 1):
        engine.process_event(event)
        if i % 10 == 0:
            logger.debug(f"Processed {i}/{len(events)} events")
        time.sleep(0.05)  # Small delay to simulate real-time processing
    
    # Keep running for a short time to process any pending correlations
    logger.info("Waiting for pending correlations...")
    time.sleep(2)
    
    # Stop the engine
    engine.stop()
    
    # Print statistics
    elapsed = time.time() - start_time
    stats = engine.get_rule_stats()
    
    print("\n" + "="*50)
    print("CORRELATION ENGINE DEMO COMPLETE")
    print("="*50)
    print(f"Processed {len(events)} events in {elapsed:.2f} seconds")
    print(f"Active rules: {stats['enabled_rules']}/{stats['total_rules']}")
    
    for rule in stats['rules']:
        print(f"\n- {rule['name']} (Severity: {rule['severity']})")
        print(f"  Active groups: {rule['window_count']}")
        print(f"  Total events: {rule['total_events']}")
    
    print("\nCheck the console output for any generated alerts.")
    print("="*50 + "\n")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
