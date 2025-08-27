"""
Script to start the EDR agent.
"""
import os
import sys
import time
import logging
import traceback
from pathlib import Path
from edr.agent.edr_agent import EDRAgent

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('edr_agent.log')
    ]
)

def main():
    """Main function to start the EDR agent."""
    print("Starting EDR Agent...")
    
    # Configuration
    config = {
        'agent_id': 'edr-agent-001',
        'data_dir': str(Path.home() / '.edr'),
        'rules_dir': str(Path(__file__).parent / 'edr' / 'rules'),
        'log_level': 'INFO'
    }
    
    try:
        # Create and start the agent
        agent = EDRAgent(config)
        agent.start()
        
        print("EDR Agent is running. Press Ctrl+C to stop.")
        
        # Keep the main thread alive
        while True:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping EDR Agent...")
                agent.stop()
                break
                
    except Exception as e:
        print(f"Error starting EDR agent: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
