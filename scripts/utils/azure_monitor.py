"""
Azure Monitor Logs Source for Enhanced Log Collector.
"""

import os
import time
import json
import logging
import requests
from typing import Dict, List, Optional, Callable, Any, Union
from datetime import datetime, timedelta, timezone
from threading import Thread, Event, Lock
from queue import Queue
from concurrent.futures import ThreadPoolExecutor

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.subscription import SubscriptionClient

from ..core.enhanced_log_collector import LogSource, LogSourceType

class AzureMonitorSource(LogSource):
    """Log source for Azure Monitor Logs."""
    
    def __init__(self, source_id: str, **kwargs):
        """Initialize the Azure Monitor source.
        
        Args:
            source_id: Unique identifier for this source
            **kwargs: Additional configuration options
        """
        config = {
            'tenant_id': kwargs.get('tenant_id'),
            'client_id': kwargs.get('client_id'),
            'client_secret': kwargs.get('client_secret'),
            'subscription_ids': kwargs.get('subscription_ids', []),  # List of subscription IDs to monitor
            'resource_groups': kwargs.get('resource_groups', []),    # List of resource groups to monitor
            'log_categories': kwargs.get('log_categories', [
                'Security', 'AuditLogs', 'SignInLogs', 'AzureActivity',
                'NetworkSecurityGroupEvent', 'NetworkSecurityGroupRuleCounter'
            ]),
            'poll_interval': kwargs.get('poll_interval', 300),  # 5 minutes
            'lookback_minutes': kwargs.get('lookback_minutes', 15),
            'max_workers': kwargs.get('max_workers', 5),
            'use_managed_identity': kwargs.get('use_managed_identity', False)
        }
        super().__init__(source_id, LogSourceType.CLOUD, config)
        
        # State tracking
        self._stop_event = Event()
        self._last_processed_times = {}
        self._state_file = f'azure_monitor_state_{source_id}.json'
        self._load_state()
        
        # Initialize Azure clients
        self.credential = self._get_credentials()
        self.subscription_client = None
        self.monitor_clients = {}
        
        # Thread pool for processing
        self._executor = ThreadPoolExecutor(max_workers=config['max_workers'])
        self._event_queue = Queue(maxsize=1000)
        
        # Start the processor thread
        self._processor_thread = Thread(
            target=self._process_events_loop,
            name=f"AzureMonitorProcessor-{source_id}",
            daemon=True
        )
    
    def _get_credentials(self):
        """Get Azure credentials."""
        if self.config['use_managed_identity']:
            return DefaultAzureCredential()
        else:
            return ClientSecretCredential(
                tenant_id=self.config['tenant_id'],
                client_id=self.config['client_id'],
                client_secret=self.config['client_secret']
            )
    
    def _get_monitor_client(self, subscription_id: str):
        """Get or create a MonitorManagementClient for the given subscription."""
        if subscription_id not in self.monitor_clients:
            self.monitor_clients[subscription_id] = MonitorManagementClient(
                credential=self.credential,
                subscription_id=subscription_id
            )
        return self.monitor_clients[subscription_id]
    
    def _get_subscription_client(self):
        """Get the subscription client."""
        if not self.subscription_client:
            self.subscription_client = SubscriptionClient(self.credential)
        return self.subscription_client
    
    def _get_subscriptions(self) -> List[str]:
        """Get the list of subscriptions to monitor."""
        if self.config['subscription_ids']:
            return self.config['subscription_ids']
            
        # If no subscriptions specified, get all accessible ones
        try:
            sub_client = self._get_subscription_client()
            return [sub.subscription_id for sub in sub_client.subscriptions.list()]
        except Exception as e:
            self.logger.error(f"Error listing subscriptions: {e}")
            return []
    
    def start(self):
        """Start collecting Azure Monitor logs."""
        super().start()
        
        try:
            # Start the processor thread
            self._processor_thread.start()
            
            # Start the poller thread
            self._poller_thread = Thread(
                target=self._poll_loop,
                name=f"AzureMonitorPoller-{self.source_id}",
                daemon=True
            )
            self._poller_thread.start()
            
            self.logger.info("Started Azure Monitor source")
            
        except Exception as e:
            self.logger.error(f"Failed to start Azure Monitor source: {e}")
            self.stop()
    
    def stop(self):
        """Stop collecting Azure Monitor logs."""
        self._stop_event.set()
        
        # Save state before stopping
        self._save_state()
        
        # Shutdown the executor
        self._executor.shutdown(wait=False)
        
        super().stop()
    
    def _poll_loop(self):
        """Main loop for polling Azure Monitor logs."""
        while not self._stop_event.is_set():
            try:
                self._poll_logs()
                
                # Wait for the next poll interval
                self._stop_event.wait(self.config['poll_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in poll loop: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _poll_logs(self):
        """Poll for new logs from Azure Monitor."""
        try:
            # Get subscriptions to monitor
            subscriptions = self._get_subscriptions()
            
            # Process each subscription
            for subscription_id in subscriptions:
                if self._stop_event.is_set():
                    break
                    
                # Get or create monitor client for this subscription
                monitor_client = self._get_monitor_client(subscription_id)
                
                # Process each log category
                for category in self.config['log_categories']:
                    if self._stop_event.is_set():
                        break
                        
                    # Get the last processed time for this subscription and category
                    state_key = f"{subscription_id}:{category}"
                    last_processed = self._last_processed_times.get(state_key)
                    
                    # Set the time range for the query
                    end_time = datetime.now(timezone.utc)
                    start_time = last_processed if last_processed else end_time - timedelta(
                        minutes=self.config['lookback_minutes']
                    )
                    
                    # Skip if the time range is too small
                    if (end_time - start_time).total_seconds() < 60:
                        continue
                    
                    try:
                        # Query Azure Monitor logs
                        self._query_azure_monitor(
                            monitor_client=monitor_client,
                            subscription_id=subscription_id,
                            category=category,
                            start_time=start_time,
                            end_time=end_time
                        )
                        
                        # Update the last processed time
                        self._last_processed_times[state_key] = end_time
                        
                    except Exception as e:
                        self.logger.error(
                            f"Error querying {category} logs for subscription {subscription_id}: {e}"
                        )
                        
        except Exception as e:
            self.logger.error(f"Error polling Azure Monitor logs: {e}")
    
    def _query_azure_monitor(self, monitor_client, subscription_id: str, category: str,
                            start_time: datetime, end_time: datetime):
        """Query Azure Monitor logs for a specific category and time range."""
        # Format the time range
        timespan = f"{start_time.isoformat()}/{end_time.isoformat()}"
        
        # Build the query based on the log category
        if category == 'Security':
            query = "SecurityEvent | where TimeGenerated > ago(1h) | limit 100"
        elif category == 'AuditLogs':
            query = "AuditLogs | where TimeGenerated > ago(1h) | limit 100"
        elif category == 'SignInLogs':
            query = "SigninLogs | where TimeGenerated > ago(1h) | limit 100"
        elif category == 'AzureActivity':
            query = "AzureActivity | where TimeGenerated > ago(1h) | limit 100"
        else:
            # Default query for other log types
            query = f"{category} | where TimeGenerated > ago(1h) | limit 100"
        
        try:
            # Execute the query
            result = monitor_client.query.workspace(
                workspace_id=self._get_log_analytics_workspace_id(subscription_id),
                body={
                    "query": query,
                    "timespan": timespan
                }
            )
            
            # Process the results
            if result.tables:
                for row in result.tables[0].rows:
                    # Convert the row to a dictionary
                    event = {}
                    for i, col in enumerate(result.tables[0].columns):
                        event[col.name] = row[i]
                    
                    # Add to the processing queue
                    self._event_queue.put({
                        'subscription_id': subscription_id,
                        'category': category,
                        'event': event,
                        'timestamp': event.get('TimeGenerated', datetime.utcnow().isoformat())
                    })
            
        except Exception as e:
            self.logger.error(f"Error executing Azure Monitor query: {e}")
            raise
    
    def _get_log_analytics_workspace_id(self, subscription_id: str) -> str:
        """Get the Log Analytics workspace ID for the given subscription."""
        # This is a placeholder - in a real implementation, you would look up the workspace ID
        # from your configuration or from Azure Resource Graph
        return f"/subscriptions/{subscription_id}/resourcegroups/DefaultResourceGroup/providers/Microsoft.OperationalInsights/workspaces/DefaultWorkspace"
    
    def _process_events_loop(self):
        """Process events from the queue."""
        while not self._stop_event.is_set():
            try:
                event = self._event_queue.get(timeout=1.0)
                self._executor.submit(self._process_event, event)
                self._event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in event processor: {e}")
    
    def _process_event(self, event: dict):
        """Process a single event."""
        try:
            # Create the log entry
            entry = {
                '@timestamp': event.get('timestamp', datetime.utcnow().isoformat()),
                'source': self.source_id,
                'subscription_id': event.get('subscription_id'),
                'category': event.get('category'),
                'event': event.get('event', {}),
                'raw': json.dumps(event.get('event', {}), default=str)
            }
            
            # Notify callbacks
            self._notify_callbacks(entry)
            
        except Exception as e:
            self.logger.error(f"Error processing event: {e}")
    
    def _load_state(self):
        """Load the state from disk."""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file, 'r') as f:
                    state = json.load(f)
                    
                    self._last_processed_times = {
                        k: datetime.fromisoformat(v) 
                        for k, v in state.get('last_processed_times', {}).items()
                    }
                    
                    self.logger.info(f"Loaded state from {self._state_file}")
                    
        except Exception as e:
            self.logger.error(f"Error loading state: {e}")
    
    def _save_state(self):
        """Save the state to disk."""
        try:
            state = {
                'last_processed_times': {
                    k: v.isoformat() 
                    for k, v in self._last_processed_times.items()
                }
            }
            
            with open(self._state_file, 'w') as f:
                json.dump(state, f)
            
            self.logger.debug(f"Saved state to {self._state_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving state: {e}")

# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Create an Azure Monitor source
    source = AzureMonitorSource(
        source_id='azure_monitor',
        tenant_id='your-tenant-id',
        client_id='your-client-id',
        client_secret='your-client-secret',
        subscription_ids=['your-subscription-id'],
        log_categories=['Security', 'AuditLogs', 'SignInLogs', 'AzureActivity'],
        poll_interval=300,  # 5 minutes
        lookback_minutes=15
    )
    
    # Register a callback to print events
    def print_event(entry):
        event = entry.get('event', {})
        print(f"[{entry.get('@timestamp')}] [{entry.get('category')}] {event.get('OperationName', '')}")
    
    source.register_callback(print_event)
    
    # Start the source
    source.start()
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Azure Monitor source...")
        source.stop()
