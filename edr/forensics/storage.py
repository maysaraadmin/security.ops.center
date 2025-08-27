"""
Storage backends for forensic data and timeline events.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Union
import hashlib
import os
from abc import ABC, abstractmethod

from ..forensics.timeline import TimelineEvent, EventType, TimelineStorage

class ElasticsearchStorage(TimelineStorage):
    """Elasticsearch backend for timeline storage and querying."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the Elasticsearch storage backend."""
        try:
            from elasticsearch import Elasticsearch, helpers
            from elasticsearch.exceptions import ElasticsearchException
            self.es = Elasticsearch(
                hosts=config.get('hosts', ['http://localhost:9200']),
                http_auth=config.get('http_auth'),
                verify_certs=config.get('verify_certs', True),
                timeout=config.get('timeout', 30),
                max_retries=3,
                retry_on_timeout=True
            )
            self.helpers = helpers
            self.ElasticsearchException = ElasticsearchException
            self.index_prefix = config.get('index_prefix', 'edr-timeline')
            self.logger = logging.getLogger('edr.forensics.storage.elasticsearch')
            self._ensure_index_template()
        except ImportError:
            raise ImportError("Elasticsearch client not installed. Install with: pip install elasticsearch")
    
    def _get_index_name(self, timestamp: datetime) -> str:
        """Get the index name for a given timestamp (monthly indices)."""
        return f"{self.index_prefix}-{timestamp.strftime('%Y.%m')}"
    
    def _ensure_index_template(self) -> None:
        """Ensure the index template exists in Elasticsearch."""
        template_name = f"{self.index_prefix}-template"
        template = {
            "index_patterns": [f"{self.index_prefix}-*"],
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1,
                "index.refresh_interval": "30s",
                "index.mapping.total_fields.limit": 5000,
                "index.mapping.nested_fields.limit": 50
            },
            "mappings": {
                "properties": {
                    "event_id": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "source": {"type": "keyword"},
                    "description": {"type": "text"},
                    "tags": {"type": "keyword"},
                    "process": {
                        "properties": {
                            "pid": {"type": "long"},
                            "name": {"type": "keyword"},
                            "path": {"type": "keyword"},
                            "command_line": {"type": "text"},
                            "parent_pid": {"type": "long"},
                            "parent_name": {"type": "keyword"},
                            "integrity_level": {"type": "keyword"},
                            "user": {"type": "keyword"}
                        }
                    },
                    "file": {
                        "properties": {
                            "path": {"type": "keyword"},
                            "name": {"type": "keyword"},
                            "size": {"type": "long"},
                            "hash_md5": {"type": "keyword"},
                            "hash_sha1": {"type": "keyword"},
                            "hash_sha256": {"type": "keyword"},
                            "created": {"type": "date"},
                            "modified": {"type": "date"},
                            "accessed": {"type": "date"}
                        }
                    },
                    "network": {
                        "properties": {
                            "source_ip": {"type": "ip"},
                            "source_port": {"type": "integer"},
                            "dest_ip": {"type": "ip"},
                            "dest_port": {"type": "integer"},
                            "protocol": {"type": "keyword"},
                            "direction": {"type": "keyword"},
                            "size": {"type": "long"},
                            "dns_query": {"type": "keyword"},
                            "dns_response": {"type": "keyword"}
                        }
                    },
                    "registry": {
                        "properties": {
                            "key": {"type": "keyword"},
                            "value": {"type": "keyword"},
                            "data": {"type": "keyword"},
                            "action": {"type": "keyword"}
                        }
                    },
                    "user": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "domain": {"type": "keyword"},
                            "sid": {"type": "keyword"},
                            "logon_id": {"type": "keyword"},
                            "session_id": {"type": "integer"}
                        }
                    },
                    "endpoint": {
                        "properties": {
                            "hostname": {"type": "keyword"},
                            "ip_address": {"type": "ip"},
                            "os": {"type": "keyword"},
                            "os_version": {"type": "keyword"}
                        }
                    },
                    "metadata": {"type": "object", "enabled": True}
                }
            }
        }
        
        try:
            self.es.indices.put_template(
                name=template_name,
                body=template,
                create=True
            )
            self.logger.info(f"Created index template: {template_name}")
        except self.ElasticsearchException as e:
            if 'resource_already_exists_exception' not in str(e):
                self.logger.error(f"Failed to create index template: {e}")
    
    def store_event(self, event: TimelineEvent) -> bool:
        """Store a timeline event in Elasticsearch."""
        try:
            # Convert event to dictionary
            event_dict = event.to_dict()
            
            # Ensure timestamp is a datetime object
            if isinstance(event_dict['timestamp'], str):
                event_dict['timestamp'] = datetime.fromisoformat(
                    event_dict['timestamp'].replace('Z', '+00:00')
                )
            
            # Get index name based on timestamp
            index_name = self._get_index_name(event_dict['timestamp'])
            
            # Prepare document for Elasticsearch
            doc = {
                '_index': index_name,
                '_id': event.event_id,
                '_source': event_dict
            }
            
            # Index the document
            self.es.index(
                index=index_name,
                id=event.event_id,
                body=event_dict,
                refresh=True
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store event {event.event_id}: {e}")
            return False
    
    def store_events_bulk(self, events: List[TimelineEvent]) -> Tuple[int, int]:
        """Store multiple events in bulk."""
        if not events:
            return 0, 0
            
        success = 0
        actions = []
        
        for event in events:
            try:
                event_dict = event.to_dict()
                
                if isinstance(event_dict['timestamp'], str):
                    event_dict['timestamp'] = datetime.fromisoformat(
                        event_dict['timestamp'].replace('Z', '+00:00')
                    )
                
                index_name = self._get_index_name(event_dict['timestamp'])
                
                actions.append({
                    '_op_type': 'index',
                    '_index': index_name,
                    '_id': event.event_id,
                    '_source': event_dict
                })
                
            except Exception as e:
                self.logger.error(f"Error preparing event {getattr(event, 'event_id', 'unknown')} for bulk insert: {e}")
        
        if actions:
            try:
                success, _ = self.helpers.bulk(self.es, actions, stats_only=True)
                return success, len(actions) - success
            except Exception as e:
                self.logger.error(f"Bulk insert failed: {e}")
                return 0, len(actions)
        
        return 0, 0
    
    def get_event(self, event_id: str) -> Optional[TimelineEvent]:
        """Retrieve a timeline event by ID."""
        try:
            # Search across all indices with the prefix
            result = self.es.search(
                index=f"{self.index_prefix}-*",
                body={
                    "query": {
                        "term": {
                            "event_id": event_id
                        }
                    },
                    "size": 1
                }
            )
            
            if result['hits']['total']['value'] > 0:
                hit = result['hits']['hits'][0]
                return TimelineEvent.from_dict(hit['_source'])
                
        except Exception as e:
            self.logger.error(f"Failed to retrieve event {event_id}: {e}")
            
        return None
    
    def query_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[EventType]] = None,
        source: Optional[str] = None,
        process_id: Optional[int] = None,
        file_path: Optional[str] = None,
        ip_address: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 1000
    ) -> List[TimelineEvent]:
        """Query timeline events based on criteria."""
        try:
            # Build the query
            must_conditions = []
            
            # Time range filter
            if start_time or end_time:
                time_filter = {}
                if start_time:
                    time_filter['gte'] = start_time.isoformat()
                if end_time:
                    time_filter['lte'] = end_time.isoformat()
                must_conditions.append({'range': {'timestamp': time_filter}})
            
            # Event type filter
            if event_types:
                must_conditions.append({
                    'terms': {
                        'event_type': [et.value for et in event_types]
                    }
                })
            
            # Source filter
            if source:
                must_conditions.append({'term': {'source': source}})
            
            # Process ID filter
            if process_id is not None:
                must_conditions.append({'term': {'process.pid': process_id}})
            
            # File path filter (partial match)
            if file_path:
                must_conditions.append({
                    'wildcard': {
                        'file.path': f"*{file_path}*"
                    }
                })
            
            # IP address filter (source or destination)
            if ip_address:
                must_conditions.append({
                    'bool': {
                        'should': [
                            {'term': {'network.source_ip': ip_address}},
                            {'term': {'network.dest_ip': ip_address}}
                        ],
                        'minimum_should_match': 1
                    }
                })
            
            # Tags filter
            if tags:
                for tag in tags:
                    must_conditions.append({'term': {'tags': tag}})
            
            # Build the final query
            query = {'match_all': {}}
            if must_conditions:
                query = {'bool': {'must': must_conditions}}
            
            # Determine indices to search
            indices = f"{self.index_prefix}-*"
            
            # Execute the search
            result = self.es.search(
                index=indices,
                body={
                    'query': query,
                    'sort': [
                        {'timestamp': {'order': 'asc'}},
                        {'_id': {'order': 'asc'}}
                    ],
                    'size': min(limit, 10000)  # Limit to 10k results max
                }
            )
            
            # Convert hits to TimelineEvent objects
            events = []
            for hit in result['hits']['hits']:
                try:
                    events.append(TimelineEvent.from_dict(hit['_source']))
                except Exception as e:
                    self.logger.error(f"Error parsing event {hit.get('_id')}: {e}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Query failed: {e}")
            return []
    
    def get_event_count(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[EventType]] = None
    ) -> int:
        """Get the count of events matching the criteria."""
        try:
            # Build the query
            must_conditions = []
            
            # Time range filter
            if start_time or end_time:
                time_filter = {}
                if start_time:
                    time_filter['gte'] = start_time.isoformat()
                if end_time:
                    time_filter['lte'] = end_time.isoformat()
                must_conditions.append({'range': {'timestamp': time_filter}})
            
            # Event type filter
            if event_types:
                must_conditions.append({
                    'terms': {
                        'event_type': [et.value for et in event_types]
                    }
                })
            
            # Build the final query
            query = {'match_all': {}}
            if must_conditions:
                query = {'bool': {'must': must_conditions}}
            
            # Execute the count
            result = self.es.count(
                index=f"{self.index_prefix}-*",
                body={'query': query}
            )
            
            return result['count']
            
        except Exception as e:
            self.logger.error(f"Count query failed: {e}")
            return 0
    
    def get_event_statistics(
        self,
        start_time: datetime,
        end_time: datetime,
        interval: str = '1h'
    ) -> Dict[str, Any]:
        """Get event statistics over time."""
        try:
            result = self.es.search(
                index=f"{self.index_prefix}-*",
                body={
                    'query': {
                        'range': {
                            'timestamp': {
                                'gte': start_time.isoformat(),
                                'lte': end_time.isoformat()
                            }
                        }
                    },
                    'aggs': {
                        'events_over_time': {
                            'date_histogram': {
                                'field': 'timestamp',
                                'fixed_interval': interval,
                                'min_doc_count': 0
                            },
                            'aggs': {
                                'by_type': {
                                    'terms': {
                                        'field': 'event_type',
                                        'size': 10
                                    }
                                }
                            }
                        },
                        'top_event_types': {
                            'terms': {
                                'field': 'event_type',
                                'size': 10
                            }
                        },
                        'top_sources': {
                            'terms': {
                                'field': 'source',
                                'size': 10
                            }
                        },
                        'top_processes': {
                            'terms': {
                                'field': 'process.name',
                                'size': 10
                            }
                        }
                    },
                    'size': 0
                }
            )
            
            return {
                'time_series': result['aggregations']['events_over_time'],
                'top_event_types': result['aggregations']['top_event_types'],
                'top_sources': result['aggregations']['top_sources'],
                'top_processes': result['aggregations']['top_processes']
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get event statistics: {e}")
            return {}


class FileSystemStorage(TimelineStorage):
    """File system based storage for timeline events (for testing/development)."""
    
    def __init__(self, base_dir: str = "/tmp/edr-timeline"):
        """Initialize the file system storage."""
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        self.logger = logging.getLogger('edr.forensics.storage.filesystem')
    
    def _get_event_path(self, event_id: str) -> str:
        """Get the file path for an event."""
        return os.path.join(self.base_dir, f"{event_id}.json")
    
    def store_event(self, event: TimelineEvent) -> bool:
        """Store a timeline event in the file system."""
        try:
            event_path = self._get_event_path(event.event_id)
            with open(event_path, 'w') as f:
                json.dump(event.to_dict(), f, indent=2, default=str)
            return True
        except Exception as e:
            self.logger.error(f"Failed to store event {event.event_id}: {e}")
            return False
    
    def get_event(self, event_id: str) -> Optional[TimelineEvent]:
        """Retrieve a timeline event by ID."""
        try:
            event_path = self._get_event_path(event_id)
            if os.path.exists(event_path):
                with open(event_path, 'r') as f:
                    return TimelineEvent.from_dict(json.load(f))
        except Exception as e:
            self.logger.error(f"Failed to retrieve event {event_id}: {e}")
        return None
    
    def query_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[EventType]] = None,
        source: Optional[str] = None,
        process_id: Optional[int] = None,
        file_path: Optional[str] = None,
        ip_address: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 1000
    ) -> List[TimelineEvent]:
        """Query timeline events based on criteria."""
        events = []
        count = 0
        
        try:
            for filename in os.listdir(self.base_dir):
                if not filename.endswith('.json'):
                    continue
                    
                try:
                    with open(os.path.join(self.base_dir, filename), 'r') as f:
                        event_data = json.load(f)
                        event = TimelineEvent.from_dict(event_data)
                        
                        # Apply filters
                        if start_time and event.timestamp < start_time:
                            continue
                        if end_time and event.timestamp > end_time:
                            continue
                        if event_types and event.event_type not in event_types:
                            continue
                        if source and event.source != source:
                            continue
                        if process_id is not None and (
                            not event.process or event.process.get('pid') != process_id
                        ):
                            continue
                        if file_path and (
                            not event.file or 
                            file_path.lower() not in event.file.get('path', '').lower()
                        ):
                            continue
                        if ip_address and (
                            not event.network or 
                            (event.network.get('source_ip') != ip_address and
                             event.network.get('dest_ip') != ip_address)
                        ):
                            continue
                        if tags and not all(tag in event.tags for tag in tags):
                            continue
                        
                        events.append(event)
                        count += 1
                        
                        if count >= limit:
                            break
                            
                except Exception as e:
                    self.logger.error(f"Error loading event from {filename}: {e}")
        except Exception as e:
            self.logger.error(f"Error listing event files: {e}")
        
        # Sort by timestamp
        events.sort(key=lambda x: x.timestamp)
        return events


def get_storage_backend(backend_type: str, config: Dict[str, Any]) -> TimelineStorage:
    """Factory function to get the appropriate storage backend."""
    if backend_type.lower() == 'elasticsearch':
        return ElasticsearchStorage(config)
    elif backend_type.lower() == 'filesystem':
        return FileSystemStorage(**config)
    else:
        raise ValueError(f"Unsupported storage backend: {backend_type}")
