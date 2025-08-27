"""REST API for exposing SIEM metrics."""
from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse, Response
from typing import Dict, Any, List, Optional
import json
import logging

from utils.metrics import get_metrics_snapshot, init_metrics, get_metrics_collector, MetricsCollector
from models.database import Database

logger = logging.getLogger('siem.api.metrics')

# Create FastAPI app
app = FastAPI(
    title="SIEM Metrics API",
    description="REST API for SIEM metrics collection and monitoring",
    version="1.0.0"
)

# Create API router
router = APIRouter(
    prefix="/api/v1/metrics",
    tags=["metrics"],
    responses={404: {"description": "Not found"}},
)

# Global metrics collector
_metrics_collector: Optional[MetricsCollector] = None

def get_metrics() -> MetricsCollector:
    """Get or initialize the metrics collector."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = get_metrics_collector()
    return _metrics_collector

@router.get("/", response_model=Dict[str, Any])
async def get_all_metrics(metrics: MetricsCollector = Depends(get_metrics)) -> Dict[str, Any]:
    """Get a snapshot of all metrics."""
    try:
        return metrics.get_metrics_snapshot()
    except Exception as e:
        logger.error(f"Error getting metrics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{metric_name}", response_model=Dict[str, Any])
async def get_metric(
    metric_name: str,
    metrics: MetricsCollector = Depends(get_metrics)
) -> Dict[str, Any]:
    """Get a specific metric by name."""
    try:
        metric = metrics.get_metric(metric_name)
        if metric is None:
            raise HTTPException(status_code=404, detail="Metric not found")
        
        response = {
            'name': metric.name,
            'value': metric.value,
            'timestamp': metric.timestamp.isoformat(),
            'type': metric.__class__.__name__.lower(),
            'tags': metric.tags
        }
        
        if isinstance(metric, Histogram):
            response['summary'] = metric.get_summary()
            
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting metric {metric_name}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/prometheus/metrics", response_class=Response)
async def get_prometheus_metrics(metrics: MetricsCollector = Depends(get_metrics)) -> Response:
    """Get metrics in Prometheus exposition format."""
    try:
        snapshot = metrics.get_metrics_snapshot()
        prometheus_lines = []
        
        for name, metric_data in snapshot['metrics'].items():
            metric_type = metric_data['type']
            tags = metric_data.get('tags', {})
            
            # Convert tags to Prometheus label string
            if tags:
                label_str = ",".join([f'{k}="{v}"' for k, v in tags.items()])
                label_str = f"{{{label_str}}}" if label_str else ""
            else:
                label_str = ""
            
            if metric_type == 'histogram':
                # For histograms, we'll create multiple time series
                summary = metric_data.get('summary', {})
                for stat, value in summary.items():
                    if stat in ['count', 'sum']:
                        prometheus_lines.append(
                            f"{name}_{stat}{label_str} {value}"
                        )
                    else:
                        prometheus_lines.append(
                            f"{name}_{stat}{label_str} {value}"
                        )
            else:
                # For counters and gauges
                value = metric_data.get('value', 0)
                prometheus_lines.append(
                    f"{name}{label_str} {value}"
                )
        
        # Add a timestamp to the response
        prometheus_lines.append(f"# HELP siem_metrics_timestamp Timestamp when metrics were collected")
        prometheus_lines.append(f"# TYPE siem_metrics_timestamp gauge")
        prometheus_lines.append(f"siem_metrics_timestamp {time.time()}")
        
        return Response(
            content="\n".join(prometheus_lines) + "\n",
            media_type="text/plain; version=0.0.4"
        )
    except Exception as e:
        logger.error(f"Error generating Prometheus metrics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error generating metrics")

@router.post("/collect")
async def trigger_metrics_collection(metrics: MetricsCollector = Depends(get_metrics)) -> Dict[str, str]:
    """Trigger an immediate metrics collection."""
    try:
        metrics.collect_metrics()
        return {"status": "success", "message": "Metrics collection triggered"}
    except Exception as e:
        logger.error(f"Error triggering metrics collection: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error triggering metrics collection")

def setup_metrics_api(app, db: Optional[Database] = None) -> None:
    """Set up the metrics API endpoints.
    
    Args:
        app: FastAPI application instance
        db: Optional database connection for metrics collection
    """
    # Initialize metrics if not already done
    init_metrics(db)
    
    # Include the router
    app.include_router(router)
    
    # Add startup event to initialize metrics
    @app.on_event("startup")
    async def startup_event():
        # Ensure metrics collector is running
        get_metrics_collector().start()
    
    # Add shutdown event to clean up
    @app.on_event("shutdown")
    async def shutdown_event():
        get_metrics_collector().stop()
    
    logger.info("Metrics API endpoints registered")
    return app
