"""
Metrics export HTTP endpoint.

Provides HTTP endpoints for exporting metrics in various formats
including Prometheus-compatible format and JSON.
"""

import logging
from typing import Optional, Dict, Any, List
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from threading import Thread
import json

from .metrics_exporter import (
    PrometheusExporter,
    JSONExporter,
    MetricsAggregator,
    MetricsFilter
)
from .telemetry_system import get_telemetry_system

logger = logging.getLogger(__name__)


class MetricsEndpointHandler(BaseHTTPRequestHandler):
    """HTTP handler for metrics endpoint."""
    
    def __init__(self, *args, **kwargs):
        """Initialize handler."""
        self.prometheus_exporter = PrometheusExporter()
        self.json_exporter = JSONExporter(pretty=True)
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests."""
        try:
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            query_params = parse_qs(parsed_path.query)
            
            if path == '/metrics':
                self._handle_prometheus_metrics(query_params)
            elif path == '/metrics/json':
                self._handle_json_metrics(query_params)
            elif path == '/metrics/aggregated':
                self._handle_aggregated_metrics(query_params)
            elif path == '/metrics/filtered':
                self._handle_filtered_metrics(query_params)
            elif path == '/health':
                self._handle_health_check()
            else:
                self._send_error(404, "Not Found")
        
        except Exception as e:
            logger.error(f"Error handling request: {e}", exc_info=True)
            self._send_error(500, f"Internal Server Error: {str(e)}")
    
    def _handle_prometheus_metrics(self, query_params: Dict[str, List[str]]):
        """
        Handle Prometheus metrics endpoint.
        
        Args:
            query_params: Query parameters from request
        """
        try:
            # Get telemetry system
            telemetry = get_telemetry_system()
            
            # Get metrics snapshot
            snapshot = telemetry.metrics_collector.get_snapshot()
            
            # Apply filters if specified
            if 'attack' in query_params:
                attack_names = query_params['attack']
                filter_obj = MetricsFilter(attack_names=attack_names)
                snapshot = filter_obj.filter(snapshot)
            
            # Export to Prometheus format
            metrics_text = self.prometheus_exporter.export(snapshot)
            
            # Send response
            self._send_response(
                200,
                metrics_text,
                self.prometheus_exporter.get_content_type()
            )
        
        except Exception as e:
            logger.error(f"Error exporting Prometheus metrics: {e}", exc_info=True)
            self._send_error(500, f"Error exporting metrics: {str(e)}")
    
    def _handle_json_metrics(self, query_params: Dict[str, List[str]]):
        """
        Handle JSON metrics endpoint.
        
        Args:
            query_params: Query parameters from request
        """
        try:
            # Get telemetry system
            telemetry = get_telemetry_system()
            
            # Get metrics snapshot
            snapshot = telemetry.metrics_collector.get_snapshot()
            
            # Apply filters if specified
            if 'attack' in query_params:
                attack_names = query_params['attack']
                filter_obj = MetricsFilter(attack_names=attack_names)
                snapshot = filter_obj.filter(snapshot)
            
            # Export to JSON format
            metrics_json = self.json_exporter.export(snapshot)
            
            # Send response
            self._send_response(
                200,
                metrics_json,
                self.json_exporter.get_content_type()
            )
        
        except Exception as e:
            logger.error(f"Error exporting JSON metrics: {e}", exc_info=True)
            self._send_error(500, f"Error exporting metrics: {str(e)}")
    
    def _handle_aggregated_metrics(self, query_params: Dict[str, List[str]]):
        """
        Handle aggregated metrics endpoint.
        
        Aggregates metrics over multiple snapshots if available.
        
        Args:
            query_params: Query parameters from request
        """
        try:
            # Get telemetry system
            telemetry = get_telemetry_system()
            
            # For now, just return current snapshot
            # In future, could aggregate historical snapshots
            snapshot = telemetry.metrics_collector.get_snapshot()
            
            # Determine output format
            format_param = query_params.get('format', ['json'])[0]
            
            if format_param == 'prometheus':
                metrics_text = self.prometheus_exporter.export(snapshot)
                content_type = self.prometheus_exporter.get_content_type()
            else:
                metrics_text = self.json_exporter.export(snapshot)
                content_type = self.json_exporter.get_content_type()
            
            # Send response
            self._send_response(200, metrics_text, content_type)
        
        except Exception as e:
            logger.error(f"Error exporting aggregated metrics: {e}", exc_info=True)
            self._send_error(500, f"Error exporting metrics: {str(e)}")
    
    def _handle_filtered_metrics(self, query_params: Dict[str, List[str]]):
        """
        Handle filtered metrics endpoint.
        
        Supports filtering by:
        - attack: Filter by attack name(s)
        - min_executions: Minimum number of executions
        - min_success_rate: Minimum success rate
        
        Args:
            query_params: Query parameters from request
        """
        try:
            # Get telemetry system
            telemetry = get_telemetry_system()
            
            # Get metrics snapshot
            snapshot = telemetry.metrics_collector.get_snapshot()
            
            # Build filter
            attack_names = query_params.get('attack', None)
            min_executions = None
            min_success_rate = None
            
            if 'min_executions' in query_params:
                try:
                    min_executions = int(query_params['min_executions'][0])
                except (ValueError, IndexError):
                    pass
            
            if 'min_success_rate' in query_params:
                try:
                    min_success_rate = float(query_params['min_success_rate'][0])
                except (ValueError, IndexError):
                    pass
            
            # Apply filter
            filter_obj = MetricsFilter(
                attack_names=attack_names,
                min_executions=min_executions,
                min_success_rate=min_success_rate
            )
            filtered_snapshot = filter_obj.filter(snapshot)
            
            # Determine output format
            format_param = query_params.get('format', ['json'])[0]
            
            if format_param == 'prometheus':
                metrics_text = self.prometheus_exporter.export(filtered_snapshot)
                content_type = self.prometheus_exporter.get_content_type()
            else:
                metrics_text = self.json_exporter.export(filtered_snapshot)
                content_type = self.json_exporter.get_content_type()
            
            # Send response
            self._send_response(200, metrics_text, content_type)
        
        except Exception as e:
            logger.error(f"Error exporting filtered metrics: {e}", exc_info=True)
            self._send_error(500, f"Error exporting metrics: {str(e)}")
    
    def _handle_health_check(self):
        """Handle health check endpoint."""
        try:
            # Get telemetry system
            telemetry = get_telemetry_system()
            
            # Get basic stats
            snapshot = telemetry.metrics_collector.get_snapshot()
            
            health_data = {
                'status': 'healthy',
                'timestamp': snapshot.timestamp.isoformat(),
                'total_attacks': len(snapshot.attack_metrics),
                'total_executions': snapshot.global_stats.get('total_executions', 0)
            }
            
            # Send response
            self._send_response(
                200,
                json.dumps(health_data, indent=2),
                'application/json'
            )
        
        except Exception as e:
            logger.error(f"Error in health check: {e}", exc_info=True)
            self._send_error(500, f"Health check failed: {str(e)}")
    
    def _send_response(self, status_code: int, content: str, content_type: str):
        """
        Send HTTP response.
        
        Args:
            status_code: HTTP status code
            content: Response content
            content_type: Content type header
        """
        self.send_response(status_code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))
    
    def _send_error(self, status_code: int, message: str):
        """
        Send error response.
        
        Args:
            status_code: HTTP status code
            message: Error message
        """
        error_data = {
            'error': message,
            'status_code': status_code
        }
        content = json.dumps(error_data, indent=2)
        
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.info(f"{self.address_string()} - {format % args}")


class MetricsEndpointServer:
    """
    HTTP server for metrics endpoint.
    
    Provides a simple HTTP server that exposes metrics in various formats.
    Can be run in a background thread.
    """
    
    def __init__(self, host: str = '127.0.0.1', port: int = 9090):
        """
        Initialize metrics endpoint server.
        
        Args:
            host: Host to bind to
            port: Port to bind to
        """
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[Thread] = None
        self._running = False
    
    def start(self):
        """Start the metrics endpoint server."""
        if self._running:
            logger.warning("Metrics endpoint server already running")
            return
        
        try:
            # Create server
            self.server = HTTPServer((self.host, self.port), MetricsEndpointHandler)
            
            # Start server in background thread
            self.thread = Thread(target=self._run_server, daemon=True)
            self.thread.start()
            
            self._running = True
            logger.info(f"✅ Metrics endpoint server started on http://{self.host}:{self.port}")
            logger.info(f"   - Prometheus metrics: http://{self.host}:{self.port}/metrics")
            logger.info(f"   - JSON metrics: http://{self.host}:{self.port}/metrics/json")
            logger.info(f"   - Filtered metrics: http://{self.host}:{self.port}/metrics/filtered")
            logger.info(f"   - Health check: http://{self.host}:{self.port}/health")
        
        except Exception as e:
            logger.error(f"Failed to start metrics endpoint server: {e}", exc_info=True)
            raise
    
    def stop(self):
        """Stop the metrics endpoint server."""
        if not self._running:
            logger.warning("Metrics endpoint server not running")
            return
        
        try:
            if self.server:
                self.server.shutdown()
                self.server.server_close()
            
            if self.thread:
                self.thread.join(timeout=5.0)
            
            self._running = False
            logger.info("✅ Metrics endpoint server stopped")
        
        except Exception as e:
            logger.error(f"Error stopping metrics endpoint server: {e}", exc_info=True)
    
    def _run_server(self):
        """Run the server (called in background thread)."""
        try:
            if self.server:
                self.server.serve_forever()
        except Exception as e:
            logger.error(f"Error in metrics endpoint server: {e}", exc_info=True)
            self._running = False
    
    def is_running(self) -> bool:
        """
        Check if server is running.
        
        Returns:
            True if server is running
        """
        return self._running
    
    def get_url(self) -> str:
        """
        Get the base URL of the server.
        
        Returns:
            Base URL
        """
        return f"http://{self.host}:{self.port}"


# Global server instance
_metrics_server: Optional[MetricsEndpointServer] = None


def start_metrics_endpoint(host: str = '127.0.0.1', port: int = 9090) -> MetricsEndpointServer:
    """
    Start the metrics endpoint server.
    
    Args:
        host: Host to bind to
        port: Port to bind to
    
    Returns:
        Metrics endpoint server instance
    """
    global _metrics_server
    
    if _metrics_server and _metrics_server.is_running():
        logger.warning("Metrics endpoint server already running")
        return _metrics_server
    
    _metrics_server = MetricsEndpointServer(host=host, port=port)
    _metrics_server.start()
    
    return _metrics_server


def stop_metrics_endpoint():
    """Stop the metrics endpoint server."""
    global _metrics_server
    
    if _metrics_server:
        _metrics_server.stop()
        _metrics_server = None


def get_metrics_endpoint() -> Optional[MetricsEndpointServer]:
    """
    Get the global metrics endpoint server instance.
    
    Returns:
        Metrics endpoint server or None if not started
    """
    return _metrics_server
