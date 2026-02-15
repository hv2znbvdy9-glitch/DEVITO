"""
AVA gRPC Prometheus Metrics
Umfassendes Monitoring für gRPC-Server
"""

import time
from typing import Optional, Callable
from functools import wraps

import grpc
from grpc import aio

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Info, Summary,
        CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

from ava.core.logging import logger


# ============================================================================
# METRICS DEFINITIONS
# ============================================================================

class GRPCMetrics:
    """Prometheus Metrics für gRPC-Server."""
    
    def __init__(self, registry: Optional['CollectorRegistry'] = None):
        """
        Initialisiere Metrics.
        
        Args:
            registry: Prometheus Registry (optional)
        """
        if not PROMETHEUS_AVAILABLE:
            logger.warning("⚠️  prometheus_client not installed, metrics disabled")
            self.enabled = False
            return
        
        self.enabled = True
        self.registry = registry
        
        # Server Info
        self.server_info = Info(
            'ava_grpc_server',
            'AVA gRPC Server Information',
            registry=registry
        )
        self.server_info.info({
            'version': '2.0.0',
            'python_version': __import__('sys').version.split()[0]
        })
        
        # Request Metrics
        self.requests_total = Counter(
            'ava_grpc_requests_total',
            'Total gRPC requests',
            ['method', 'status'],
            registry=registry
        )
        
        self.request_duration = Histogram(
            'ava_grpc_request_duration_seconds',
            'gRPC request duration in seconds',
            ['method'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            registry=registry
        )
        
        self.request_size = Histogram(
            'ava_grpc_request_size_bytes',
            'gRPC request size in bytes',
            ['method'],
            buckets=[100, 1000, 10000, 100000, 1000000, 10000000],
            registry=registry
        )
        
        self.response_size = Histogram(
            'ava_grpc_response_size_bytes',
            'gRPC response size in bytes',
            ['method'],
            buckets=[100, 1000, 10000, 100000, 1000000, 10000000],
            registry=registry
        )
        
        # Active Requests
        self.active_requests = Gauge(
            'ava_grpc_active_requests',
            'Currently active gRPC requests',
            ['method'],
            registry=registry
        )
        
        # Error Metrics
        self.errors_total = Counter(
            'ava_grpc_errors_total',
            'Total gRPC errors',
            ['method', 'code'],
            registry=registry
        )
        
        # Authentication Metrics
        self.auth_attempts_total = Counter(
            'ava_grpc_auth_attempts_total',
            'Total authentication attempts',
            ['status'],
            registry=registry
        )
        
        self.auth_failures_total = Counter(
            'ava_grpc_auth_failures_total',
            'Total authentication failures',
            ['reason'],
            registry=registry
        )
        
        # Connection Metrics
        self.connections_total = Counter(
            'ava_grpc_connections_total',
            'Total gRPC connections',
            registry=registry
        )
        
        self.active_connections = Gauge(
            'ava_grpc_active_connections',
            'Currently active gRPC connections',
            registry=registry
        )
        
        # Rate-Limiting Metrics
        self.rate_limit_hits = Counter(
            'ava_grpc_rate_limit_hits_total',
            'Total rate limit hits',
            ['user_id'],
            registry=registry
        )
        
        # Uptime
        self.uptime_seconds = Gauge(
            'ava_grpc_uptime_seconds',
            'Server uptime in seconds',
            registry=registry
        )
        
        # TLS Metrics
        self.tls_handshakes_total = Counter(
            'ava_grpc_tls_handshakes_total',
            'Total TLS handshakes',
            ['status'],
            registry=registry
        )
        
        self.tls_cert_expiry_seconds = Gauge(
            'ava_grpc_tls_cert_expiry_seconds',
            'Seconds until TLS certificate expires',
            registry=registry
        )
        
        # Message Size Summary
        self.message_size = Summary(
            'ava_grpc_message_size_bytes',
            'gRPC message sizes',
            ['type'],
            registry=registry
        )
        
        logger.info("✅ Prometheus metrics initialized")
    
    def record_request(
        self,
        method: str,
        status: str,
        duration: float,
        request_size: int = 0,
        response_size: int = 0
    ):
        """
        Request-Metrics aufzeichnen.
        
        Args:
            method: RPC-Methode
            status: Status-Code
            duration: Dauer in Sekunden
            request_size: Request-Größe in Bytes
            response_size: Response-Größe in Bytes
        """
        if not self.enabled:
            return
        
        self.requests_total.labels(method=method, status=status).inc()
        self.request_duration.labels(method=method).observe(duration)
        
        if request_size > 0:
            self.request_size.labels(method=method).observe(request_size)
            self.message_size.labels(type='request').observe(request_size)
        
        if response_size > 0:
            self.response_size.labels(method=method).observe(response_size)
            self.message_size.labels(type='response').observe(response_size)
    
    def record_error(self, method: str, code: str):
        """Error aufzeichnen."""
        if self.enabled:
            self.errors_total.labels(method=method, code=code).inc()
    
    def record_auth(self, success: bool, reason: str = ""):
        """Auth-Versuch aufzeichnen."""
        if not self.enabled:
            return
        
        status = "success" if success else "failure"
        self.auth_attempts_total.labels(status=status).inc()
        
        if not success:
            self.auth_failures_total.labels(reason=reason).inc()
    
    def record_rate_limit(self, user_id: str):
        """Rate-Limit-Hit aufzeichnen."""
        if self.enabled:
            self.rate_limit_hits.labels(user_id=user_id).inc()
    
    def inc_active_requests(self, method: str):
        """Aktive Requests erhöhen."""
        if self.enabled:
            self.active_requests.labels(method=method).inc()
    
    def dec_active_requests(self, method: str):
        """Aktive Requests verringern."""
        if self.enabled:
            self.active_requests.labels(method=method).dec()
    
    def inc_connections(self):
        """Connection-Counter erhöhen."""
        if self.enabled:
            self.connections_total.inc()
            self.active_connections.inc()
    
    def dec_connections(self):
        """Aktive Connections verringern."""
        if self.enabled:
            self.active_connections.dec()
    
    def update_uptime(self, uptime_seconds: float):
        """Uptime aktualisieren."""
        if self.enabled:
            self.uptime_seconds.set(uptime_seconds)
    
    def set_cert_expiry(self, seconds_until_expiry: int):
        """TLS-Cert-Expiry setzen."""
        if self.enabled:
            self.tls_cert_expiry_seconds.set(seconds_until_expiry)


# ============================================================================
# METRICS INTERCEPTOR
# ============================================================================

class MetricsInterceptor(aio.ServerInterceptor):
    """gRPC Interceptor für automatisches Metrics-Recording."""
    
    def __init__(self, metrics: GRPCMetrics):
        self.metrics = metrics
    
    async def intercept_service(self, continuation, handler_call_details):
        """Interceptor-Logik."""
        method = handler_call_details.method
        start_time = time.time()
        
        # Active Requests erhöhen
        self.metrics.inc_active_requests(method)
        
        try:
            # Handler ausführen
            handler = await continuation(handler_call_details)
            
            # Wrapper für Response-Tracking
            if handler and hasattr(handler, 'unary_unary'):
                original_handler = handler.unary_unary
                
                async def wrapped_handler(request, context):
                    try:
                        response = await original_handler(request, context)
                        
                        # Success-Metrics
                        duration = time.time() - start_time
                        self.metrics.record_request(
                            method=method,
                            status="OK",
                            duration=duration,
                            request_size=request.ByteSize() if hasattr(request, 'ByteSize') else 0,
                            response_size=response.ByteSize() if hasattr(response, 'ByteSize') else 0
                        )
                        
                        return response
                    
                    except grpc.RpcError as e:
                        # Error-Metrics
                        duration = time.time() - start_time
                        status_code = e.code().name if hasattr(e, 'code') else 'UNKNOWN'
                        
                        self.metrics.record_request(
                            method=method,
                            status=status_code,
                            duration=duration
                        )
                        self.metrics.record_error(method=method, code=status_code)
                        
                        raise
                    
                    finally:
                        self.metrics.dec_active_requests(method)
                
                # Handler ersetzen
                handler.unary_unary = wrapped_handler
            
            return handler
        
        except Exception as e:
            # Unerwarteter Fehler
            duration = time.time() - start_time
            self.metrics.record_request(
                method=method,
                status="INTERNAL",
                duration=duration
            )
            self.metrics.record_error(method=method, code="INTERNAL")
            self.metrics.dec_active_requests(method)
            
            raise


# ============================================================================
# METRICS HTTP ENDPOINT
# ============================================================================

class MetricsHTTPHandler:
    """HTTP-Endpoint für Prometheus Scraping."""
    
    def __init__(self, metrics: GRPCMetrics):
        self.metrics = metrics
    
    async def handle(self, request):
        """
        Handle HTTP-Request für /metrics.
        
        Args:
            request: aiohttp Request
        
        Returns:
            aiohttp Response
        """
        if not PROMETHEUS_AVAILABLE:
            return {
                "status": 503,
                "body": "Prometheus client not available"
            }
        
        # Metrics generieren
        metrics_output = generate_latest(self.metrics.registry)
        
        return {
            "status": 200,
            "body": metrics_output,
            "content_type": CONTENT_TYPE_LATEST
        }


# ============================================================================
# DECORATOR für Method-Metrics
# ============================================================================

def track_metrics(metrics: GRPCMetrics):
    """
    Decorator für automatisches Metrics-Tracking.
    
    Usage:
        @track_metrics(metrics)
        async def MyMethod(self, request, context):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(self, request, context):
            method_name = f"/ava.v1.AVAService/{func.__name__}"
            start_time = time.time()
            
            metrics.inc_active_requests(method_name)
            
            try:
                response = await func(self, request, context)
                
                # Success
                duration = time.time() - start_time
                metrics.record_request(
                    method=method_name,
                    status="OK",
                    duration=duration,
                    request_size=request.ByteSize() if hasattr(request, 'ByteSize') else 0,
                    response_size=response.ByteSize() if hasattr(response, 'ByteSize') else 0
                )
                
                return response
            
            except grpc.RpcError as e:
                # gRPC Error
                duration = time.time() - start_time
                status_code = e.code().name if hasattr(e, 'code') else 'UNKNOWN'
                
                metrics.record_request(
                    method=method_name,
                    status=status_code,
                    duration=duration
                )
                metrics.record_error(method=method_name, code=status_code)
                
                raise
            
            finally:
                metrics.dec_active_requests(method_name)
        
        return wrapper
    
    return decorator


# Globale Metrics-Instanz
_global_metrics: Optional[GRPCMetrics] = None


def get_metrics() -> GRPCMetrics:
    """
    Globale Metrics-Instanz abrufen.
    
    Returns:
        GRPCMetrics-Instanz
    """
    global _global_metrics
    
    if _global_metrics is None:
        _global_metrics = GRPCMetrics()
    
    return _global_metrics
