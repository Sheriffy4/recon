"""
Example: Using the Metrics Export Endpoint

This example demonstrates how to start the metrics endpoint server
and export metrics in various formats.
"""

import time
import requests
from core.bypass.attacks.telemetry import (
    initialize_telemetry,
    get_telemetry_system,
    start_metrics_endpoint,
    stop_metrics_endpoint
)


def main():
    """Run metrics endpoint example."""
    print("=" * 60)
    print("Metrics Export Endpoint Example")
    print("=" * 60)
    print()
    
    # Initialize telemetry system
    print("1. Initializing telemetry system...")
    initialize_telemetry()
    telemetry = get_telemetry_system()
    print("   ✅ Telemetry system initialized")
    print()
    
    # Start metrics endpoint server
    print("2. Starting metrics endpoint server...")
    server = start_metrics_endpoint(host='127.0.0.1', port=9090)
    print(f"   ✅ Server started at {server.get_url()}")
    print()
    
    # Simulate some attack executions
    print("3. Simulating attack executions...")
    attacks = [
        ('payload_base64', True, 45.2),
        ('payload_padding', True, 32.1),
        ('http_host_header', False, 67.8),
        ('tls_extension_reorder', True, 89.3),
        ('payload_base64', True, 43.5),
        ('payload_padding', False, 35.7),
    ]
    
    for attack_name, success, exec_time in attacks:
        telemetry.metrics_collector.record_execution(
            attack_name=attack_name,
            success=success,
            execution_time_ms=exec_time,
            segments_generated=5,
            payload_size=1024,
            is_fallback=False,
            is_error=False
        )
        print(f"   - Recorded: {attack_name} ({'success' if success else 'failed'}, {exec_time}ms)")
    
    print()
    
    # Wait a moment for metrics to be available
    time.sleep(0.5)
    
    # Demonstrate different endpoints
    print("4. Accessing metrics endpoints:")
    print()
    
    # Prometheus metrics
    print("   a) Prometheus metrics endpoint:")
    print(f"      URL: {server.get_url()}/metrics")
    try:
        response = requests.get(f"{server.get_url()}/metrics")
        if response.status_code == 200:
            print(f"      ✅ Status: {response.status_code}")
            print(f"      Content-Type: {response.headers['Content-Type']}")
            lines = response.text.split('\n')[:10]
            print("      Sample output:")
            for line in lines:
                if line.strip():
                    print(f"        {line}")
        else:
            print(f"      ❌ Status: {response.status_code}")
    except Exception as e:
        print(f"      ❌ Error: {e}")
    print()
    
    # JSON metrics
    print("   b) JSON metrics endpoint:")
    print(f"      URL: {server.get_url()}/metrics/json")
    try:
        response = requests.get(f"{server.get_url()}/metrics/json")
        if response.status_code == 200:
            print(f"      ✅ Status: {response.status_code}")
            print(f"      Content-Type: {response.headers['Content-Type']}")
            data = response.json()
            print(f"      Total attacks: {len(data['attack_metrics'])}")
            print(f"      Global executions: {data['global_stats']['total_executions']}")
            print(f"      Global success rate: {data['global_stats']['global_success_rate']:.2%}")
        else:
            print(f"      ❌ Status: {response.status_code}")
    except Exception as e:
        print(f"      ❌ Error: {e}")
    print()
    
    # Filtered metrics
    print("   c) Filtered metrics endpoint (only payload attacks):")
    print(f"      URL: {server.get_url()}/metrics/filtered?attack=payload_base64&attack=payload_padding&format=json")
    try:
        response = requests.get(
            f"{server.get_url()}/metrics/filtered",
            params={
                'attack': ['payload_base64', 'payload_padding'],
                'format': 'json'
            }
        )
        if response.status_code == 200:
            print(f"      ✅ Status: {response.status_code}")
            data = response.json()
            print(f"      Filtered attacks: {list(data['attack_metrics'].keys())}")
            for attack_name, metrics in data['attack_metrics'].items():
                print(f"        - {attack_name}: {metrics['total_executions']} executions, "
                      f"{metrics['success_rate']:.2%} success rate")
        else:
            print(f"      ❌ Status: {response.status_code}")
    except Exception as e:
        print(f"      ❌ Error: {e}")
    print()
    
    # Health check
    print("   d) Health check endpoint:")
    print(f"      URL: {server.get_url()}/health")
    try:
        response = requests.get(f"{server.get_url()}/health")
        if response.status_code == 200:
            print(f"      ✅ Status: {response.status_code}")
            data = response.json()
            print(f"      Health status: {data['status']}")
            print(f"      Total attacks: {data['total_attacks']}")
            print(f"      Total executions: {data['total_executions']}")
        else:
            print(f"      ❌ Status: {response.status_code}")
    except Exception as e:
        print(f"      ❌ Error: {e}")
    print()
    
    # Aggregated metrics
    print("   e) Aggregated metrics endpoint:")
    print(f"      URL: {server.get_url()}/metrics/aggregated?format=json")
    try:
        response = requests.get(
            f"{server.get_url()}/metrics/aggregated",
            params={'format': 'json'}
        )
        if response.status_code == 200:
            print(f"      ✅ Status: {response.status_code}")
            data = response.json()
            print(f"      Timestamp: {data['timestamp']}")
            print(f"      Total attacks: {len(data['attack_metrics'])}")
        else:
            print(f"      ❌ Status: {response.status_code}")
    except Exception as e:
        print(f"      ❌ Error: {e}")
    print()
    
    # Keep server running for a bit
    print("5. Server is running. You can access the endpoints in your browser:")
    print(f"   - Prometheus: {server.get_url()}/metrics")
    print(f"   - JSON: {server.get_url()}/metrics/json")
    print(f"   - Health: {server.get_url()}/health")
    print()
    print("   Press Ctrl+C to stop the server...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n")
        print("6. Stopping metrics endpoint server...")
        stop_metrics_endpoint()
        print("   ✅ Server stopped")
        print()
        print("=" * 60)
        print("Example completed!")
        print("=" * 60)


if __name__ == '__main__':
    main()
