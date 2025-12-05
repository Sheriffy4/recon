import asyncio
import logging
from web.monitoring_server import MonitoringWebServer


# Mock objects for dependencies
class MockMonitoringSystem:
    def get_status_report(self):
        return {
            "total_sites": 0,
            "accessible_sites": 0,
            "sites_with_bypass": 0,
            "average_response_time": 0,
            "sites": {},
        }


class MockHybridEngine:
    pass


async def main():
    logging.basicConfig(level=logging.INFO)

    # Instantiate mock dependencies
    monitoring_system = MockMonitoringSystem()
    hybrid_engine = MockHybridEngine()

    # Instantiate and start the web server
    server = MonitoringWebServer(monitoring_system, host='0.0.0.0', port=5000)
    await server.start()

    print("Web server is running on http://0.0.0.0:5000. Press Ctrl+C to stop.")

    try:
        # Keep the server running
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        await server.stop()


if __name__ == "__main__":
    # Add project root to path to allow imports
    import sys

    if "." not in sys.path:
        sys.path.insert(0, ".")
    asyncio.run(main())
