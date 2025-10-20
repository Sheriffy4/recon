import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

try:
    from aiohttp import web, WSMsgType
    from aiohttp.web import Application, Request, Response, WebSocketResponse

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None
    Application = None
    Request = None
    Response = None
    WebSocketResponse = None


class MonitoringWebServer:
    """Веб-сервер для мониторинга системы обхода DPI."""

    def __init__(self, monitoring_system, port: int = 8080):
        if not AIOHTTP_AVAILABLE:
            raise ImportError(
                "aiohttp is required for web interface. Install with: pip install aiohttp"
            )
        self.monitoring_system = monitoring_system
        self.port = port
        self.app: Optional[Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.websockets: set = set()
        self.logger = logging.getLogger(__name__)

    def create_app(self) -> Application:
        """Создает веб-приложение."""
        app = web.Application()
        app.router.add_get("/api/status", self.api_status)
        app.router.add_get("/api/sites", self.api_sites)
        app.router.add_post("/api/sites", self.api_add_site)
        app.router.add_delete("/api/sites/{domain}", self.api_remove_site)
        app.router.add_post("/api/recovery/{domain}", self.api_trigger_recovery)
        app.router.add_get("/api/config", self.api_get_config)
        app.router.add_post("/api/config", self.api_set_config)
        app.router.add_get("/api/quic", self.api_quic)
        app.router.add_get("/api/health", self.handle_health)
        app.router.add_get("/ws", self.websocket_handler)
        app.router.add_get("/", self.index_handler)
        app.router.add_static("/", path=Path(__file__).parent / "static", name="static")
        return app

    async def index_handler(self, request: Request) -> Response:
        """Главная страница."""
        html_content = self.get_dashboard_html()
        return Response(text=html_content, content_type="text/html")

    async def api_status(self, request: Request) -> Response:
        """API: Общий статус системы."""
        report = self.monitoring_system.get_status_report()
        return web.json_response(report)

    async def api_quic(self, request: Request) -> Response:
        """API: QUIC-метрики из базы знаний."""
        data = {"domain_quic_scores": {}, "note": "PCAP-derived ServerHello/ClientHello ratio"}
        try:
            from core.knowledge.cdn_asn_db import CdnAsnKnowledgeBase
            kb = CdnAsnKnowledgeBase()
            data["domain_quic_scores"] = getattr(kb, "domain_quic_scores", {})
        except Exception as e:
            data["error"] = str(e)
        return web.json_response(data)

    async def handle_health(self, request: Request) -> Response:
        """API: Health status (alias for /api/status)."""
        return await self.api_status(request)

    async def api_sites(self, request: Request) -> Response:
        """API: Список всех сайтов."""
        sites = {}
        for site_key, health in self.monitoring_system.monitored_sites.items():
            sites[site_key] = health.to_dict()
        return web.json_response(sites)

    async def api_add_site(self, request: Request) -> Response:
        """API: Добавить сайт для мониторинга."""
        try:
            data = await request.json()
            domain = data.get("domain")
            port = data.get("port", 443)
            if not domain:
                return web.json_response({"error": "Domain is required"}, status=400)
            self.monitoring_system.add_site(domain, port)
            return web.json_response(
                {"success": True, "message": f"Added {domain}:{port}"}
            )
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def api_remove_site(self, request: Request) -> Response:
        """API: Удалить сайт из мониторинга."""
        try:
            domain = request.match_info["domain"]
            port = int(request.query.get("port", 443))
            self.monitoring_system.remove_site(domain, port)
            return web.json_response(
                {"success": True, "message": f"Removed {domain}:{port}"}
            )
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def api_trigger_recovery(self, request: Request) -> Response:
        """API: Запустить восстановление для сайта."""
        try:
            domain = request.match_info["domain"]
            port = int(request.query.get("port", 443))
            site_key = f"{domain}:{port}"
            if site_key not in self.monitoring_system.monitored_sites:
                return web.json_response({"error": "Site not found"}, status=404)
            health = self.monitoring_system.monitored_sites[site_key]
            await self.monitoring_system._trigger_recovery(health)
            return web.json_response(
                {"success": True, "message": f"Recovery triggered for {domain}:{port}"}
            )
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def api_get_config(self, request: Request) -> Response:
        """API: Получить конфигурацию."""
        from core.monitoring_system import asdict

        config_dict = asdict(self.monitoring_system.config)
        return web.json_response(config_dict)

    async def api_set_config(self, request: Request) -> Response:
        """API: Обновить конфигурацию."""
        try:
            data = await request.json()
            for key, value in data.items():
                if hasattr(self.monitoring_system.config, key):
                    setattr(self.monitoring_system.config, key, value)
            return web.json_response(
                {"success": True, "message": "Configuration updated"}
            )
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def websocket_handler(self, request: Request) -> WebSocketResponse:
        """WebSocket обработчик для real-time обновлений."""
        ws = WebSocketResponse()
        await ws.prepare(request)
        self.websockets.add(ws)
        self.logger.info("WebSocket client connected")
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        if data.get("type") == "ping":
                            await ws.send_str(json.dumps({"type": "pong"}))
                    except json.JSONDecodeError:
                        pass
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error(f"WebSocket error: {ws.exception()}")
        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")
        finally:
            self.websockets.discard(ws)
            self.logger.info("WebSocket client disconnected")
        return ws

    async def broadcast_update(self, data: dict):
        """Отправляет обновления всем подключенным WebSocket клиентам."""
        if not self.websockets:
            return
        message = json.dumps(data)
        disconnected = set()
        for ws in self.websockets:
            try:
                await ws.send_str(message)
            except Exception:
                disconnected.add(ws)
        self.websockets -= disconnected

    async def start(self):
        """Запускает веб-сервер."""
        self.app = self.create_app()
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "localhost", self.port)
        await self.site.start()
        self.logger.info(f"🌐 Web interface started at http://localhost:{self.port}")
        asyncio.create_task(self.update_broadcaster())

    async def stop(self):
        """Останавливает веб-сервер."""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        self.logger.info("🛑 Web interface stopped")

    async def update_broadcaster(self):
        """Периодически отправляет обновления статуса."""
        while True:
            try:
                if self.websockets:
                    report = self.monitoring_system.get_status_report()
                    await self.broadcast_update(
                        {"type": "status_update", "data": report}
                    )
                await asyncio.sleep(5)
            except Exception as e:
                self.logger.error(f"Error in update broadcaster: {e}")
                await asyncio.sleep(10)

    def get_dashboard_html(self) -> str:
        """Возвращает HTML код дашборда."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Monitoring</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 20px; background-color: #f0f2f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin-bottom: 16px; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1, h2 { margin: 0 0 16px 0; color: #333; }
        #health { white-space:pre; font-family:monospace; background: #fafafa; padding: 10px; border-radius: 4px; }
        #quic { white-space:pre; font-family:monospace; background: #fafafa; padding: 10px; border-radius: 4px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Recon Monitoring</h1>
            <div id='health'></div>
        </div>
        <div class="card">
            <h2>QUIC Metrics (PCAP-derived SH/CH ratio)</h2>
            <canvas id="quicChart" height="120"></canvas>
            <div id='quic'></div>
        </div>
    </div>
    <script>
        let quicChart = null;
        function renderChart(scores){
            const ctx = document.getElementById('quicChart').getContext('2d');
            const labels = Object.keys(scores);
            const data = labels.map(k => scores[k]);
            if (!labels.length) {
                if (quicChart) { quicChart.destroy(); quicChart = null; }
                return;
            }
            const cfg = {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'QUIC success score',
                        data: data,
                        backgroundColor: 'rgba(54, 162, 235, 0.5)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: True,
                    plugins: { legend: { display: True}, tooltip: { enabled: True} },
                    scales: { y: { beginAtZero: True, max: 1.0 } }
                }
            };
            if (quicChart) {
                quicChart.data.labels = labels;
                quicChart.data.datasets[0].data = data;
                quicChart.update();
            } else {
                quicChart = new Chart(ctx, cfg);
            }
        }
        async function load(){
            try {
                const h_res = await fetch('/api/health');
                const h = await h_res.json();
                document.getElementById('health').innerText = JSON.stringify(h, null, 2);
            } catch (e) { document.getElementById('health').innerText = 'Failed to load health data.'; }

            try {
                const q_res = await fetch('/api/quic');
                const q = await q_res.json();
                document.getElementById('quic').innerText = JSON.stringify(q, null, 2);
                if (q && q.domain_quic_scores) {
                    renderChart(q.domain_quic_scores);
                }
            } catch (e) { document.getElementById('quic').innerText = 'Failed to load QUIC data.'; }
        }
        load();
        setInterval(load, 5000);
    </script>
</body>
</html>
"""
