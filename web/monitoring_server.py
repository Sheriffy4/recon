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

    def __init__(self, monitoring_system, port: int=8080):
        if not AIOHTTP_AVAILABLE:
            raise ImportError('aiohttp is required for web interface. Install with: pip install aiohttp')
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
        app.router.add_get('/api/status', self.api_status)
        app.router.add_get('/api/sites', self.api_sites)
        app.router.add_post('/api/sites', self.api_add_site)
        app.router.add_delete('/api/sites/{domain}', self.api_remove_site)
        app.router.add_post('/api/recovery/{domain}', self.api_trigger_recovery)
        app.router.add_get('/api/config', self.api_get_config)
        app.router.add_post('/api/config', self.api_set_config)
        app.router.add_get('/ws', self.websocket_handler)
        app.router.add_get('/', self.index_handler)
        app.router.add_static('/', path=Path(__file__).parent / 'static', name='static')
        return app

    async def index_handler(self, request: Request) -> Response:
        """Главная страница."""
        html_content = self.get_dashboard_html()
        return Response(text=html_content, content_type='text/html')

    async def api_status(self, request: Request) -> Response:
        """API: Общий статус системы."""
        report = self.monitoring_system.get_status_report()
        return web.json_response(report)

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
            domain = data.get('domain')
            port = data.get('port', 443)
            if not domain:
                return web.json_response({'error': 'Domain is required'}, status=400)
            self.monitoring_system.add_site(domain, port)
            return web.json_response({'success': True, 'message': f'Added {domain}:{port}'})
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)

    async def api_remove_site(self, request: Request) -> Response:
        """API: Удалить сайт из мониторинга."""
        try:
            domain = request.match_info['domain']
            port = int(request.query.get('port', 443))
            self.monitoring_system.remove_site(domain, port)
            return web.json_response({'success': True, 'message': f'Removed {domain}:{port}'})
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)

    async def api_trigger_recovery(self, request: Request) -> Response:
        """API: Запустить восстановление для сайта."""
        try:
            domain = request.match_info['domain']
            port = int(request.query.get('port', 443))
            site_key = f'{domain}:{port}'
            if site_key not in self.monitoring_system.monitored_sites:
                return web.json_response({'error': 'Site not found'}, status=404)
            health = self.monitoring_system.monitored_sites[site_key]
            await self.monitoring_system._trigger_recovery(health)
            return web.json_response({'success': True, 'message': f'Recovery triggered for {domain}:{port}'})
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)

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
            return web.json_response({'success': True, 'message': 'Configuration updated'})
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)

    async def websocket_handler(self, request: Request) -> WebSocketResponse:
        """WebSocket обработчик для real-time обновлений."""
        ws = WebSocketResponse()
        await ws.prepare(request)
        self.websockets.add(ws)
        self.logger.info('WebSocket client connected')
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        if data.get('type') == 'ping':
                            await ws.send_str(json.dumps({'type': 'pong'}))
                    except json.JSONDecodeError:
                        pass
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error(f'WebSocket error: {ws.exception()}')
        except Exception as e:
            self.logger.error(f'WebSocket error: {e}')
        finally:
            self.websockets.discard(ws)
            self.logger.info('WebSocket client disconnected')
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
        self.site = web.TCPSite(self.runner, 'localhost', self.port)
        await self.site.start()
        self.logger.info(f'🌐 Web interface started at http://localhost:{self.port}')
        asyncio.create_task(self.update_broadcaster())

    async def stop(self):
        """Останавливает веб-сервер."""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        self.logger.info('🛑 Web interface stopped')

    async def update_broadcaster(self):
        """Периодически отправляет обновления статуса."""
        while True:
            try:
                if self.websockets:
                    report = self.monitoring_system.get_status_report()
                    await self.broadcast_update({'type': 'status_update', 'data': report})
                await asyncio.sleep(5)
            except Exception as e:
                self.logger.error(f'Error in update broadcaster: {e}')
                await asyncio.sleep(10)

    def get_dashboard_html(self) -> str:
        """Возвращает HTML код дашборда."""
        return '\n<!DOCTYPE html>\n<html lang="en">\n<head>\n    <meta charset="UTF-8">\n    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n    <title>DPI Bypass Monitor</title>\n    <style>\n        * { margin: 0; padding: 0; box-sizing: border-box; }\n        body { \n            font-family: \'Segoe UI\', Tahoma, Geneva, Verdana, sans-serif;\n            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n            min-height: 100vh;\n            color: #333;\n        }\n        .container { \n            max-width: 1200px; \n            margin: 0 auto; \n            padding: 20px;\n        }\n        .header {\n            background: rgba(255,255,255,0.95);\n            border-radius: 15px;\n            padding: 20px;\n            margin-bottom: 20px;\n            box-shadow: 0 8px 32px rgba(0,0,0,0.1);\n            backdrop-filter: blur(10px);\n        }\n        .header h1 {\n            color: #4a5568;\n            margin-bottom: 10px;\n            font-size: 2.5em;\n        }\n        .status-cards {\n            display: grid;\n            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));\n            gap: 20px;\n            margin-bottom: 30px;\n        }\n        .card {\n            background: rgba(255,255,255,0.95);\n            border-radius: 15px;\n            padding: 20px;\n            box-shadow: 0 8px 32px rgba(0,0,0,0.1);\n            backdrop-filter: blur(10px);\n            transition: transform 0.3s ease;\n        }\n        .card:hover { transform: translateY(-5px); }\n        .card h3 { color: #4a5568; margin-bottom: 10px; }\n        .card .value { font-size: 2em; font-weight: bold; color: #2d3748; }\n        .sites-grid {\n            display: grid;\n            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));\n            gap: 20px;\n        }\n        .site-card {\n            background: rgba(255,255,255,0.95);\n            border-radius: 15px;\n            padding: 20px;\n            box-shadow: 0 8px 32px rgba(0,0,0,0.1);\n            backdrop-filter: blur(10px);\n        }\n        .site-status {\n            display: flex;\n            align-items: center;\n            margin-bottom: 10px;\n        }\n        .status-indicator {\n            width: 12px;\n            height: 12px;\n            border-radius: 50%;\n            margin-right: 10px;\n        }\n        .status-ok { background: #48bb78; }\n        .status-error { background: #f56565; }\n        .site-details { font-size: 0.9em; color: #666; }\n        .controls {\n            margin-top: 15px;\n        }\n        .btn {\n            background: #4299e1;\n            color: white;\n            border: none;\n            padding: 8px 16px;\n            border-radius: 8px;\n            cursor: pointer;\n            margin-right: 10px;\n            transition: background 0.3s ease;\n        }\n        .btn:hover { background: #3182ce; }\n        .btn-danger { background: #f56565; }\n        .btn-danger:hover { background: #e53e3e; }\n        .add-site {\n            background: rgba(255,255,255,0.95);\n            border-radius: 15px;\n            padding: 20px;\n            margin-bottom: 20px;\n            box-shadow: 0 8px 32px rgba(0,0,0,0.1);\n        }\n        .form-group {\n            margin-bottom: 15px;\n        }\n        .form-group label {\n            display: block;\n            margin-bottom: 5px;\n            font-weight: bold;\n        }\n        .form-group input {\n            width: 100%;\n            padding: 10px;\n            border: 1px solid #ddd;\n            border-radius: 8px;\n            font-size: 16px;\n        }\n        .connection-status { font-size: 0.8em; margin-top: 5px; }\n        .online { color: #48bb78; }\n        .offline { color: #f56565; }\n    </style>\n</head>\n<body>\n    <div class="container">\n        <div class="header">\n            <h1>🛡️ DPI Bypass Monitor</h1>\n            <p>Real-time monitoring and auto-recovery system</p>\n            <div class="connection-status" id="connectionStatus">\n                <span class="offline">⚫ Connecting...</span>\n            </div>\n        </div>\n        \n        <div class="status-cards">\n            <div class="card">\n                <h3>📊 Total Sites</h3>\n                <div class="value" id="totalSites">0</div>\n            </div>\n            <div class="card">\n                <h3>✅ Accessible</h3>\n                <div class="value" id="accessibleSites">0</div>\n            </div>\n            <div class="card">\n                <h3>🔧 With Bypass</h3>\n                <div class="value" id="bypassSites">0</div>\n            </div>\n            <div class="card">\n                <h3>⚡ Avg Response</h3>\n                <div class="value" id="avgResponse">0ms</div>\n            </div>\n        </div>\n        \n        <div class="add-site">\n            <h3>➕ Add Site to Monitor</h3>\n            <div style="display: flex; gap: 15px; align-items: end;">\n                <div class="form-group" style="flex: 1;">\n                    <label for="newDomain">Domain:</label>\n                    <input type="text" id="newDomain" placeholder="example.com" />\n                </div>\n                <div class="form-group">\n                    <label for="newPort">Port:</label>\n                    <input type="number" id="newPort" value="443" style="width: 80px;" />\n                </div>\n                <button class="btn" onclick="addSite()">Add Site</button>\n            </div>\n        </div>\n        \n        <div class="sites-grid" id="sitesGrid">\n            <!-- Sites will be populated by JavaScript -->\n        </div>\n    </div>\n\n    <script>\n        let ws = null;\n        let reconnectInterval = null;\n        \n        function connectWebSocket() {\n            const protocol = window.location.protocol === \'https:\' ? \'wss:\' : \'ws:\';\n            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);\n            \n            ws.onopen = function() {\n                console.log(\'WebSocket connected\');\n                document.getElementById(\'connectionStatus\').innerHTML = \'<span class="online">🟢 Connected</span>\';\n                if (reconnectInterval) {\n                    clearInterval(reconnectInterval);\n                    reconnectInterval = null;\n                }\n                loadInitialData();\n            };\n            \n            ws.onmessage = function(event) {\n                const data = JSON.parse(event.data);\n                if (data.type === \'status_update\') {\n                    updateDashboard(data.data);\n                }\n            };\n            \n            ws.onclose = function() {\n                console.log(\'WebSocket disconnected\');\n                document.getElementById(\'connectionStatus\').innerHTML = \'<span class="offline">🔴 Disconnected</span>\';\n                \n                if (!reconnectInterval) {\n                    reconnectInterval = setInterval(connectWebSocket, 5000);\n                }\n            };\n            \n            ws.onerror = function(error) {\n                console.error(\'WebSocket error:\', error);\n            };\n        }\n        \n        async function loadInitialData() {\n            try {\n                const response = await fetch(\'/api/status\');\n                const data = await response.json();\n                updateDashboard(data);\n            } catch (error) {\n                console.error(\'Failed to load initial data:\', error);\n            }\n        }\n        \n        function updateDashboard(data) {\n            document.getElementById(\'totalSites\').textContent = data.total_sites;\n            document.getElementById(\'accessibleSites\').textContent = data.accessible_sites;\n            document.getElementById(\'bypassSites\').textContent = data.sites_with_bypass;\n            document.getElementById(\'avgResponse\').textContent = Math.round(data.average_response_time) + \'ms\';\n            \n            updateSitesGrid(data.sites);\n        }\n        \n        function updateSitesGrid(sites) {\n            const grid = document.getElementById(\'sitesGrid\');\n            grid.innerHTML = \'\';\n            \n            for (const [siteKey, site] of Object.entries(sites)) {\n                const card = document.createElement(\'div\');\n                card.className = \'site-card\';\n                \n                const statusClass = site.is_accessible ? \'status-ok\' : \'status-error\';\n                const statusText = site.is_accessible ? \'Online\' : \'Offline\';\n                const bypassText = site.bypass_active ? `🔧 ${site.current_strategy || \'Active\'}` : \'⚪ No bypass\';\n                \n                card.innerHTML = `\n                    <div class="site-status">\n                        <div class="status-indicator ${statusClass}"></div>\n                        <strong>${site.domain}:${site.port}</strong>\n                    </div>\n                    <div class="site-details">\n                        <div>Status: ${statusText}</div>\n                        <div>Response: ${Math.round(site.response_time_ms)}ms</div>\n                        <div>IP: ${site.ip}</div>\n                        <div>Bypass: ${bypassText}</div>\n                        <div>Failures: ${site.consecutive_failures}</div>\n                        <div>Last check: ${new Date(site.last_check).toLocaleTimeString()}</div>\n                    </div>\n                    <div class="controls">\n                        <button class="btn" onclick="triggerRecovery(\'${site.domain}\', ${site.port})">🔄 Recover</button>\n                        <button class="btn btn-danger" onclick="removeSite(\'${site.domain}\', ${site.port})">🗑️ Remove</button>\n                    </div>\n                `;\n                \n                grid.appendChild(card);\n            }\n        }\n        \n        async function addSite() {\n            const domain = document.getElementById(\'newDomain\').value.trim();\n            const port = parseInt(document.getElementById(\'newPort\').value);\n            \n            if (!domain) {\n                alert(\'Please enter a domain\');\n                return;\n            }\n            \n            try {\n                const response = await fetch(\'/api/sites\', {\n                    method: \'POST\',\n                    headers: { \'Content-Type\': \'application/json\' },\n                    body: JSON.stringify({ domain, port })\n                });\n                \n                const result = await response.json();\n                if (result.success) {\n                    document.getElementById(\'newDomain\').value = \'\';\n                    document.getElementById(\'newPort\').value = \'443\';\n                } else {\n                    alert(\'Error: \' + result.error);\n                }\n            } catch (error) {\n                alert(\'Failed to add site: \' + error.message);\n            }\n        }\n        \n        async function removeSite(domain, port) {\n            if (!confirm(`Remove ${domain}:${port} from monitoring?`)) return;\n            \n            try {\n                const response = await fetch(`/api/sites/${domain}?port=${port}`, {\n                    method: \'DELETE\'\n                });\n                \n                const result = await response.json();\n                if (!result.success) {\n                    alert(\'Error: \' + result.error);\n                }\n            } catch (error) {\n                alert(\'Failed to remove site: \' + error.message);\n            }\n        }\n        \n        async function triggerRecovery(domain, port) {\n            try {\n                const response = await fetch(`/api/recovery/${domain}?port=${port}`, {\n                    method: \'POST\'\n                });\n                \n                const result = await response.json();\n                if (result.success) {\n                    alert(`Recovery triggered for ${domain}:${port}`);\n                } else {\n                    alert(\'Error: \' + result.error);\n                }\n            } catch (error) {\n                alert(\'Failed to trigger recovery: \' + error.message);\n            }\n        }\n        \n        // Initialize\n        connectWebSocket();\n    </script>\n</body>\n</html>\n        '