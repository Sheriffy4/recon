# recon/web/monitoring_server.py - Веб-интерфейс для мониторинга

import asyncio
import json
import logging
from datetime import datetime
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
    
    def __init__(self, monitoring_system, hybrid_engine, port: int = 8080):
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for web interface. Install with: pip install aiohttp")
        
        self.monitoring_system = monitoring_system
        self.hybrid_engine = hybrid_engine
        self.port = port
        self.app: Optional[Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.websockets: set = set()
        self.logger = logging.getLogger(__name__)
    
    def create_app(self) -> Application:
        """Создает веб-приложение."""
        app = web.Application()
        
        # API маршруты
        app.router.add_get('/api/status', self.api_status)
        app.router.add_get('/api/sites', self.api_sites)
        app.router.add_post('/api/sites', self.api_add_site)
        app.router.add_delete('/api/sites/{domain}', self.api_remove_site)
        app.router.add_post('/api/recovery/{domain}', self.api_trigger_recovery)
        app.router.add_get('/api/config', self.api_get_config)
        app.router.add_post('/api/config', self.api_set_config)
        
        # Service control routes
        app.router.add_get('/api/service/status', self.api_service_status)
        app.router.add_post('/api/service/start', self.api_service_start)
        app.router.add_post('/api/service/stop', self.api_service_stop)

        # Strategy search routes
        app.router.add_post('/api/search/start', self.api_search_start)

        # WebSocket для real-time обновлений
        app.router.add_get('/ws', self.websocket_handler)
        
        # Статические файлы
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
            site_key = f"{domain}:{port}"
            
            if site_key not in self.monitoring_system.monitored_sites:
                return web.json_response({'error': 'Site not found'}, status=404)
            
            health = self.monitoring_system.monitored_sites[site_key]
            await self.monitoring_system._trigger_recovery(health)
            
            return web.json_response({'success': True, 'message': f'Recovery triggered for {domain}:{port}'})
        
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)
    
    async def api_get_config(self, request: Request) -> Response:
        """API: Получить конфигурацию."""
        from ..core.monitoring_system import asdict
        config_dict = asdict(self.monitoring_system.config)
        return web.json_response(config_dict)
    
    async def api_set_config(self, request: Request) -> Response:
        """API: Обновить конфигурацию."""
        try:
            data = await request.json()
            
            # Обновляем конфигурацию
            for key, value in data.items():
                if hasattr(self.monitoring_system.config, key):
                    setattr(self.monitoring_system.config, key, value)
            
            return web.json_response({'success': True, 'message': 'Configuration updated'})
        
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)

    async def api_service_status(self, request: Request) -> Response:
        """API: Get bypass service status."""
        # Placeholder
        is_running = hasattr(self, 'bypass_process') and self.bypass_process is not None
        return web.json_response({'status': 'running' if is_running else 'stopped'})

    async def api_service_start(self, request: Request) -> Response:
        """API: Start the bypass service."""
        # Placeholder
        self.logger.info("Received request to start bypass service.")
        # In a real implementation, this would start recon_service.py
        # For now, we'll just simulate it.
        self.bypass_process = "dummy_process"
        return web.json_response({'success': True, 'message': 'Bypass service started.'})

    async def api_service_stop(self, request: Request) -> Response:
        """API: Stop the bypass service."""
        # Placeholder
        self.logger.info("Received request to stop bypass service.")
        self.bypass_process = None
        return web.json_response({'success': True, 'message': 'Bypass service stopped.'})

    async def api_search_start(self, request: Request) -> Response:
        """API: Start a new strategy search."""
        # Placeholder
        data = await request.json()
        domain = data.get('domain')
        self.logger.info(f"Received request to start strategy search for {domain}.")
        # This would trigger a long-running task.
        # We can use asyncio.create_task to run it in the background.
        asyncio.create_task(self._run_strategy_search(domain))
        return web.json_response({'success': True, 'message': f'Strategy search started for {domain}.'})

    async def _run_strategy_search(self, domain: str):
        """Placeholder for the actual strategy search logic."""
        self.logger.info(f"Starting background search for {domain}...")
        await self.broadcast_update({'type': 'search_status', 'data': {'status': 'running', 'domain': domain, 'progress': 0}})
        await asyncio.sleep(5) # Simulate work
        await self.broadcast_update({'type': 'search_status', 'data': {'status': 'running', 'domain': domain, 'progress': 50}})
        await asyncio.sleep(5) # Simulate more work
        await self.broadcast_update({'type': 'search_status', 'data': {'status': 'complete', 'domain': domain, 'progress': 100, 'best_strategy': '--dpi-desync=fake'}})
        self.logger.info(f"Search for {domain} complete.")
    
    async def websocket_handler(self, request: Request) -> WebSocketResponse:
        """WebSocket обработчик для real-time обновлений."""
        ws = WebSocketResponse()
        await ws.prepare(request)
        
        self.websockets.add(ws)
        self.logger.info("WebSocket client connected")
        
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    # Обрабатываем команды от клиента
                    try:
                        data = json.loads(msg.data)
                        if data.get('type') == 'ping':
                            await ws.send_str(json.dumps({'type': 'pong'}))
                    except json.JSONDecodeError:
                        pass
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error(f'WebSocket error: {ws.exception()}')
        
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
        
        # Удаляем отключенные соединения
        self.websockets -= disconnected
    
    async def start(self):
        """Запускает веб-сервер."""
        self.app = self.create_app()
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        
        self.site = web.TCPSite(self.runner, 'localhost', self.port)
        await self.site.start()
        
        self.logger.info(f"🌐 Web interface started at http://localhost:{self.port}")
        
        # Запускаем задачу для периодической отправки обновлений
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
                    await self.broadcast_update({
                        'type': 'status_update',
                        'data': report
                    })
                
                await asyncio.sleep(5)  # Обновления каждые 5 секунд
            
            except Exception as e:
                self.logger.error(f"Error in update broadcaster: {e}")
                await asyncio.sleep(10)
    
    def get_dashboard_html(self) -> str:
        """Возвращает HTML код дашборда."""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DPI Bypass Monitor</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px;
        }
        .header {
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }
        .header h1 {
            color: #4a5568;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        .status-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            transition: transform 0.3s ease;
        }
        .card:hover { transform: translateY(-5px); }
        .card h3 { color: #4a5568; margin-bottom: 10px; }
        .card .value { font-size: 2em; font-weight: bold; color: #2d3748; }
        .sites-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        .site-card {
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }
        .site-status {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 10px;
        }
        .status-ok { background: #48bb78; }
        .status-error { background: #f56565; }
        .site-details { font-size: 0.9em; color: #666; }
        .controls {
            margin-top: 15px;
        }
        .btn {
            background: #4299e1;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            margin-right: 10px;
            transition: background 0.3s ease;
        }
        .btn:hover { background: #3182ce; }
        .btn-danger { background: #f56565; }
        .btn-danger:hover { background: #e53e3e; }
        .add-site {
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        .form-group input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
        }
        .connection-status { font-size: 0.8em; margin-top: 5px; }
        .online { color: #48bb78; }
        .offline { color: #f56565; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ DPI Bypass Monitor</h1>
            <p>Real-time monitoring and auto-recovery system</p>
            <div class="connection-status" id="connectionStatus">
                <span class="offline">⚫ Connecting...</span>
            </div>
        </div>
        
        <div class="status-cards">
            <div class="card">
                <h3>📊 Total Sites</h3>
                <div class="value" id="totalSites">0</div>
            </div>
            <div class="card">
                <h3>✅ Accessible</h3>
                <div class="value" id="accessibleSites">0</div>
            </div>
            <div class="card">
                <h3>🔧 With Bypass</h3>
                <div class="value" id="bypassSites">0</div>
            </div>
            <div class="card">
                <h3>⚡ Avg Response</h3>
                <div class="value" id="avgResponse">0ms</div>
            </div>
            <div class="card">
                <h3>⚙️ Bypass Service Control</h3>
                <div id="serviceStatus" style="margin-top: 10px; font-weight: bold;">Status: Unknown</div>
                <div class="controls">
                    <button class="btn" onclick="startService()">▶️ Start Service</button>
                    <button class="btn btn-danger" onclick="stopService()">⏹️ Stop Service</button>
                </div>
            </div>
            <div class="card">
                <h3>🔍 New Strategy Search</h3>
                <div class="form-group" style="text-align: left;">
                    <label for="searchDomain">Domain:</label>
                    <input type="text" id="searchDomain" placeholder="example.com" />
                </div>
                <div class="controls">
                    <button class="btn" onclick="startSearch()">🚀 Start Search</button>
                </div>
                <div id="searchStatus" style="margin-top: 10px;"></div>
            </div>
        </div>
        
        <div class="add-site">
            <h3>➕ Add Site to Monitor</h3>
            <div style="display: flex; gap: 15px; align-items: end;">
                <div class="form-group" style="flex: 1;">
                    <label for="newDomain">Domain:</label>
                    <input type="text" id="newDomain" placeholder="example.com" />
                </div>
                <div class="form-group">
                    <label for="newPort">Port:</label>
                    <input type="number" id="newPort" value="443" style="width: 80px;" />
                </div>
                <button class="btn" onclick="addSite()">Add Site</button>
            </div>
        </div>
        
        <div class="sites-grid" id="sitesGrid">
            <!-- Sites will be populated by JavaScript -->
        </div>
    </div>

    <script>
        let ws = null;
        let reconnectInterval = null;
        
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
            
            ws.onopen = function() {
                console.log('WebSocket connected');
                document.getElementById('connectionStatus').innerHTML = '<span class="online">🟢 Connected</span>';
                if (reconnectInterval) {
                    clearInterval(reconnectInterval);
                    reconnectInterval = null;
                }
                loadInitialData();
                setInterval(updateServiceStatus, 5000); // Update service status every 5 seconds
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                if (data.type === 'status_update') {
                    updateDashboard(data.data);
                } else if (data.type === 'search_status') {
                    const searchData = data.data;
                    const statusEl = document.getElementById('searchStatus');
                    if (searchData.status === 'running') {
                        statusEl.textContent = `Searching ${searchData.domain}: ${searchData.progress}%`;
                    } else if (searchData.status === 'complete') {
                        statusEl.innerHTML = `Search for ${searchData.domain} complete! <br>Best strategy: <strong>${searchData.best_strategy}</strong>`;
                    }
                }
            };
            
            ws.onclose = function() {
                console.log('WebSocket disconnected');
                document.getElementById('connectionStatus').innerHTML = '<span class="offline">🔴 Disconnected</span>';
                
                if (!reconnectInterval) {
                    reconnectInterval = setInterval(connectWebSocket, 5000);
                }
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
            };
        }
        
        async function loadInitialData() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                updateDashboard(data);
                updateServiceStatus();
            } catch (error) {
                console.error('Failed to load initial data:', error);
            }
        }
        
        function updateDashboard(data) {
            document.getElementById('totalSites').textContent = data.total_sites;
            document.getElementById('accessibleSites').textContent = data.accessible_sites;
            document.getElementById('bypassSites').textContent = data.sites_with_bypass;
            document.getElementById('avgResponse').textContent = Math.round(data.average_response_time) + 'ms';
            
            updateSitesGrid(data.sites);
        }
        
        function updateSitesGrid(sites) {
            const grid = document.getElementById('sitesGrid');
            grid.innerHTML = '';
            
            for (const [siteKey, site] of Object.entries(sites)) {
                const card = document.createElement('div');
                card.className = 'site-card';
                
                const statusClass = site.is_accessible ? 'status-ok' : 'status-error';
                const statusText = site.is_accessible ? 'Online' : 'Offline';
                const bypassText = site.bypass_active ? `🔧 ${site.current_strategy || 'Active'}` : '⚪ No bypass';
                
                card.innerHTML = `
                    <div class="site-status">
                        <div class="status-indicator ${statusClass}"></div>
                        <strong>${site.domain}:${site.port}</strong>
                    </div>
                    <div class="site-details">
                        <div>Status: ${statusText}</div>
                        <div>Response: ${Math.round(site.response_time_ms)}ms</div>
                        <div>IP: ${site.ip}</div>
                        <div>Bypass: ${bypassText}</div>
                        <div>Failures: ${site.consecutive_failures}</div>
                        <div>Last check: ${new Date(site.last_check).toLocaleTimeString()}</div>
                    </div>
                    <div class="controls">
                        <button class="btn" onclick="triggerRecovery('${site.domain}', ${site.port})">🔄 Recover</button>
                        <button class="btn btn-danger" onclick="removeSite('${site.domain}', ${site.port})">🗑️ Remove</button>
                    </div>
                `;
                
                grid.appendChild(card);
            }
        }
        
        async function addSite() {
            const domain = document.getElementById('newDomain').value.trim();
            const port = parseInt(document.getElementById('newPort').value);
            
            if (!domain) {
                alert('Please enter a domain');
                return;
            }
            
            try {
                const response = await fetch('/api/sites', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain, port })
                });
                
                const result = await response.json();
                if (result.success) {
                    document.getElementById('newDomain').value = '';
                    document.getElementById('newPort').value = '443';
                } else {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Failed to add site: ' + error.message);
            }
        }
        
        async function removeSite(domain, port) {
            if (!confirm(`Remove ${domain}:${port} from monitoring?`)) return;
            
            try {
                const response = await fetch(`/api/sites/${domain}?port=${port}`, {
                    method: 'DELETE'
                });
                
                const result = await response.json();
                if (!result.success) {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Failed to remove site: ' + error.message);
            }
        }
        
        async function triggerRecovery(domain, port) {
            try {
                const response = await fetch(`/api/recovery/${domain}?port=${port}`, {
                    method: 'POST'
                });
                
                const result = await response.json();
                if (result.success) {
                    alert(`Recovery triggered for ${domain}:${port}`);
                } else {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Failed to trigger recovery: ' + error.message);
            }
        }
        
        async function startService() {
            try {
                await fetch('/api/service/start', { method: 'POST' });
                alert('Start command sent to bypass service.');
                updateServiceStatus();
            } catch (error) {
                alert('Failed to start service: ' + error.message);
            }
        }

        async function stopService() {
            try {
                await fetch('/api/service/stop', { method: 'POST' });
                alert('Stop command sent to bypass service.');
                updateServiceStatus();
            } catch (error) {
                alert('Failed to stop service: ' + error.message);
            }
        }

        async function updateServiceStatus() {
            try {
                const response = await fetch('/api/service/status');
                const data = await response.json();
                const statusEl = document.getElementById('serviceStatus');
                if (data.status === 'running') {
                    statusEl.innerHTML = 'Status: <span class="online">Running</span>';
                } else {
                    statusEl.innerHTML = 'Status: <span class="offline">Stopped</span>';
                }
            } catch (error) {
                document.getElementById('serviceStatus').innerHTML = 'Status: <span class="offline">Error</span>';
            }
        }

        async function startSearch() {
            const domain = document.getElementById('searchDomain').value.trim();
            if (!domain) {
                alert('Please enter a domain for the search.');
                return;
            }

            try {
                await fetch('/api/search/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain })
                });
                document.getElementById('searchStatus').textContent = `Search started for ${domain}...`;
            } catch (error) {
                alert('Failed to start search: ' + error.message);
            }
        }

        // Initialize
        connectWebSocket();
    </script>
</body>
</html>
        '''