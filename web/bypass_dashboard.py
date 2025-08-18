#!/usr/bin/env python3
"""
Web dashboard for bypass engine management.
Provides HTML interface for managing pools, strategies, and attacks.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

try:
    from aiohttp import web
    from aiohttp.web import Application, Request, Response
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None

from web.bypass_api import BypassEngineAPI


class BypassDashboard:
    """Web dashboard for bypass engine management."""
    
    def __init__(self, bypass_api: BypassEngineAPI):
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for web dashboard. Install with: pip install aiohttp")
        
        self.bypass_api = bypass_api
        self.logger = logging.getLogger(__name__)
    
    def setup_routes(self, app: Application):
        """Setup dashboard routes on the application."""
        
        # Main dashboard pages
        app.router.add_get('/bypass', self.dashboard_home)
        app.router.add_get('/bypass/pools', self.pools_page)
        app.router.add_get('/bypass/attacks', self.attacks_page)
        app.router.add_get('/bypass/testing', self.testing_page)
        app.router.add_get('/bypass/config', self.config_page)
        
        # Pool management pages
        app.router.add_get('/bypass/pools/{pool_id}', self.pool_detail_page)
        app.router.add_get('/bypass/pools/{pool_id}/edit', self.pool_edit_page)
        
        # Attack management pages
        app.router.add_get('/bypass/attacks/{attack_id}', self.attack_detail_page)
    
    async def dashboard_home(self, request: Request) -> Response:
        """Main bypass engine dashboard."""
        html = self._get_dashboard_html()
        return Response(text=html, content_type='text/html')
    
    async def pools_page(self, request: Request) -> Response:
        """Strategy pools management page."""
        html = self._get_pools_html()
        return Response(text=html, content_type='text/html')
    
    async def attacks_page(self, request: Request) -> Response:
        """Attack registry management page."""
        html = self._get_attacks_html()
        return Response(text=html, content_type='text/html')
    
    async def testing_page(self, request: Request) -> Response:
        """Real-time testing interface."""
        html = self._get_testing_html()
        return Response(text=html, content_type='text/html')
    
    async def config_page(self, request: Request) -> Response:
        """Configuration import/export page."""
        html = self._get_config_html()
        return Response(text=html, content_type='text/html')
    
    async def pool_detail_page(self, request: Request) -> Response:
        """Detailed pool information page."""
        pool_id = request.match_info['pool_id']
        html = self._get_pool_detail_html(pool_id)
        return Response(text=html, content_type='text/html')
    
    async def pool_edit_page(self, request: Request) -> Response:
        """Pool editing page."""
        pool_id = request.match_info['pool_id']
        html = self._get_pool_edit_html(pool_id)
        return Response(text=html, content_type='text/html')
    
    async def attack_detail_page(self, request: Request) -> Response:
        """Detailed attack information page."""
        attack_id = request.match_info['attack_id']
        html = self._get_attack_detail_html(attack_id)
        return Response(text=html, content_type='text/html')
    
    def _get_base_html(self, title: str, content: str, extra_css: str = "", extra_js: str = "") -> str:
        """Base HTML template."""
        return f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Bypass Engine Management</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        
        /* Navigation */
        .nav {{
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 15px 20px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            display: flex;
            align-items: center;
            gap: 20px;
        }}
        .nav h1 {{ color: #4a5568; font-size: 1.8em; }}
        .nav-links {{ display: flex; gap: 15px; margin-left: auto; }}
        .nav-link {{
            color: #4a5568;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 8px;
            transition: background 0.3s ease;
        }}
        .nav-link:hover {{ background: rgba(66, 153, 225, 0.1); }}
        .nav-link.active {{ background: #4299e1; color: white; }}
        
        /* Cards */
        .card {{
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            transition: transform 0.3s ease;
        }}
        .card:hover {{ transform: translateY(-2px); }}
        .card h2 {{ color: #4a5568; margin-bottom: 15px; }}
        .card h3 {{ color: #4a5568; margin-bottom: 10px; }}
        
        /* Grid layouts */
        .grid {{ display: grid; gap: 20px; }}
        .grid-2 {{ grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); }}
        .grid-3 {{ grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }}
        .grid-4 {{ grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); }}
        
        /* Buttons */
        .btn {{
            background: #4299e1;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: background 0.3s ease;
            font-size: 14px;
        }}
        .btn:hover {{ background: #3182ce; }}
        .btn-sm {{ padding: 6px 12px; font-size: 12px; }}
        .btn-success {{ background: #48bb78; }}
        .btn-success:hover {{ background: #38a169; }}
        .btn-danger {{ background: #f56565; }}
        .btn-danger:hover {{ background: #e53e3e; }}
        .btn-warning {{ background: #ed8936; }}
        .btn-warning:hover {{ background: #dd6b20; }}
        
        /* Forms */
        .form-group {{ margin-bottom: 15px; }}
        .form-group label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
        .form-group input, .form-group select, .form-group textarea {{
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
        }}
        .form-group textarea {{ resize: vertical; min-height: 80px; }}
        .form-row {{ display: flex; gap: 15px; }}
        .form-row .form-group {{ flex: 1; }}
        
        /* Status indicators */
        .status {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .status-enabled {{ background: #c6f6d5; color: #22543d; }}
        .status-disabled {{ background: #fed7d7; color: #742a2a; }}
        .status-testing {{ background: #fef5e7; color: #744210; }}
        .status-success {{ background: #c6f6d5; color: #22543d; }}
        .status-failed {{ background: #fed7d7; color: #742a2a; }}
        
        /* Tables */
        .table {{ width: 100%; border-collapse: collapse; }}
        .table th, .table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        .table th {{ background: #f7fafc; font-weight: bold; }}
        .table tr:hover {{ background: #f7fafc; }}
        
        /* Connection status */
        .connection-status {{ font-size: 0.8em; }}
        .online {{ color: #48bb78; }}
        .offline {{ color: #f56565; }}
        
        /* Loading spinner */
        .spinner {{
            border: 2px solid #f3f3f3;
            border-top: 2px solid #4299e1;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-right: 10px;
        }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        
        /* Modal */
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }}
        .modal-content {{
            background-color: white;
            margin: 5% auto;
            padding: 20px;
            border-radius: 15px;
            width: 80%;
            max-width: 600px;
            max-height: 80vh;
            overflow-y: auto;
        }}
        .close {{
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }}
        .close:hover {{ color: black; }}
        
        {extra_css}
    </style>
</head>
<body>
    <div class="container">
        <nav class="nav">
            <h1>🛡️ Bypass Engine</h1>
            <div class="nav-links">
                <a href="/bypass" class="nav-link">Dashboard</a>
                <a href="/bypass/pools" class="nav-link">Pools</a>
                <a href="/bypass/attacks" class="nav-link">Attacks</a>
                <a href="/bypass/testing" class="nav-link">Testing</a>
                <a href="/bypass/config" class="nav-link">Config</a>
            </div>
            <div class="connection-status" id="connectionStatus">
                <span class="offline">⚫ Connecting...</span>
            </div>
        </nav>
        
        {content}
    </div>
    
    <script>
        // WebSocket connection for real-time updates
        let ws = null;
        let reconnectInterval = null;
        
        function connectWebSocket() {{
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${{protocol}}//${{window.location.host}}/api/bypass/ws`);
            
            ws.onopen = function() {{
                console.log('Bypass WebSocket connected');
                document.getElementById('connectionStatus').innerHTML = '<span class="online">🟢 Connected</span>';
                if (reconnectInterval) {{
                    clearInterval(reconnectInterval);
                    reconnectInterval = null;
                }}
            }};
            
            ws.onmessage = function(event) {{
                const data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            }};
            
            ws.onclose = function() {{
                console.log('Bypass WebSocket disconnected');
                document.getElementById('connectionStatus').innerHTML = '<span class="offline">🔴 Disconnected</span>';
                
                if (!reconnectInterval) {{
                    reconnectInterval = setInterval(connectWebSocket, 5000);
                }}
            }};
            
            ws.onerror = function(error) {{
                console.error('Bypass WebSocket error:', error);
            }};
        }}
        
        function handleWebSocketMessage(data) {{
            // Handle different message types
            switch(data.type) {{
                case 'pool_created':
                case 'pool_updated':
                case 'pool_deleted':
                    if (typeof updatePoolsList === 'function') updatePoolsList();
                    break;
                case 'attack_tested':
                case 'attack_enabled':
                case 'attack_disabled':
                    if (typeof updateAttacksList === 'function') updateAttacksList();
                    break;
                case 'strategy_test_completed':
                    if (typeof handleTestCompleted === 'function') handleTestCompleted(data);
                    break;
            }}
        }}
        
        // Utility functions
        async function apiCall(url, options = {{}}) {{
            try {{
                const response = await fetch(url, {{
                    headers: {{
                        'Content-Type': 'application/json',
                        ...options.headers
                    }},
                    ...options
                }});
                
                const data = await response.json();
                
                if (!data.success) {{
                    throw new Error(data.error || 'API call failed');
                }}
                
                return data;
            }} catch (error) {{
                console.error('API call failed:', error);
                alert('Error: ' + error.message);
                throw error;
            }}
        }}
        
        function showModal(modalId) {{
            document.getElementById(modalId).style.display = 'block';
        }}
        
        function hideModal(modalId) {{
            document.getElementById(modalId).style.display = 'none';
        }}
        
        function formatDate(dateString) {{
            return new Date(dateString).toLocaleString();
        }}
        
        function formatDuration(ms) {{
            if (ms < 1000) return ms.toFixed(0) + 'ms';
            return (ms / 1000).toFixed(1) + 's';
        }}
        
        // Initialize
        connectWebSocket();
        
        {extra_js}
    </script>
</body>
</html>
        '''
    
    def _get_dashboard_html(self) -> str:
        """Main dashboard HTML."""
        content = '''
        <div class="grid grid-4">
            <div class="card">
                <h3>📊 Pools</h3>
                <div class="value" id="totalPools">Loading...</div>
                <p>Strategy pools configured</p>
            </div>
            <div class="card">
                <h3>⚔️ Attacks</h3>
                <div class="value" id="totalAttacks">Loading...</div>
                <p>Available attacks</p>
            </div>
            <div class="card">
                <h3>🧪 Tests</h3>
                <div class="value" id="activeTests">Loading...</div>
                <p>Active test sessions</p>
            </div>
            <div class="card">
                <h3>🔗 Connections</h3>
                <div class="value" id="wsConnections">Loading...</div>
                <p>WebSocket connections</p>
            </div>
        </div>
        
        <div class="grid grid-2">
            <div class="card">
                <h2>📈 Recent Activity</h2>
                <div id="recentActivity">Loading...</div>
            </div>
            <div class="card">
                <h2>🎯 Quick Actions</h2>
                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <a href="/bypass/pools" class="btn">Manage Pools</a>
                    <a href="/bypass/attacks" class="btn">View Attacks</a>
                    <a href="/bypass/testing" class="btn btn-success">Run Tests</a>
                    <a href="/bypass/config" class="btn btn-warning">Import/Export</a>
                </div>
            </div>
        </div>
        '''
        
        extra_js = '''
        async function loadDashboardData() {
            try {
                const stats = await apiCall('/api/bypass/stats');
                
                document.getElementById('totalPools').textContent = stats.statistics.pools.total_pools;
                document.getElementById('totalAttacks').textContent = stats.statistics.attacks.total_attacks;
                document.getElementById('activeTests').textContent = stats.statistics.active_tests;
                document.getElementById('wsConnections').textContent = stats.statistics.websocket_connections;
                
                // Load recent activity (placeholder)
                document.getElementById('recentActivity').innerHTML = '<p>No recent activity</p>';
                
            } catch (error) {
                console.error('Failed to load dashboard data:', error);
            }
        }
        
        // Load data on page load
        loadDashboardData();
        
        // Refresh data every 30 seconds
        setInterval(loadDashboardData, 30000);
        '''
        
        return self._get_base_html("Dashboard", content, extra_js=extra_js)
    
    def _get_pools_html(self) -> str:
        """Pools management HTML."""
        content = '''
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>Strategy Pools</h2>
                <button class="btn btn-success" onclick="showModal('createPoolModal')">Create Pool</button>
            </div>
            
            <div id="poolsList">Loading pools...</div>
        </div>
        
        <!-- Create Pool Modal -->
        <div id="createPoolModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="hideModal('createPoolModal')">&times;</span>
                <h2>Create New Pool</h2>
                <form id="createPoolForm">
                    <div class="form-group">
                        <label for="poolName">Pool Name:</label>
                        <input type="text" id="poolName" required>
                    </div>
                    <div class="form-group">
                        <label for="poolDescription">Description:</label>
                        <textarea id="poolDescription"></textarea>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="poolPriority">Priority:</label>
                            <select id="poolPriority">
                                <option value="LOW">Low</option>
                                <option value="NORMAL" selected>Normal</option>
                                <option value="HIGH">High</option>
                                <option value="CRITICAL">Critical</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="strategyAttacks">Attacks (comma-separated):</label>
                            <input type="text" id="strategyAttacks" placeholder="tcp_fragmentation,http_manipulation">
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="initialDomains">Initial Domains (one per line):</label>
                        <textarea id="initialDomains" placeholder="example.com&#10;google.com"></textarea>
                    </div>
                    <button type="submit" class="btn btn-success">Create Pool</button>
                </form>
            </div>
        </div>
        '''
        
        extra_js = '''
        async function updatePoolsList() {
            try {
                const response = await apiCall('/api/bypass/pools');
                const pools = response.pools;
                
                let html = '';
                if (pools.length === 0) {
                    html = '<p>No pools configured. Create your first pool to get started.</p>';
                } else {
                    html = '<div class="grid grid-3">';
                    pools.forEach(pool => {
                        html += `
                            <div class="card">
                                <h3>${pool.name}</h3>
                                <p>${pool.description || 'No description'}</p>
                                <div style="margin: 10px 0;">
                                    <span class="status status-${pool.priority.toLowerCase()}">${pool.priority}</span>
                                </div>
                                <div style="font-size: 0.9em; color: #666; margin: 10px 0;">
                                    <div>Domains: ${pool.domain_count}</div>
                                    <div>Subdomains: ${pool.subdomain_count}</div>
                                    <div>Port overrides: ${pool.port_count}</div>
                                    <div>Created: ${formatDate(pool.created_at)}</div>
                                </div>
                                <div style="display: flex; gap: 5px; margin-top: 15px;">
                                    <a href="/bypass/pools/${pool.id}" class="btn btn-sm">View</a>
                                    <a href="/bypass/pools/${pool.id}/edit" class="btn btn-sm btn-warning">Edit</a>
                                    <button class="btn btn-sm btn-danger" onclick="deletePool('${pool.id}', '${pool.name}')">Delete</button>
                                </div>
                            </div>
                        `;
                    });
                    html += '</div>';
                }
                
                document.getElementById('poolsList').innerHTML = html;
            } catch (error) {
                document.getElementById('poolsList').innerHTML = '<p>Failed to load pools</p>';
            }
        }
        
        async function createPool() {
            const formData = {
                name: document.getElementById('poolName').value,
                description: document.getElementById('poolDescription').value,
                priority: document.getElementById('poolPriority').value,
                strategy: {
                    attacks: document.getElementById('strategyAttacks').value.split(',').map(s => s.trim()).filter(s => s),
                    parameters: {}
                },
                domains: document.getElementById('initialDomains').value.split('\\n').map(s => s.trim()).filter(s => s)
            };
            
            try {
                await apiCall('/api/bypass/pools', {
                    method: 'POST',
                    body: JSON.stringify(formData)
                });
                
                hideModal('createPoolModal');
                document.getElementById('createPoolForm').reset();
                updatePoolsList();
            } catch (error) {
                // Error already handled by apiCall
            }
        }
        
        async function deletePool(poolId, poolName) {
            if (!confirm(`Delete pool "${poolName}"? This action cannot be undone.`)) return;
            
            try {
                await apiCall(`/api/bypass/pools/${poolId}`, { method: 'DELETE' });
                updatePoolsList();
            } catch (error) {
                // Error already handled by apiCall
            }
        }
        
        // Form submission
        document.getElementById('createPoolForm').addEventListener('submit', function(e) {
            e.preventDefault();
            createPool();
        });
        
        // Load pools on page load
        updatePoolsList();
        '''
        
        return self._get_base_html("Pools", content, extra_js=extra_js)
    
    def _get_attacks_html(self) -> str:
        """Attacks management HTML."""
        content = '''
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>Attack Registry</h2>
                <div>
                    <select id="categoryFilter" onchange="updateAttacksList()">
                        <option value="">All Categories</option>
                        <option value="TCP_FRAGMENTATION">TCP Fragmentation</option>
                        <option value="HTTP_MANIPULATION">HTTP Manipulation</option>
                        <option value="TLS_EVASION">TLS Evasion</option>
                        <option value="DNS_TUNNELING">DNS Tunneling</option>
                        <option value="PACKET_TIMING">Packet Timing</option>
                        <option value="PROTOCOL_OBFUSCATION">Protocol Obfuscation</option>
                    </select>
                    <label style="margin-left: 15px;">
                        <input type="checkbox" id="enabledOnlyFilter" onchange="updateAttacksList()">
                        Enabled only
                    </label>
                </div>
            </div>
            
            <div id="attacksList">Loading attacks...</div>
        </div>
        '''
        
        extra_js = '''
        async function updateAttacksList() {
            try {
                const category = document.getElementById('categoryFilter').value;
                const enabledOnly = document.getElementById('enabledOnlyFilter').checked;
                
                let url = '/api/bypass/attacks?';
                if (category) url += `category=${category}&`;
                if (enabledOnly) url += 'enabled_only=true&';
                
                const response = await apiCall(url);
                const attacks = response.attacks;
                
                let html = '';
                if (attacks.length === 0) {
                    html = '<p>No attacks found matching the current filters.</p>';
                } else {
                    html = `
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Category</th>
                                    <th>Complexity</th>
                                    <th>Status</th>
                                    <th>Tests</th>
                                    <th>Last Tested</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                    `;
                    
                    attacks.forEach(attack => {
                        const statusClass = attack.enabled ? 'enabled' : 'disabled';
                        const lastTested = attack.last_tested ? formatDate(attack.last_tested) : 'Never';
                        
                        html += `
                            <tr>
                                <td>
                                    <strong>${attack.name}</strong>
                                    <br><small>${attack.description.substring(0, 100)}...</small>
                                </td>
                                <td>${attack.category}</td>
                                <td>${attack.complexity}</td>
                                <td><span class="status status-${statusClass}">${attack.enabled ? 'Enabled' : 'Disabled'}</span></td>
                                <td>${attack.test_case_count}</td>
                                <td>${lastTested}</td>
                                <td>
                                    <a href="/bypass/attacks/${attack.id}" class="btn btn-sm">View</a>
                                    <button class="btn btn-sm btn-success" onclick="testAttack('${attack.id}')">Test</button>
                                    ${attack.enabled ? 
                                        `<button class="btn btn-sm btn-danger" onclick="toggleAttack('${attack.id}', false)">Disable</button>` :
                                        `<button class="btn btn-sm btn-success" onclick="toggleAttack('${attack.id}', true)">Enable</button>`
                                    }
                                </td>
                            </tr>
                        `;
                    });
                    
                    html += '</tbody></table>';
                }
                
                document.getElementById('attacksList').innerHTML = html;
            } catch (error) {
                document.getElementById('attacksList').innerHTML = '<p>Failed to load attacks</p>';
            }
        }
        
        async function testAttack(attackId) {
            try {
                const button = event.target;
                const originalText = button.textContent;
                button.innerHTML = '<span class="spinner"></span>Testing...';
                button.disabled = true;
                
                await apiCall(`/api/bypass/attacks/${attackId}/test`, {
                    method: 'POST',
                    body: JSON.stringify({})
                });
                
                button.textContent = originalText;
                button.disabled = false;
                
                // Refresh the list to show updated test results
                setTimeout(updateAttacksList, 1000);
            } catch (error) {
                button.textContent = originalText;
                button.disabled = false;
            }
        }
        
        async function toggleAttack(attackId, enable) {
            try {
                const endpoint = enable ? 'enable' : 'disable';
                const body = enable ? {} : { reason: 'Disabled via web interface' };
                
                await apiCall(`/api/bypass/attacks/${attackId}/${endpoint}`, {
                    method: 'POST',
                    body: JSON.stringify(body)
                });
                
                updateAttacksList();
            } catch (error) {
                // Error already handled by apiCall
            }
        }
        
        // Load attacks on page load
        updateAttacksList();
        '''
        
        return self._get_base_html("Attacks", content, extra_js=extra_js)
    
    def _get_testing_html(self) -> str:
        """Real-time testing interface HTML."""
        content = '''
        <div class="grid grid-2">
            <div class="card">
                <h2>🧪 Strategy Testing</h2>
                <form id="strategyTestForm">
                    <div class="form-group">
                        <label for="testDomain">Target Domain:</label>
                        <input type="text" id="testDomain" placeholder="example.com" required>
                    </div>
                    <div class="form-group">
                        <label for="testAttacks">Attacks (comma-separated):</label>
                        <input type="text" id="testAttacks" placeholder="tcp_fragmentation,http_manipulation" required>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="testPorts">Target Ports:</label>
                            <input type="text" id="testPorts" value="443" placeholder="443,80">
                        </div>
                        <div class="form-group">
                            <label for="testMode">Compatibility Mode:</label>
                            <select id="testMode">
                                <option value="native">Native</option>
                                <option value="emulated">Emulated</option>
                                <option value="hybrid">Hybrid</option>
                            </select>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-success">Start Test</button>
                </form>
            </div>
            
            <div class="card">
                <h2>📊 Test Results</h2>
                <div id="testResults">No tests running</div>
            </div>
        </div>
        
        <div class="card">
            <h2>🔄 Active Tests</h2>
            <div id="activeTestsList">No active tests</div>
        </div>
        '''
        
        extra_js = '''
        let activeTests = {};
        
        async function startStrategyTest() {
            const formData = {
                domain: document.getElementById('testDomain').value,
                strategy: {
                    attacks: document.getElementById('testAttacks').value.split(',').map(s => s.trim()).filter(s => s),
                    target_ports: document.getElementById('testPorts').value.split(',').map(s => parseInt(s.trim())).filter(p => p),
                    compatibility_mode: document.getElementById('testMode').value,
                    parameters: {}
                }
            };
            
            try {
                const response = await apiCall('/api/bypass/strategies/test', {
                    method: 'POST',
                    body: JSON.stringify(formData)
                });
                
                const testId = response.test_id;
                activeTests[testId] = {
                    domain: formData.domain,
                    attacks: formData.strategy.attacks,
                    status: 'running',
                    started_at: new Date(),
                    results: []
                };
                
                updateActiveTestsList();
                document.getElementById('strategyTestForm').reset();
                
            } catch (error) {
                // Error already handled by apiCall
            }
        }
        
        function updateActiveTestsList() {
            const container = document.getElementById('activeTestsList');
            
            if (Object.keys(activeTests).length === 0) {
                container.innerHTML = '<p>No active tests</p>';
                return;
            }
            
            let html = '<div class="grid grid-2">';
            
            for (const [testId, test] of Object.entries(activeTests)) {
                const duration = Math.round((new Date() - test.started_at) / 1000);
                const statusClass = test.status === 'completed' ? 'success' : 
                                  test.status === 'failed' ? 'failed' : 'testing';
                
                html += `
                    <div class="card">
                        <h3>${test.domain}</h3>
                        <div style="margin: 10px 0;">
                            <span class="status status-${statusClass}">${test.status}</span>
                        </div>
                        <div style="font-size: 0.9em; color: #666;">
                            <div>Attacks: ${test.attacks.join(', ')}</div>
                            <div>Duration: ${duration}s</div>
                            <div>Results: ${test.results.length}</div>
                        </div>
                        ${test.results.length > 0 ? `
                            <div style="margin-top: 10px;">
                                <strong>Results:</strong>
                                ${test.results.map(r => `
                                    <div style="font-size: 0.8em; margin: 2px 0;">
                                        ${r.attack_id}: ${r.success ? '✅' : '❌'} (${formatDuration(r.execution_time_ms)})
                                    </div>
                                `).join('')}
                            </div>
                        ` : ''}
                        <button class="btn btn-sm btn-danger" onclick="removeTest('${testId}')">Remove</button>
                    </div>
                `;
            }
            
            html += '</div>';
            container.innerHTML = html;
        }
        
        function removeTest(testId) {
            delete activeTests[testId];
            updateActiveTestsList();
        }
        
        function handleTestCompleted(data) {
            if (data.test_id in activeTests) {
                activeTests[data.test_id].status = 'completed';
                activeTests[data.test_id].results = data.results;
                updateActiveTestsList();
                
                // Show notification
                const successCount = data.results.filter(r => r.success).length;
                const totalCount = data.results.length;
                
                document.getElementById('testResults').innerHTML = `
                    <div class="card">
                        <h3>Test Completed: ${data.domain}</h3>
                        <p>Success rate: ${successCount}/${totalCount} (${Math.round(successCount/totalCount*100)}%)</p>
                    </div>
                `;
            }
        }
        
        // Form submission
        document.getElementById('strategyTestForm').addEventListener('submit', function(e) {
            e.preventDefault();
            startStrategyTest();
        });
        
        // Update active tests every 5 seconds
        setInterval(updateActiveTestsList, 5000);
        '''
        
        return self._get_base_html("Testing", content, extra_js=extra_js)
    
    def _get_config_html(self) -> str:
        """Configuration import/export HTML."""
        content = '''
        <div class="grid grid-2">
            <div class="card">
                <h2>📤 Export Configuration</h2>
                <p>Export your current bypass engine configuration including all pools, strategies, and settings.</p>
                <button class="btn btn-success" onclick="exportConfig()">Export Configuration</button>
                <div id="exportResult" style="margin-top: 15px;"></div>
            </div>
            
            <div class="card">
                <h2>📥 Import Configuration</h2>
                <p>Import a previously exported configuration. This will merge with your current settings.</p>
                <div class="form-group">
                    <label for="configFile">Configuration File:</label>
                    <input type="file" id="configFile" accept=".json">
                </div>
                <button class="btn btn-warning" onclick="importConfig()">Import Configuration</button>
                <div id="importResult" style="margin-top: 15px;"></div>
            </div>
        </div>
        
        <div class="card">
            <h2>📋 Configuration Preview</h2>
            <div id="configPreview">Click "Export Configuration" to see current configuration</div>
        </div>
        '''
        
        extra_js = '''
        async function exportConfig() {
            try {
                const response = await apiCall('/api/bypass/config/export');
                const config = response.config;
                
                // Show preview
                document.getElementById('configPreview').innerHTML = `
                    <pre style="background: #f7fafc; padding: 15px; border-radius: 8px; overflow-x: auto;">
${JSON.stringify(config, null, 2)}
                    </pre>
                `;
                
                // Create download link
                const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `bypass-config-${new Date().toISOString().split('T')[0]}.json`;
                a.click();
                URL.revokeObjectURL(url);
                
                document.getElementById('exportResult').innerHTML = `
                    <div style="color: #48bb78;">
                        ✅ Configuration exported successfully!<br>
                        Pools: ${config.pools.length}<br>
                        Exported at: ${formatDate(config.exported_at)}
                    </div>
                `;
                
            } catch (error) {
                document.getElementById('exportResult').innerHTML = `
                    <div style="color: #f56565;">❌ Export failed: ${error.message}</div>
                `;
            }
        }
        
        async function importConfig() {
            const fileInput = document.getElementById('configFile');
            const file = fileInput.files[0];
            
            if (!file) {
                alert('Please select a configuration file');
                return;
            }
            
            try {
                const text = await file.text();
                const config = JSON.parse(text);
                
                const response = await apiCall('/api/bypass/config/import', {
                    method: 'POST',
                    body: JSON.stringify({ config })
                });
                
                document.getElementById('importResult').innerHTML = `
                    <div style="color: #48bb78;">
                        ✅ ${response.message}
                    </div>
                `;
                
                // Clear file input
                fileInput.value = '';
                
            } catch (error) {
                document.getElementById('importResult').innerHTML = `
                    <div style="color: #f56565;">❌ Import failed: ${error.message}</div>
                `;
            }
        }
        '''
        
        return self._get_base_html("Configuration", content, extra_js=extra_js)
    
    def _get_pool_detail_html(self, pool_id: str) -> str:
        """Pool detail page HTML."""
        content = f'''
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 id="poolTitle">Loading pool...</h2>
                <div>
                    <a href="/bypass/pools/{pool_id}/edit" class="btn btn-warning">Edit Pool</a>
                    <a href="/bypass/pools" class="btn">Back to Pools</a>
                </div>
            </div>
            
            <div id="poolDetails">Loading pool details...</div>
        </div>
        '''
        
        extra_js = f'''
        async function loadPoolDetails() {{
            try {{
                const response = await apiCall('/api/bypass/pools/{pool_id}');
                const pool = response.pool;
                
                document.getElementById('poolTitle').textContent = pool.name;
                
                let html = `
                    <div class="grid grid-2">
                        <div>
                            <h3>Basic Information</h3>
                            <p><strong>Description:</strong> ${{pool.description || 'No description'}}</p>
                            <p><strong>Priority:</strong> ${{pool.priority}}</p>
                            <p><strong>Created:</strong> ${{formatDate(pool.created_at)}}</p>
                            <p><strong>Updated:</strong> ${{formatDate(pool.updated_at)}}</p>
                            <p><strong>Tags:</strong> ${{pool.tags.join(', ') || 'None'}}</p>
                        </div>
                        <div>
                            <h3>Strategy</h3>
                            <p><strong>Name:</strong> ${{pool.strategy.name}}</p>
                            <p><strong>Attacks:</strong> ${{pool.strategy.attacks.join(', ')}}</p>
                            <p><strong>Target Ports:</strong> ${{pool.strategy.target_ports.join(', ')}}</p>
                            <p><strong>Compatibility:</strong> ${{pool.strategy.compatibility_mode}}</p>
                            <p><strong>Success Rate:</strong> ${{(pool.strategy.success_rate * 100).toFixed(1)}}%</p>
                        </div>
                    </div>
                    
                    <h3>Domains (${{pool.domains.length}})</h3>
                    <div style="max-height: 200px; overflow-y: auto; border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px;">
                        ${{pool.domains.length > 0 ? 
                            pool.domains.map(domain => `<div style="padding: 2px 0;">${{domain}}</div>`).join('') :
                            '<p>No domains configured</p>'
                        }}
                    </div>
                    
                    ${{Object.keys(pool.subdomains).length > 0 ? `
                        <h3>Subdomain Overrides</h3>
                        <div class="table">
                            <table class="table">
                                <thead>
                                    <tr><th>Subdomain</th><th>Strategy</th><th>Attacks</th></tr>
                                </thead>
                                <tbody>
                                    ${{Object.entries(pool.subdomains).map(([subdomain, strategy]) => `
                                        <tr>
                                            <td>${{subdomain}}</td>
                                            <td>${{strategy.name}}</td>
                                            <td>${{strategy.attacks.join(', ')}}</td>
                                        </tr>
                                    `).join('')}}
                                </tbody>
                            </table>
                        </div>
                    ` : ''}}
                    
                    ${{Object.keys(pool.ports).length > 0 ? `
                        <h3>Port Overrides</h3>
                        <div class="table">
                            <table class="table">
                                <thead>
                                    <tr><th>Port</th><th>Strategy</th><th>Attacks</th></tr>
                                </thead>
                                <tbody>
                                    ${{Object.entries(pool.ports).map(([port, strategy]) => `
                                        <tr>
                                            <td>${{port}}</td>
                                            <td>${{strategy.name}}</td>
                                            <td>${{strategy.attacks.join(', ')}}</td>
                                        </tr>
                                    `).join('')}}
                                </tbody>
                            </table>
                        </div>
                    ` : ''}}
                `;
                
                document.getElementById('poolDetails').innerHTML = html;
                
            }} catch (error) {{
                document.getElementById('poolDetails').innerHTML = '<p>Failed to load pool details</p>';
            }}
        }}
        
        // Load pool details on page load
        loadPoolDetails();
        '''
        
        return self._get_base_html(f"Pool Details", content, extra_js=extra_js)
    
    def _get_pool_edit_html(self, pool_id: str) -> str:
        """Pool editing page HTML."""
        content = f'''
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>Edit Pool</h2>
                <a href="/bypass/pools/{pool_id}" class="btn">Cancel</a>
            </div>
            
            <form id="editPoolForm">
                <div id="poolEditForm">Loading pool data...</div>
                <button type="submit" class="btn btn-success">Save Changes</button>
            </form>
        </div>
        '''
        
        extra_js = f'''
        let currentPool = null;
        
        async function loadPoolForEdit() {{
            try {{
                const response = await apiCall('/api/bypass/pools/{pool_id}');
                currentPool = response.pool;
                
                let html = `
                    <div class="form-group">
                        <label for="editPoolName">Pool Name:</label>
                        <input type="text" id="editPoolName" value="${{currentPool.name}}" required>
                    </div>
                    <div class="form-group">
                        <label for="editPoolDescription">Description:</label>
                        <textarea id="editPoolDescription">${{currentPool.description}}</textarea>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="editPoolPriority">Priority:</label>
                            <select id="editPoolPriority">
                                <option value="LOW" ${{currentPool.priority === 'LOW' ? 'selected' : ''}}>Low</option>
                                <option value="NORMAL" ${{currentPool.priority === 'NORMAL' ? 'selected' : ''}}>Normal</option>
                                <option value="HIGH" ${{currentPool.priority === 'HIGH' ? 'selected' : ''}}>High</option>
                                <option value="CRITICAL" ${{currentPool.priority === 'CRITICAL' ? 'selected' : ''}}>Critical</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="editStrategyAttacks">Attacks (comma-separated):</label>
                            <input type="text" id="editStrategyAttacks" value="${{currentPool.strategy.attacks.join(', ')}}">
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="editPoolTags">Tags (comma-separated):</label>
                        <input type="text" id="editPoolTags" value="${{currentPool.tags.join(', ')}}">
                    </div>
                `;
                
                document.getElementById('poolEditForm').innerHTML = html;
                
            }} catch (error) {{
                document.getElementById('poolEditForm').innerHTML = '<p>Failed to load pool data</p>';
            }}
        }}
        
        async function savePoolChanges() {{
            if (!currentPool) return;
            
            const formData = {{
                name: document.getElementById('editPoolName').value,
                description: document.getElementById('editPoolDescription').value,
                priority: document.getElementById('editPoolPriority').value,
                strategy: {{
                    attacks: document.getElementById('editStrategyAttacks').value.split(',').map(s => s.trim()).filter(s => s),
                    parameters: currentPool.strategy.parameters
                }},
                tags: document.getElementById('editPoolTags').value.split(',').map(s => s.trim()).filter(s => s)
            }};
            
            try {{
                await apiCall('/api/bypass/pools/{pool_id}', {{
                    method: 'PUT',
                    body: JSON.stringify(formData)
                }});
                
                // Redirect to pool detail page
                window.location.href = '/bypass/pools/{pool_id}';
                
            }} catch (error) {{
                // Error already handled by apiCall
            }}
        }}
        
        // Form submission
        document.getElementById('editPoolForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            savePoolChanges();
        }});
        
        // Load pool data on page load
        loadPoolForEdit();
        '''
        
        return self._get_base_html("Edit Pool", content, extra_js=extra_js)
    
    def _get_attack_detail_html(self, attack_id: str) -> str:
        """Attack detail page HTML."""
        content = f'''
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 id="attackTitle">Loading attack...</h2>
                <a href="/bypass/attacks" class="btn">Back to Attacks</a>
            </div>
            
            <div id="attackDetails">Loading attack details...</div>
        </div>
        '''
        
        extra_js = f'''
        async function loadAttackDetails() {{
            try {{
                const response = await apiCall('/api/bypass/attacks/{attack_id}');
                const attack = response.attack;
                
                document.getElementById('attackTitle').textContent = attack.name;
                
                let html = `
                    <div class="grid grid-2">
                        <div>
                            <h3>Basic Information</h3>
                            <p><strong>Description:</strong> ${{attack.description}}</p>
                            <p><strong>Category:</strong> ${{attack.category}}</p>
                            <p><strong>Complexity:</strong> ${{attack.complexity}}</p>
                            <p><strong>Stability:</strong> ${{attack.stability}}</p>
                            <p><strong>Status:</strong> 
                                <span class="status status-${{attack.enabled ? 'enabled' : 'disabled'}}">
                                    ${{attack.enabled ? 'Enabled' : 'Disabled'}}
                                </span>
                            </p>
                            <p><strong>Protocols:</strong> ${{attack.supported_protocols.join(', ')}}</p>
                            <p><strong>Ports:</strong> ${{attack.supported_ports.join(', ')}}</p>
                        </div>
                        <div>
                            <h3>Testing Information</h3>
                            <p><strong>Test Cases:</strong> ${{attack.test_cases.length}}</p>
                            <p><strong>Last Tested:</strong> ${{attack.last_tested ? formatDate(attack.last_tested) : 'Never'}}</p>
                            <p><strong>Tags:</strong> ${{attack.tags.join(', ') || 'None'}}</p>
                            <div style="margin-top: 15px;">
                                <button class="btn btn-success" onclick="testAttack()">Run Test</button>
                                ${{attack.enabled ? 
                                    '<button class="btn btn-danger" onclick="toggleAttack(false)">Disable</button>' :
                                    '<button class="btn btn-success" onclick="toggleAttack(true)">Enable</button>'
                                }}
                            </div>
                        </div>
                    </div>
                    
                    ${{attack.test_cases.length > 0 ? `
                        <h3>Test Cases</h3>
                        <table class="table">
                            <thead>
                                <tr><th>Name</th><th>Target</th><th>Description</th><th>Expected</th></tr>
                            </thead>
                            <tbody>
                                ${{attack.test_cases.map(tc => `
                                    <tr>
                                        <td>${{tc.name}}</td>
                                        <td>${{tc.target_domain}}</td>
                                        <td>${{tc.description}}</td>
                                        <td>${{tc.expected_success ? 'Success' : 'Failure'}}</td>
                                    </tr>
                                `).join('')}}
                            </tbody>
                        </table>
                    ` : ''}}
                    
                    ${{attack.recent_test_results.length > 0 ? `
                        <h3>Recent Test Results</h3>
                        <table class="table">
                            <thead>
                                <tr><th>Test Case</th><th>Result</th><th>Duration</th><th>Timestamp</th><th>Error</th></tr>
                            </thead>
                            <tbody>
                                ${{attack.recent_test_results.map(tr => `
                                    <tr>
                                        <td>${{tr.test_case_id}}</td>
                                        <td><span class="status status-${{tr.success ? 'success' : 'failed'}}">${{tr.success ? 'Success' : 'Failed'}}</span></td>
                                        <td>${{formatDuration(tr.execution_time_ms)}}</td>
                                        <td>${{formatDate(tr.timestamp)}}</td>
                                        <td>${{tr.error_message || '-'}}</td>
                                    </tr>
                                `).join('')}}
                            </tbody>
                        </table>
                    ` : ''}}
                `;
                
                document.getElementById('attackDetails').innerHTML = html;
                
            }} catch (error) {{
                document.getElementById('attackDetails').innerHTML = '<p>Failed to load attack details</p>';
            }}
        }}
        
        async function testAttack() {{
            try {{
                const button = event.target;
                const originalText = button.textContent;
                button.innerHTML = '<span class="spinner"></span>Testing...';
                button.disabled = true;
                
                await apiCall('/api/bypass/attacks/{attack_id}/test', {{
                    method: 'POST',
                    body: JSON.stringify({{}})
                }});
                
                button.textContent = originalText;
                button.disabled = false;
                
                // Refresh details to show new test results
                setTimeout(loadAttackDetails, 1000);
                
            }} catch (error) {{
                button.textContent = originalText;
                button.disabled = false;
            }}
        }}
        
        async function toggleAttack(enable) {{
            try {{
                const endpoint = enable ? 'enable' : 'disable';
                const body = enable ? {{}} : {{ reason: 'Disabled via web interface' }};
                
                await apiCall('/api/bypass/attacks/{attack_id}/' + endpoint, {{
                    method: 'POST',
                    body: JSON.stringify(body)
                }});
                
                loadAttackDetails();
                
            }} catch (error) {{
                // Error already handled by apiCall
            }}
        }}
        
        // Load attack details on page load
        loadAttackDetails();
        '''
        
        return self._get_base_html("Attack Details", content, extra_js=extra_js)