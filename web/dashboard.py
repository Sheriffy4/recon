# recon/web/dashboard.py
import threading
import logging
import json
from flask import Flask, render_template_string

try:
    import plotly.graph_objs as go
    import plotly.utils

    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

# ИСПРАВЛЕНИЕ: Добавляем зависимости для WebSocket
try:
    from flask_socketio import SocketIO

    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False


class ReconDashboard:
    """
    ИСПРАВЛЕНИЕ: Расширенная веб-панель с графиками и real-time обновлениями через WebSocket.
    """

    TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Recon Dashboard</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 20px; background-color: #f4f7f6; color: #333; }
            .container { max-width: 1200px; margin: 0 auto; }
            h1, h2 { color: #2c3e50; }
            .stats { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; }
            .stat-card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; flex-grow: 1; }
            .stat-card h3 { margin-top: 0; color: #3498db; }
            .stat-card p { font-size: 2em; margin: 0; font-weight: bold; color: #2c3e50; }
            .chart { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .success { color: #27ae60; }
            .warning { color: #f39c12; }
            .error { color: #e74c3c; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🚀 Recon DPI Bypass Dashboard</h1>
            <div id="stats" class="stats"></div>
            <div id="live-stats" class="stats"></div> <!-- НОВЫЙ БЛОК -->
            <div id="success-chart" class="chart"></div>
            <div id="dpi-types-chart" class="chart"></div>
            <div id="latency-chart" class="chart"></div>
            <script>
                $(document).ready(function() {
                    var socket = io();

                    socket.on('connect', function() {
                        console.log('Connected to dashboard server!');
                    });

                    socket.on('update', function(data) {
                        console.log('Received update:', data);
                        $('#stats').html(data.stats_html);
                        $('#live-stats').html(data.live_stats_html); // ОБНОВЛЯЕМ LIVE СТАТИСТИКУ
                        
                        if (data.success_chart) Plotly.react('success-chart', JSON.parse(data.success_chart), {title: 'Success Rate Over Time'});
                        if (data.dpi_types_chart) Plotly.react('dpi-types-chart', JSON.parse(data.dpi_types_chart), {title: 'DPI Types Distribution'});
                        if (data.latency_chart) Plotly.react('latency-chart', JSON.parse(data.latency_chart), {title: 'Strategy Latency Distribution (ms)'});
                    });

                    // Запрашиваем обновление каждые 5 секунд
                    setInterval(() => socket.emit('request_update'), 5000);
                });
            </script>
        </div>
    </body>
    </html>
    """

    def __init__(self, signature_manager, bypass_engine=None, port=8080):
        if not PLOTLY_AVAILABLE or not SOCKETIO_AVAILABLE:
            logging.warning(
                "Plotly или Flask-SocketIO не установлены. Расширенный дашборд будет недоступен."
            )
            self.app = None
            return

        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, async_mode="threading")
        self.signature_manager = signature_manager
        self.bypass_engine = bypass_engine  # Сохраняем движок
        self.port = port
        self.setup_routes()

    def _get_dashboard_data(self):
        """Собирает все данные для дашборда в одном месте."""
        stats = self.signature_manager.get_statistics()
        engine_stats = self.bypass_engine.stats if self.bypass_engine else {}
        # Попробуем получить тренд и health (если доступны из мониторинга/диагностики)
        prod_trend = {}
        health_alerts = []
        try:

            monitor = getattr(self.bypass_engine, "strategy_monitor", None)
            if monitor and hasattr(monitor, "prod_effectiveness_tester"):
                prod_trend = monitor.prod_effectiveness_tester.get_trend()
        except Exception:
            pass
        try:
            # Предположим, что диагностика может хранить последние health-статусы
            diagnostic = getattr(self.bypass_engine, "diagnostic_system", None)
            if diagnostic and hasattr(diagnostic, "recent_health_alerts"):
                health_alerts = list(diagnostic.recent_health_alerts)[-5:]
        except Exception:
            pass

        stats_html = f"""
        <div class="stat-card"><h3>Total Signatures</h3><p>{stats.get('total_signatures', 0)}</p></div>
        <div class="stat-card"><h3>Avg Success Rate</h3><p class="success">{stats.get('average_success_rate', 0):.1%}</p></div>
        <div class="stat-card"><h3>Recent Updates (7d)</h3><p>{stats.get('recent_updates_7d', 0)}</p></div>
        """

        live_stats_html = f"""
        <div class="stat-card"><h3>Packets Captured</h3><p>{engine_stats.get('packets_captured', 0)}</p></div>
        <div class="stat-card"><h3>Bypasses Applied</h3><p class="success">{engine_stats.get('tls_packets_bypassed', 0)}</p></div>
        <div class="stat-card"><h3>Fake Packets Sent</h3><p class="warning">{engine_stats.get('fake_packets_sent', 0)}</p></div>
        <div class="stat-card"><h3>Prod Success Rate</h3><p class="success">{(prod_trend.get('success_rate') or 0):.1%}</p></div>
        <div class="stat-card"><h3>Prod Avg Latency</h3><p>{int(prod_trend.get('avg_latency_ms') or 0)} ms</p></div>
        """

        # Генерация графиков (остается как есть, но можно добавить live-графики)
        dpi_types_chart = go.Figure(
            data=[
                go.Pie(
                    labels=list(stats.get("dpi_types", {}).keys()),
                    values=list(stats.get("dpi_types", {}).values()),
                )
            ]
        )
        latencies = [
            entry.get("working_strategy", {}).get("avg_latency_ms", 0)
            for entry in self.signature_manager.signatures.values()
            if entry.get("working_strategy")
        ]
        latency_chart = go.Figure(data=[go.Box(y=latencies, name="Latency (ms)")])

        return {
            "stats_html": stats_html,
            "live_stats_html": live_stats_html,
            "dpi_types_chart": json.dumps(
                dpi_types_chart, cls=plotly.utils.PlotlyJSONEncoder
            ),
            "latency_chart": json.dumps(
                latency_chart, cls=plotly.utils.PlotlyJSONEncoder
            ),
            "health_alerts": health_alerts,
        }

    def setup_routes(self):
        @self.app.route("/")
        def index():
            return render_template_string(self.TEMPLATE)

        @self.socketio.on("connect")
        def handle_connect():
            logging.info("Dashboard client connected")
            self.socketio.emit("update", self._get_dashboard_data())

        @self.socketio.on("request_update")
        def handle_request_update():
            self.socketio.emit("update", self._get_dashboard_data())

    def start(self):
        """Запускает веб-сервер в отдельном потоке."""
        if not self.app:
            return

        def run_app():
            try:
                # Используем socketio.run для поддержки WebSocket
                self.socketio.run(
                    self.app,
                    host="0.0.0.0",
                    port=self.port,
                    debug=False,
                    allow_unsafe_werkzeug=True,
                )
            except Exception as e:
                logging.error(f"Dashboard server failed: {e}")

        thread = threading.Thread(target=run_app, daemon=True)
        thread.start()
        logging.info(f"📊 Advanced Dashboard доступен на http://localhost:{self.port}")
