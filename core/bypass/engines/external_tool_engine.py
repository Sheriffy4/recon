"""
Engine for external bypass tools (zapret, goodbyedpi).
"""
import subprocess
import platform
import shutil
import time
from typing import Dict, Any, Set, Optional, List
from pathlib import Path
from recon.core.bypass.engines.base import BaseBypassEngine, EngineConfig

class ExternalToolEngine(BaseBypassEngine):
    """Engine that manages external bypass tools like zapret or goodbyedpi."""
    TOOL_CONFIGS = {'zapret': {'windows': {'executable': 'winws.exe', 'path': 'bin', 'base_args': ['--wf-l3=ipv4']}, 'linux': {'executable': 'nfqws', 'path': '/opt/zapret', 'base_args': []}}, 'goodbyedpi': {'windows': {'executable': 'goodbyedpi.exe', 'path': 'bin', 'base_args': []}, 'linux': None}}

    def __init__(self, config: EngineConfig):
        super().__init__(config)
        self.process: Optional[subprocess.Popen] = None
        self.tool_name = config.tool_name or 'zapret'
        if self.tool_name not in self.TOOL_CONFIGS:
            raise ValueError(f'Unknown tool: {self.tool_name}')

    def _find_tool_path(self) -> Path:
        """Find executable path for the tool."""
        system = 'windows' if platform.system() == 'Windows' else 'linux'
        tool_config = self.TOOL_CONFIGS[self.tool_name].get(system)
        if not tool_config:
            raise RuntimeError(f'Tool {self.tool_name} not supported on {system}')
        if self.config.base_path:
            tool_path = Path(self.config.base_path) / tool_config['path'] / tool_config['executable']
            if tool_path.exists():
                return tool_path
        found = shutil.which(tool_config['executable'])
        if found:
            return Path(found)
        abs_path = Path(tool_config['path']) / tool_config['executable']
        if abs_path.exists():
            return abs_path
        raise FileNotFoundError(f"Tool executable not found: {tool_config['executable']}")

    def _build_command(self, target_ips: Set[str], strategy_map: Dict[str, Dict[str, Any]]) -> List[str]:
        """Build command line for the tool."""
        tool_path = self._find_tool_path()
        system = 'windows' if platform.system() == 'Windows' else 'linux'
        tool_config = self.TOOL_CONFIGS[self.tool_name][system]
        command = [str(tool_path)] + tool_config['base_args']
        if self.tool_name == 'zapret' and system == 'windows':
            ports = set()
            for strategy in strategy_map.values():
                port = strategy.get('target_port', 443)
                ports.add(port)
            for port in ports:
                command.extend(['--wf-tcp', str(port)])
        if target_ips and strategy_map:
            first_ip = next(iter(target_ips))
            strategy = strategy_map.get(first_ip, {})
            strategy_args = self._convert_strategy_to_args(strategy)
            command.extend(strategy_args)
        return command

    def _convert_strategy_to_args(self, strategy: Dict[str, Any]) -> List[str]:
        """Convert strategy dict to tool-specific arguments."""
        args = []
        from recon.core.zapret import synth
        strategy_string = synth(strategy)
        if strategy_string:
            args.extend(strategy_string.split())
        return args

    def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict[str, Any]]) -> bool:
        """Start the external tool."""
        if self.is_running:
            self.logger.warning(f'{self.tool_name} already running')
            return False
        try:
            command = self._build_command(target_ips, strategy_map)
            self.logger.info(f"Starting {self.tool_name}: {' '.join(command)}")
            if platform.system() == 'Windows':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, startupinfo=startupinfo, cwd=str(Path(command[0]).parent))
            else:
                self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(Path(command[0]).parent))
            time.sleep(1.5)
            if self.process.poll() is not None:
                self.logger.error(f'{self.tool_name} terminated immediately')
                self.process = None
                return False
            self.is_running = True
            self.stats.start_time = time.time()
            self.logger.info(f'{self.tool_name} started (PID: {self.process.pid})')
            return True
        except Exception as e:
            self.logger.error(f'Failed to start {self.tool_name}: {e}')
            self.process = None
            return False

    def stop(self) -> bool:
        """Stop the external tool."""
        if not self.is_running or not self.process:
            return True
        try:
            pid = self.process.pid
            self.logger.info(f'Stopping {self.tool_name} (PID: {pid})')
            if platform.system() == 'Windows':
                result = subprocess.run(['taskkill', '/F', '/T', '/PID', str(pid)], capture_output=True, check=False, timeout=5)
                if result.returncode != 0 and 'not found' not in result.stderr:
                    self.logger.warning(f'taskkill failed: {result.stderr}')
            else:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.logger.warning("Process didn't terminate, killing")
                    self.process.kill()
                    self.process.wait(timeout=2)
            self.logger.info(f'{self.tool_name} stopped')
        except Exception as e:
            self.logger.error(f'Error stopping {self.tool_name}: {e}')
            return False
        finally:
            self.process = None
            self.is_running = False
            self.stats.stop_time = time.time()
        return True

    def is_healthy(self) -> bool:
        """Check if the external tool is still running."""
        if not self.is_running or not self.process:
            return False
        return self.process.poll() is None