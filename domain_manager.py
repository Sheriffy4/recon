# recon/core/domain_manager.py
import statistics
import socket
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class DomainTestResult:
    domain: str
    strategy: str
    success: bool
    rtt: float
    error_type: str = None


class DomainManager:
    """Управление списком доменов для массового и параллельного тестирования стратегий."""

    def __init__(self, domains_file: str = None, default_domains: List[str] = None):
        self.domains = self._load_domains(domains_file, default_domains)
        self.results_log: List[DomainTestResult] = []

    def _load_domains(self, filename: str, defaults: List[str]) -> List[str]:
        """Загружает домены из файла или использует дефолтные."""
        if filename and Path(filename).exists():
            with open(filename, "r", encoding="utf-8") as f:
                # --- ИСПРАВЛЕНИЕ: Добавлена проверка на комментарии ---
                return [
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith(("#", "/"))
                ]
        return defaults or []

    def test_strategy_on_all(
        self, strategy_task: Dict, engine_run_func, max_workers: int = 5
    ) -> Dict:
        """Тестирует одну стратегию на всех доменах параллельно."""
        latencies = []
        successful_domains = []
        failed_domains = []

        def run_test_for_domain(domain: str):
            try:
                ip = socket.gethostbyname(domain)
                result, rtt = engine_run_func(ip, 443, domain, strategy_task)
                return domain, result, rtt
            except socket.gaierror:
                return domain, "DNS_ERROR", 0.0
            except Exception as e:
                return domain, f"ENGINE_ERROR: {e}", 0.0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_domain = {
                executor.submit(run_test_for_domain, domain): domain
                for domain in self.domains
            }

            for future in as_completed(future_to_domain):
                domain, result, rtt = future.result()

                test_result = DomainTestResult(
                    domain=domain,
                    strategy=str(strategy_task),
                    success=(result == "SUCCESS"),
                    rtt=rtt * 1000,
                    error_type=result if result != "SUCCESS" else None,
                )
                self.results_log.append(test_result)

                if test_result.success:
                    successful_domains.append(domain)
                    latencies.append(test_result.rtt)
                else:
                    failed_domains.append(domain)

        total_tested = len(self.domains)
        success_count = len(successful_domains)

        return {
            "strategy": strategy_task,
            "success_rate": (success_count / total_tested) if total_tested else 0,
            "successful_domains_count": success_count,
            "total_domains": total_tested,
            "median_latency_ms": (
                statistics.median(latencies) if latencies else float("inf")
            ),
            "successful_domains_list": successful_domains,
        }
