# recon/core/effectiveness/production_effectiveness_tester.py

import time
import statistics
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional, List, Dict, Any

LOG = logging.getLogger("ProductionEffectivenessTester")


@dataclass
class TestOutcome:
    success: bool
    latency_ms: float
    status_code: Optional[int] = None
    error: Optional[str] = None


@dataclass
class EffectivenessReport:
    domain: str
    baseline: TestOutcome
    bypass: TestOutcome
    verdict: str
    reason: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class ProductionEffectivenessTester:
    """
    Production-ready effectiveness tester:
    - Performs baseline connectivity tests (no bypass)
    - Performs bypass-enabled tests (with provided callbacks)
    - Compares results and determines effectiveness
    - Maintains history and computes trends
    - Provides simple alerting on degrading trends
    """

    def __init__(
        self,
        history_size: int = 50,
        alert_threshold: float = 0.6,
        timeout_s: float = 7.0,
    ):
        self.history_size = max(10, history_size)
        self.alert_threshold = max(0.0, min(1.0, alert_threshold))
        self.timeout_s = timeout_s
        self._history: List[EffectivenessReport] = []

    def _http_probe(self, domain: str, https: bool = True) -> TestOutcome:
        try:
            import requests  # type: ignore
        except Exception as e:
            return TestOutcome(success=False, latency_ms=0.0, error=f"requests not available: {e}")

        scheme = "https" if https else "http"
        url = f"{scheme}://{domain}"
        start = time.perf_counter()
        try:
            resp = requests.get(url, timeout=self.timeout_s)
            latency = (time.perf_counter() - start) * 1000.0
            ok = (
                200 <= resp.status_code < 500
            )  # считать подключение успешным при любом ответе сервера
            return TestOutcome(success=ok, latency_ms=latency, status_code=resp.status_code)
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000.0
            return TestOutcome(success=False, latency_ms=latency, error=str(e))

    def _append_history(self, report: EffectivenessReport) -> None:
        self._history.append(report)
        if len(self._history) > self.history_size:
            self._history.pop(0)

    def _compute_trend(self) -> Dict[str, Any]:
        if not self._history:
            return {"success_rate": None, "avg_latency_ms": None}
        successes = [1.0 if r.bypass.success else 0.0 for r in self._history]
        lats = [r.bypass.latency_ms for r in self._history if r.bypass.latency_ms > 0]
        return {
            "success_rate": sum(successes) / len(successes),
            "avg_latency_ms": statistics.mean(lats) if lats else None,
        }

    def evaluate(
        self,
        domain: str,
        start_bypass: Callable[[], None],
        stop_bypass: Callable[[], None],
        use_https: bool = True,
    ) -> EffectivenessReport:
        LOG.info(f"Starting effectiveness evaluation for {domain}")

        # 1) Baseline (без обхода)
        baseline = self._http_probe(domain, https=use_https)
        LOG.debug(
            f"Baseline outcome: success={baseline.success}, code={baseline.status_code}, latency={baseline.latency_ms:.1f}ms error={baseline.error}"
        )

        # 2) Bypass (с включённым обходом)
        start_bypass()
        try:
            time.sleep(0.2)  # дать системе активироваться
            bypass = self._http_probe(domain, https=use_https)
        finally:
            try:
                stop_bypass()
            except Exception:
                pass

        LOG.debug(
            f"Bypass outcome: success={bypass.success}, code={bypass.status_code}, latency={bypass.latency_ms:.1f}ms error={bypass.error}"
        )

        verdict, reason = self._derive_verdict(baseline, bypass)
        report = EffectivenessReport(
            domain=domain,
            baseline=baseline,
            bypass=bypass,
            verdict=verdict,
            reason=reason,
        )
        self._append_history(report)

        trend = self._compute_trend()
        if trend.get("success_rate") is not None and trend["success_rate"] < self.alert_threshold:
            LOG.warning(
                f"Effectiveness degrading: success_rate={trend['success_rate']:.2f} < threshold={self.alert_threshold:.2f}"
            )

        LOG.info(f"Effectiveness test verdict for {domain}: {verdict} ({reason or 'n/a'})")
        return report

    def _derive_verdict(self, baseline: TestOutcome, bypass: TestOutcome) -> (str, Optional[str]):
        # Отдельная проверка базовой коннективности
        if baseline.success:
            # Если baseline работает, то цель обхода — не ухудшить
            if bypass.success:
                # Сравним задержки: если обход резко ухудшает — предупреждение
                if (
                    bypass.latency_ms > baseline.latency_ms * 2
                    and bypass.latency_ms - baseline.latency_ms > 300
                ):
                    return "degrading", "bypass increases latency significantly"
                return "healthy", None
            else:
                return "failing", "bypass breaks connectivity"
        else:
            # Базовая связь отсутствует — проверяем, смог ли обход помочь
            if bypass.success:
                return "healthy", "bypass restores connectivity"
            else:
                return "failing", "baseline blocked and bypass ineffective"

    def get_history(self) -> List[EffectivenessReport]:
        return list(self._history)

    def get_trend(self) -> Dict[str, Any]:
        return self._compute_trend()
