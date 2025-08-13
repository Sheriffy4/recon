# recon/core/metrics.py
# Реализация системы метрик качества обхода, предложенная Экспертом 2.

import math


class BypassQualityMetrics:
    """Рассчитывает комплексную оценку качества успешной стратегии обхода."""

    def _calc_speed_score(self, rtt: float) -> float:
        """Оценка скорости: чем меньше RTT, тем выше оценка."""
        if rtt < 0.1:
            return 1.0  # Отлично
        if rtt > 2.0:
            return 0.1  # Очень медленно
        return max(0.1, 1.0 - (rtt / 2.0))

    def _calc_complexity_score(self, task: dict) -> float:
        """Оценка сложности: чем проще техника, тем выше оценка."""
        tech_type = task.get("type", "")
        if "combo" in tech_type:
            return 0.4  # Комбинированные атаки сложны
        if "split" in tech_type or "disorder" in tech_type:
            return 0.7  # Средняя сложность
        return 1.0  # Простые атаки

    def calculate_score(self, result: dict) -> dict:
        """
        Возвращает словарь с метриками и итоговой оценкой.
        result - элемент из списка results в cli.py
        """
        rtt = result.get("rtt", 1.0)
        task = result.get("task", {})

        speed = self._calc_speed_score(rtt)
        complexity = self._calc_complexity_score(task)

        # Итоговая оценка как средневзвешенное
        total_score = (speed * 0.6) + (complexity * 0.4)

        return {
            "speed": f"{speed:.2f}",
            "complexity": f"{complexity:.2f}",
            "total_score": f"{total_score:.2f}",
        }
