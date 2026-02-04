#!/usr/bin/env python3
"""
Strategy Reasoning Logger - Система логирования "мыслительного процесса" генерации стратегий.

Этот модуль создает детальный лог того, как система принимает решения о генерации
следующих стратегий на основе результатов тестирования, анализа PCAP и других данных.
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum


class ReasoningStep(Enum):
    """Типы шагов в процессе принятия решений"""

    INITIAL_STRATEGY = "initial_strategy"
    PCAP_ANALYSIS = "pcap_analysis"
    FAILURE_ANALYSIS = "failure_analysis"
    STRATEGY_GENERATION = "strategy_generation"
    PARAMETER_OPTIMIZATION = "parameter_optimization"
    COMPATIBILITY_CHECK = "compatibility_check"
    DECISION_MAKING = "decision_making"
    LEARNING_UPDATE = "learning_update"


@dataclass
class ReasoningEntry:
    """Запись в логе мыслительного процесса"""

    timestamp: str
    step: ReasoningStep
    domain: str
    iteration: int
    strategy_name: Optional[str]

    # Входные данные для принятия решения
    input_data: Dict[str, Any]

    # Процесс рассуждения
    reasoning: str

    # Принятое решение
    decision: Dict[str, Any]

    # Уверенность в решении (0.0 - 1.0)
    confidence: float

    # Дополнительные метаданные
    metadata: Dict[str, Any]


class StrategyReasoningLogger:
    """
    Логгер мыслительного процесса генерации стратегий.

    Записывает детальную информацию о том, как система принимает решения
    о генерации следующих стратегий на каждом шаге адаптивного процесса.
    """

    def __init__(self, enabled: bool = False, log_dir: str = "data/reasoning_logs"):
        self.enabled = enabled
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.current_session = None
        self.session_entries = []

        # Настройка логгера
        self.logger = logging.getLogger("strategy_reasoning")
        if not self.logger.handlers and enabled:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("[REASONING] %(asctime)s - %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def start_session(self, domain: str, mode: str = "auto") -> str:
        """Начать новую сессию логирования"""
        if not self.enabled:
            return ""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_id = f"{domain}_{timestamp}"

        self.current_session = {
            "session_id": session_id,
            "domain": domain,
            "mode": mode,
            "start_time": timestamp,
            "entries": [],
        }

        self.session_entries = []

        self.logger.info(f"🧠 Started reasoning session: {session_id}")
        return session_id

    def log_reasoning(
        self,
        step: ReasoningStep,
        domain: str,
        iteration: int,
        reasoning: str,
        decision: Dict[str, Any],
        confidence: float = 0.5,
        strategy_name: Optional[str] = None,
        input_data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Записать шаг мыслительного процесса"""

        if not self.enabled:
            return

        entry = ReasoningEntry(
            timestamp=datetime.now().isoformat(),
            step=step,
            domain=domain,
            iteration=iteration,
            strategy_name=strategy_name,
            input_data=input_data or {},
            reasoning=reasoning,
            decision=decision,
            confidence=confidence,
            metadata=metadata or {},
        )

        self.session_entries.append(entry)

        # Логирование в консоль
        self.logger.info(f"🧠 [{step.value.upper()}] Iter {iteration}: {reasoning}")
        self.logger.info(f"   Decision: {decision}")
        self.logger.info(f"   Confidence: {confidence:.2f}")

    def log_initial_strategy(self, domain: str, strategy: Dict[str, Any], source: str):
        """Логировать выбор начальной стратегии"""
        reasoning = f"Выбрана начальная стратегия из {source}"

        if source == "domain_rules.json":
            reasoning += f". Найдено точное совпадение для домена {domain}"
        elif source == "adaptive_knowledge.json":
            reasoning += f". Найдена сохраненная стратегия для {domain}"
        else:
            reasoning += f". Используется стратегия по умолчанию"

        self.log_reasoning(
            step=ReasoningStep.INITIAL_STRATEGY,
            domain=domain,
            iteration=0,
            reasoning=reasoning,
            decision={"strategy": strategy, "source": source},
            confidence=0.8 if source == "domain_rules.json" else 0.6,
            input_data={"available_sources": [source]},
        )

    def log_pcap_analysis(
        self,
        domain: str,
        iteration: int,
        pcap_results: Dict[str, Any],
        declared_strategy: str,
        applied_strategy: str,
    ):
        """Логировать результаты анализа PCAP"""

        match_status = "MATCH" if declared_strategy == applied_strategy else "MISMATCH"

        reasoning = f"Анализ PCAP показал {match_status}. "
        reasoning += f"Заявлена: {declared_strategy}, применена: {applied_strategy}. "

        if match_status == "MISMATCH":
            reasoning += "Обнаружено несоответствие - система применяет другую стратегию из domain_rules.json"
        else:
            reasoning += f"Стратегия применена корректно. Обнаружено атак: {len(pcap_results.get('attacks', []))}"

        confidence = 0.9 if match_status == "MATCH" else 0.3

        self.log_reasoning(
            step=ReasoningStep.PCAP_ANALYSIS,
            domain=domain,
            iteration=iteration,
            reasoning=reasoning,
            decision={
                "match_status": match_status,
                "declared_strategy": declared_strategy,
                "applied_strategy": applied_strategy,
                "pcap_attacks": pcap_results.get("attacks", []),
            },
            confidence=confidence,
            input_data=pcap_results,
        )

    def log_failure_analysis(
        self,
        domain: str,
        iteration: int,
        failed_strategy: str,
        failure_reason: str,
        retransmissions: int = 0,
        timeout: bool = False,
    ):
        """Логировать анализ неудачи"""

        reasoning = f"Стратегия {failed_strategy} не сработала. "

        if "mismatch" in failure_reason.lower():
            reasoning += "Причина: несоответствие заявленной и применяемой стратегии. "
            reasoning += (
                "Необходимо исправить domain_rules.json или изменить подход к тестированию."
            )
        elif retransmissions > 0:
            reasoning += f"Обнаружено {retransmissions} ретрансмиссий - стратегия неэффективна. "
            reasoning += "Нужно попробовать другие параметры или атаки."
        elif timeout:
            reasoning += "Тайм-аут соединения - возможно, стратегия слишком агрессивна. "
            reasoning += "Стоит попробовать более мягкие параметры."
        else:
            reasoning += f"Общая неудача: {failure_reason}"

        self.log_reasoning(
            step=ReasoningStep.FAILURE_ANALYSIS,
            domain=domain,
            iteration=iteration,
            reasoning=reasoning,
            decision={
                "failed_strategy": failed_strategy,
                "failure_reason": failure_reason,
                "next_action": "generate_alternative",
            },
            confidence=0.7,
            strategy_name=failed_strategy,
            input_data={
                "retransmissions": retransmissions,
                "timeout": timeout,
                "failure_reason": failure_reason,
            },
        )

    def log_strategy_generation(
        self,
        domain: str,
        iteration: int,
        generation_method: str,
        base_strategy: Optional[str],
        generated_strategies: List[Dict[str, Any]],
        generation_reasoning: str,
    ):
        """Логировать процесс генерации новых стратегий"""

        reasoning = f"Генерация стратегий методом '{generation_method}'. "
        reasoning += generation_reasoning
        reasoning += f" Сгенерировано {len(generated_strategies)} вариантов."

        if base_strategy:
            reasoning += f" Базовая стратегия: {base_strategy}."

        self.log_reasoning(
            step=ReasoningStep.STRATEGY_GENERATION,
            domain=domain,
            iteration=iteration,
            reasoning=reasoning,
            decision={
                "generation_method": generation_method,
                "base_strategy": base_strategy,
                "generated_count": len(generated_strategies),
                "strategies": [s.get("name", "unnamed") for s in generated_strategies],
            },
            confidence=0.6,
            input_data={
                "method": generation_method,
                "base": base_strategy,
                "strategies": generated_strategies,
            },
        )

    def log_parameter_optimization(
        self,
        domain: str,
        iteration: int,
        strategy_name: str,
        original_params: Dict[str, Any],
        optimized_params: Dict[str, Any],
        optimization_reason: str,
    ):
        """Логировать оптимизацию параметров"""

        changes = []
        for key, new_val in optimized_params.items():
            old_val = original_params.get(key)
            if old_val != new_val:
                changes.append(f"{key}: {old_val} → {new_val}")

        reasoning = f"Оптимизация параметров для {strategy_name}. "
        reasoning += optimization_reason
        if changes:
            reasoning += f" Изменения: {', '.join(changes)}"
        else:
            reasoning += " Параметры не изменились."

        self.log_reasoning(
            step=ReasoningStep.PARAMETER_OPTIMIZATION,
            domain=domain,
            iteration=iteration,
            reasoning=reasoning,
            decision={
                "strategy": strategy_name,
                "original_params": original_params,
                "optimized_params": optimized_params,
                "changes": changes,
            },
            confidence=0.7,
            strategy_name=strategy_name,
            input_data={"optimization_reason": optimization_reason, "param_changes": len(changes)},
        )

    def log_decision_making(
        self,
        domain: str,
        iteration: int,
        available_strategies: List[str],
        chosen_strategy: str,
        selection_criteria: str,
        alternatives_rejected: List[str],
    ):
        """Логировать процесс принятия решения о выборе стратегии"""

        reasoning = f"Выбор следующей стратегии из {len(available_strategies)} вариантов. "
        reasoning += f"Критерии выбора: {selection_criteria}. "
        reasoning += f"Выбрана: {chosen_strategy}. "

        if alternatives_rejected:
            reasoning += f"Отклонены: {', '.join(alternatives_rejected[:3])}"
            if len(alternatives_rejected) > 3:
                reasoning += f" и еще {len(alternatives_rejected) - 3}"

        self.log_reasoning(
            step=ReasoningStep.DECISION_MAKING,
            domain=domain,
            iteration=iteration,
            reasoning=reasoning,
            decision={
                "chosen_strategy": chosen_strategy,
                "selection_criteria": selection_criteria,
                "alternatives_count": len(available_strategies),
                "rejected_count": len(alternatives_rejected),
            },
            confidence=0.8,
            strategy_name=chosen_strategy,
            input_data={"available": available_strategies, "rejected": alternatives_rejected},
        )

    def log_learning_update(
        self,
        domain: str,
        iteration: int,
        successful_strategy: Optional[str],
        learned_insights: List[str],
        knowledge_updated: bool,
    ):
        """Логировать обновление базы знаний"""

        if successful_strategy:
            reasoning = f"Найдена рабочая стратегия: {successful_strategy}. "
            reasoning += "Обновляем базу знаний для будущих попыток. "
        else:
            reasoning = "Рабочая стратегия не найдена, но получены полезные данные. "

        if learned_insights:
            reasoning += f"Получены инсайты: {'; '.join(learned_insights)}. "

        if knowledge_updated:
            reasoning += "База знаний обновлена."
        else:
            reasoning += "База знаний не изменена."

        self.log_reasoning(
            step=ReasoningStep.LEARNING_UPDATE,
            domain=domain,
            iteration=iteration,
            reasoning=reasoning,
            decision={
                "successful_strategy": successful_strategy,
                "insights_count": len(learned_insights),
                "knowledge_updated": knowledge_updated,
            },
            confidence=0.9 if successful_strategy else 0.5,
            strategy_name=successful_strategy,
            input_data={"insights": learned_insights, "updated": knowledge_updated},
        )

    def end_session(self, success: bool = False, final_strategy: Optional[str] = None):
        """Завершить сессию и сохранить лог"""

        if not self.enabled or not self.current_session:
            return

        self.current_session["end_time"] = datetime.now().isoformat()
        self.current_session["success"] = success
        self.current_session["final_strategy"] = final_strategy
        # Convert entries to dict format with enum serialization
        entries_dict = []
        for entry in self.session_entries:
            entry_dict = asdict(entry)
            # Convert enum to string for JSON serialization
            entry_dict["step"] = entry.step.value
            entries_dict.append(entry_dict)

        self.current_session["entries"] = entries_dict

        # Сохранение в файл
        log_file = self.log_dir / f"reasoning_{self.current_session['session_id']}.json"
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(self.current_session, f, indent=2, ensure_ascii=False)

        self.logger.info(f"🧠 Session ended: {success}, saved to {log_file}")

        # Создание краткого отчета
        self._create_summary_report()

        self.current_session = None
        self.session_entries = []

    def _create_summary_report(self):
        """Создать краткий отчет по сессии"""

        if not self.current_session:
            return

        summary = {
            "session_id": self.current_session["session_id"],
            "domain": self.current_session["domain"],
            "success": self.current_session.get("success", False),
            "total_iterations": len(
                [e for e in self.session_entries if e.step == ReasoningStep.DECISION_MAKING]
            ),
            "strategies_tested": len(
                set(e.strategy_name for e in self.session_entries if e.strategy_name)
            ),
            "main_failure_reasons": [],
            "key_insights": [],
            "recommendations": [],
        }

        # Анализ основных причин неудач
        failure_entries = [
            e for e in self.session_entries if e.step == ReasoningStep.FAILURE_ANALYSIS
        ]
        for entry in failure_entries:
            reason = entry.input_data.get("failure_reason", "unknown")
            if reason not in summary["main_failure_reasons"]:
                summary["main_failure_reasons"].append(reason)

        # Ключевые инсайты
        learning_entries = [
            e for e in self.session_entries if e.step == ReasoningStep.LEARNING_UPDATE
        ]
        for entry in learning_entries:
            insights = entry.input_data.get("insights", [])
            summary["key_insights"].extend(insights)

        # Рекомендации
        if "mismatch" in str(summary["main_failure_reasons"]):
            summary["recommendations"].append("Исправить несоответствие в domain_rules.json")

        if summary["total_iterations"] > 5:
            summary["recommendations"].append("Улучшить алгоритм генерации стратегий")

        # Сохранение отчета
        summary_file = self.log_dir / f"summary_{self.current_session['session_id']}.json"
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)


# Глобальный экземпляр логгера
_reasoning_logger = None


def get_reasoning_logger() -> StrategyReasoningLogger:
    """Получить глобальный экземпляр логгера мыслительного процесса"""
    global _reasoning_logger
    if _reasoning_logger is None:
        _reasoning_logger = StrategyReasoningLogger()
    return _reasoning_logger


def enable_reasoning_logging(log_dir: str = "data/reasoning_logs") -> StrategyReasoningLogger:
    """Включить логирование мыслительного процесса"""
    global _reasoning_logger
    _reasoning_logger = StrategyReasoningLogger(enabled=True, log_dir=log_dir)
    return _reasoning_logger
