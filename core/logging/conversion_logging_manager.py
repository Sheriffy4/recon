from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from core.logging.conversion_state import ConversionState
from core.logging.logging_config import LoggingConfig


class ConversionLoggingManager:
    def __init__(self, config: LoggingConfig, logger: Optional[logging.Logger] = None):
        self._lock = threading.RLock()
        self._config = (config or LoggingConfig()).validate()
        self._logger = logger or logging.getLogger("AdaptiveEngine")

        # per-session state
        self._session_states: Dict[str, ConversionState] = {}

        # Старые сессии не нужны для долгого cleanup
        self._state_ttl = timedelta(hours=6)

    def update_config(self, new_config: LoggingConfig) -> None:
        with self._lock:
            self._config = (new_config or LoggingConfig()).validate()

    def reset_session(self, session_id: str) -> None:
        if not session_id:
            return
        with self._lock:
            self._session_states[session_id] = ConversionState()

    def cleanup_session(self, session_id: str) -> None:
        if not session_id:
            return
        with self._lock:
            self._session_states.pop(session_id, None)

    def _get_state(self, session_id: str) -> ConversionState:
        # session_id может быть None/"" и тогда используем общий ключ
        sid = session_id or "no_session"
        with self._lock:
            st = self._session_states.get(sid)
            if st is None:
                st = ConversionState()
                self._session_states[sid] = st
            return st

    def _maybe_cleanup_old_states(self) -> None:
        now = datetime.utcnow()
        with self._lock:
            to_delete = []
            for sid, st in self._session_states.items():
                if now - st.last_log_time > self._state_ttl:
                    to_delete.append(sid)
            for sid in to_delete:
                self._session_states.pop(sid, None)

    def should_log_conversion(self, session_id: Optional[str], strategy_key: str) -> bool:
        cfg = self._config
        if not cfg.enable_deduplication:
            return True

        st = self._get_state(session_id or "no_session")
        with self._lock:
            st.last_log_time = datetime.utcnow()
            if strategy_key in st.logged_strategies:
                return False
            st.logged_strategies.add(strategy_key)
            return True

    def log_conversion(
        self,
        session_id: Optional[str],
        strategy_key: str,
        details: Dict[str, Any],
        *,
        error: Optional[BaseException] = None,
    ) -> None:
        """
        Rules:
        - Ошибки логируем всегда (ERROR) независимо от dedupe/enable
        - DEBUG: показываем подробности и все повторения стратегий
        - INFO: показываем 1 строку на стратегию/сессию (dedupe on)
        - WARNING/ERROR: показываем минимально по настройкам
        """
        self._maybe_cleanup_old_states()
        cfg = self._config
        sid = session_id or None

        # 1) Errors всегда
        if error is not None or details.get("error"):
            msg = self._format_error(details, sid, strategy_key, error)
            self._logger.error(msg, exc_info=bool(error))
            return

        # 2) Если conversion logging отключено и не ошибочный случай
        if not cfg.enable_conversion_logging:
            return

        level = cfg.verbosity_level.upper()

        # 3) WARNING+ => ничего не показываем
        if level in {"WARNING", "ERROR", "CRITICAL"}:
            return

        # 4) DEBUG => всегда, подробно
        if level == "DEBUG":
            for line in self._format_detailed(details, sid, strategy_key):
                self._logger.debug(line)
            return

        # 5) INFO => dedupe + summary
        if not self.should_log_conversion(sid, strategy_key):
            return

        self._logger.info(self._format_summary(details, sid, strategy_key))

    def _session_suffix(self, session_id: Optional[str]) -> str:
        if self._config.include_session_context and session_id:
            # Можно: не каждый раз строить или сделать короче, например сокращение
            return f" (session: {session_id})"
        return ""

    def _format_summary(
        self, details: Dict[str, Any], session_id: Optional[str], strategy_key: str
    ) -> str:
        attacks = details.get("attacks")
        params = details.get("params")
        canonical = details.get("canonical")
        used_loader = details.get("used_loader")
        is_fallback = details.get("fallback")

        # Одна строка длиной 3-5 строк
        return (
            "[CONVERT] Конвертация стратегии: "
            f"attacks={attacks}, params={params}"
            f"; canonical={canonical}"
            f"; loader={'yes' if used_loader else 'no'}"
            f"; fallback={'yes' if is_fallback else 'no'}"
            f"; key={strategy_key[:12]}" + self._session_suffix(session_id)
        )

    def _format_detailed(
        self, details: Dict[str, Any], session_id: Optional[str], strategy_key: str
    ):
        attacks = details.get("attacks")
        params = details.get("params")
        canonical = details.get("canonical")
        result = details.get("result")

        yield (
            "[CONVERT] Конвертация стратегии: "
            f"attacks={attacks}, params={params}"
            f"; key={strategy_key}" + self._session_suffix(session_id)
        )
        if canonical is not None:
            yield "[CONVERT] Каноническая форма: " + str(canonical) + self._session_suffix(
                session_id
            )
        if result is not None:
            yield "[CONVERT] Результат: " + str(result) + self._session_suffix(session_id)

    def _format_error(
        self,
        details: Dict[str, Any],
        session_id: Optional[str],
        strategy_key: str,
        error: Optional[BaseException],
    ) -> str:
        attacks = details.get("attacks")
        params = details.get("params")
        canonical = details.get("canonical")
        err_txt = details.get("error") or (str(error) if error else "unknown error")
        return (
            "[CONVERT] Ошибка конвертации стратегии: "
            f"attacks={attacks}, params={params}; canonical={canonical}; "
            f"key={strategy_key[:12]}; error={err_txt}" + self._session_suffix(session_id)
        )
