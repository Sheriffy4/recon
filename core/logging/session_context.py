from __future__ import annotations

from contextvars import ContextVar
from typing import Optional


_session_id_var: ContextVar[Optional[str]] = ContextVar("discovery_session_id", default=None)


class SessionContextProvider:
    """
    Session context via ContextVar:
    - Совместим с asyncio
    - Поддерживает многопоточность
    """

    def get_session_id(self) -> Optional[str]:
        return _session_id_var.get()

    def set_session_id(self, session_id: Optional[str]):
        return _session_id_var.set(session_id)

    def reset(self, token) -> None:
        _session_id_var.reset(token)


session_context = SessionContextProvider()


def get_session_context_provider() -> SessionContextProvider:
    """
    Get the global session context provider instance.

    Returns:
        SessionContextProvider instance
    """
    return session_context
