# recon/core/bypass/attacks/registry.py (ФИНАЛЬНАЯ ВЕРСИЯ С АВТООБНАРУЖЕНИЕМ)

from __future__ import annotations
import inspect
import logging
import threading
from typing import Dict, Type, Optional, List, Any, Set

# Используем TYPE_CHECKING для импортов, нужных только для аннотаций
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .base import BaseAttack
    from ....integration.attack_adapter import AttackAdapter

LOG = logging.getLogger("AttackRegistry")

class AttackRegistry:
    """
    Централизованный реестр для всех классов атак с потокобезопасным
    автоматическим обнаружением и регистрацией.
    """
    # --- ИЗМЕНЕНИЕ 1: Добавляем все необходимые атрибуты класса ---
    _registry: Dict[str, Type["BaseAttack"]] = {}
    _categories: Dict[str, Set[str]] = {}
    _init_lock = threading.Lock()
    _initialized = False
    # --- КОНЕЦ ИЗМЕНЕНИЯ ---

    @classmethod
    def register(cls, attack_name: str, attack_class: Type["BaseAttack"]):
        """Регистрирует класс атаки с заданным именем."""
        with cls._init_lock:
            if attack_name in cls._registry:
                LOG.warning(f"Attack '{attack_name}' is being overwritten in the registry.")
            
            LOG.debug(f"Registering attack: '{attack_name}' -> {attack_class.__name__}")
            cls._registry[attack_name] = attack_class
            
            # Обновляем информацию о категориях
            category = getattr(attack_class, 'category', 'unknown')
            if category not in cls._categories:
                cls._categories[category] = set()
            cls._categories[category].add(attack_name)

    @classmethod
    def create(cls, attack_name: str) -> Optional["BaseAttack"]:
        """Создает экземпляр атаки по ее имени."""
        cls._ensure_initialized()
        attack_class = cls._registry.get(attack_name)
        if not attack_class:
            cls.logger.error(f"Attack class for '{attack_name}' not found in registry.")
            return None
        
        try:
            sig = inspect.signature(attack_class.__init__)
            if 'attack_adapter' in sig.parameters:
                # --- ИЗМЕНЕНИЕ: Используем АБСОЛЮТНЫЙ импорт ---
                from core.integration.attack_adapter import AttackAdapter
                # --- КОНЕЦ ИЗМЕНЕНИЯ ---
                adapter_instance = AttackAdapter()
                return attack_class(attack_adapter=adapter_instance)
            else:
                return attack_class()
        except Exception as e:
            cls.logger.error(f"Failed to create instance of '{attack_name}': {e}", exc_info=True)
            return None

    @classmethod
    def get(cls, attack_name: str) -> Optional[Type["BaseAttack"]]:
        """Возвращает класс атаки по имени."""
        cls._ensure_initialized()
        return cls._registry.get(attack_name)

    @classmethod
    def get_all(cls) -> Dict[str, Type["BaseAttack"]]:
        """Возвращает все зарегистрированные классы атак."""
        cls._ensure_initialized()
        return cls._registry.copy()

    @classmethod
    def get_by_category(cls, category: str) -> Dict[str, Type["BaseAttack"]]:
        """Возвращает атаки по категории."""
        cls._ensure_initialized()
        attack_names = cls._categories.get(category, set())
        return {name: cls._registry[name] for name in attack_names if name in cls._registry}

    @classmethod
    def get_categories(cls) -> List[str]:
        """Возвращает список всех уникальных категорий атак."""
        cls._ensure_initialized()
        return sorted(list(cls._categories.keys()))

    @classmethod
    def list_attacks(cls) -> List[str]:
        """Возвращает список имен всех зарегистрированных атак."""
        cls._ensure_initialized()
        return list(cls._registry.keys())

    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """Возвращает статистику по реестру."""
        cls._ensure_initialized()
        stats = {
            "total_attacks": len(cls._registry),
            "categories": {cat: len(attacks) for cat, attacks in cls._categories.items()},
        }
        return stats

    @classmethod
    def _ensure_initialized(cls):
        """Потокобезопасно гарантирует, что автообнаружение было запущено хотя бы раз."""
        if not cls._initialized:
            with cls._init_lock:
                # Double-check locking pattern
                if not cls._initialized:
                    cls._auto_discover_attacks()
                    cls._initialized = True

    @classmethod
    def _auto_discover_attacks(cls):
        """
        Автоматически обнаруживает и регистрирует все атаки, сканируя пакет.
        """
        import importlib
        import pkgutil
        from . import tcp, ip, tls, payload, http, tunneling, combo

        LOG.info("Auto-discovering and registering attacks...")
        packages_to_scan = [tcp, ip, tls, payload, http, tunneling, combo]

        for package in packages_to_scan:
            for _, module_name, _ in pkgutil.walk_packages(
                package.__path__, package.__name__ + "."
            ):
                try:
                    importlib.import_module(module_name)
                except ImportError as e:
                    LOG.error(f"Could not import attack module '{module_name}'. Error: {e}")
        
        LOG.info(f"Auto-discovery complete. Registered {len(cls._registry)} attacks.")

    @classmethod
    def clear(cls):
        """Очищает реестр (полезно для тестов)."""
        with cls._init_lock:
            cls._registry.clear()
            cls._categories.clear()
            cls._initialized = False

# --- Декоратор для регистрации ---
def register_attack(name: str):
    """Декоратор для автоматической регистрации класса атаки."""
    from .base import BaseAttack
    def decorator(attack_class: Type[BaseAttack]):
        AttackRegistry.register(name, attack_class)
        return attack_class
    return decorator