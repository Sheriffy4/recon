from __future__ import annotations
import inspect
import logging
import threading
from typing import Dict, Type, Optional, List, Any, Set
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from recon.core.bypass.attacks.base import BaseAttack
LOG = logging.getLogger('AttackRegistry')

class AttackRegistry:
    """
    Централизованный реестр для всех классов атак с потокобезопасным
    доступом. Атаки регистрируются с помощью декоратора @register_attack.
    """
    _registry: Dict[str, Type['BaseAttack']] = {}
    _categories: Dict[str, Set[str]] = {}
    _lock = threading.Lock()
    logger = LOG

    @classmethod
    def register(cls, attack_name: str, attack_class: Type['BaseAttack']):
        """Регистрирует класс атаки с заданным именем."""
        with cls._lock:
            if attack_name in cls._registry:
                cls.logger.warning(f"Attack '{attack_name}' is being overwritten in the registry.")
            cls.logger.debug(f"Registering attack: '{attack_name}' -> {attack_class.__name__}")
            cls._registry[attack_name] = attack_class
            try:
                instance = attack_class()
                category = getattr(instance, 'category', 'unknown')
            except Exception:
                category = 'unknown'
            if category not in cls._categories:
                cls._categories[category] = set()
            cls._categories[category].add(attack_name)

    @classmethod
    def create(cls, attack_name: str) -> Optional['BaseAttack']:
        """Создает экземпляр атаки по ее имени."""
        attack_class = cls._registry.get(attack_name)
        if not attack_class:
            cls.logger.error(f"Attack class for '{attack_name}' not found in registry.")
            return None
        try:
            sig = inspect.signature(attack_class.__init__)
            if 'attack_adapter' in sig.parameters:
                from recon.integration.attack_adapter import AttackAdapter
                adapter_instance = AttackAdapter()
                return attack_class(attack_adapter=adapter_instance)
            else:
                return attack_class()
        except Exception as e:
            cls.logger.error(f"Failed to create instance of '{attack_name}': {e}", exc_info=True)
            return None

    @classmethod
    def get(cls, attack_name: str) -> Optional[Type['BaseAttack']]:
        """Возвращает класс атаки по имени."""
        return cls._registry.get(attack_name)

    @classmethod
    def get_all(cls) -> Dict[str, Type['BaseAttack']]:
        """Возвращает все зарегистрированные классы атак."""
        return cls._registry.copy()

    @classmethod
    def get_by_category(cls, category: str) -> Dict[str, Type['BaseAttack']]:
        """Возвращает атаки по категории."""
        attack_names = cls._categories.get(category, set())
        return {name: cls._registry[name] for name in attack_names if name in cls._registry}

    @classmethod
    def get_categories(cls) -> List[str]:
        """Возвращает список всех уникальных категорий атак."""
        return sorted(list(cls._categories.keys()))

    @classmethod
    def list_attacks(cls) -> List[str]:
        """Возвращает список имен всех зарегистрированных атак."""
        return list(cls._registry.keys())

    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """Возвращает статистику по реестру."""
        return {'total_attacks': len(cls._registry), 'categories': {cat: len(attacks) for cat, attacks in cls._categories.items()}}

    @classmethod
    def clear(cls):
        """Очищает реестр (полезно для тестов)."""
        with cls._lock:
            cls._registry.clear()
            cls._categories.clear()

def register_attack(arg=None):
    """
    Декоратор для автоматической регистрации класса атаки.
    Может использоваться как @register_attack или @register_attack("custom_name").
    """

    def decorator(attack_class: Type[BaseAttack]):
        """Внутренний декоратор, который выполняет регистрацию."""
        try:
            name_to_register = None
            if isinstance(arg, str):
                name_to_register = arg
            else:
                try:
                    instance = attack_class()
                    name_to_register = instance.name
                except TypeError:
                    LOG.error(f"Cannot determine name for {attack_class.__name__}. Use @register_attack('attack_name') or ensure a parameterless constructor.")
            if name_to_register:
                AttackRegistry.register(name_to_register, attack_class)
        except Exception as e:
            LOG.error(f'Could not register attack class {attack_class.__name__}: {e}', exc_info=True)
            raise
        return attack_class
    if callable(arg):
        return decorator(arg)
    else:
        return decorator