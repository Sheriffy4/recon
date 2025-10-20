"""
Централизованный реестр всех атак DPI обхода.

Этот модуль предоставляет AttackRegistry - центральный компонент для:
- Регистрации всех доступных атак
- Валидации параметров атак
- Управления метаданными атак
- Автоматического обнаружения внешних модулей атак
"""

import logging
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass

from .metadata import AttackMetadata, AttackCategories, ValidationResult


logger = logging.getLogger(__name__)


class AttackRegistry:
    """Централизованный реестр всех атак DPI обхода."""
    
    def __init__(self):
        """Инициализирует реестр и регистрирует все доступные атаки."""
        self.attacks: Dict[str, Dict[str, Any]] = {}
        self._aliases: Dict[str, str] = {}
        
        # Регистрируем встроенные атаки
        self._register_builtin_attacks()
        
        # Автоматически обнаруживаем внешние атаки
        self._register_external_attacks()
        
        logger.info(f"AttackRegistry initialized with {len(self.attacks)} attacks")
    
    def register_attack(self, 
                       attack_type: str, 
                       handler: Callable, 
                       metadata: AttackMetadata) -> None:
        """
        Регистрирует новую атаку в реестре.
        
        Args:
            attack_type: Уникальный идентификатор типа атаки
            handler: Функция-обработчик атаки
            metadata: Метаданные атаки
        """
        if attack_type in self.attacks:
            logger.warning(f"Attack type '{attack_type}' already registered, overwriting")
        
        self.attacks[attack_type] = {
            'handler': handler,
            'metadata': metadata
        }
        
        # Регистрируем алиасы
        for alias in metadata.aliases:
            if alias in self._aliases:
                logger.warning(f"Alias '{alias}' already exists for '{self._aliases[alias]}', overwriting with '{attack_type}'")
            self._aliases[alias] = attack_type
        
        logger.debug(f"Registered attack '{attack_type}' with {len(metadata.aliases)} aliases")
    
    def get_attack_handler(self, attack_type: str) -> Optional[Callable]:
        """
        Возвращает обработчик для указанного типа атаки.
        
        Args:
            attack_type: Тип атаки или алиас
            
        Returns:
            Функция-обработчик или None если атака не найдена
        """
        # Разрешаем алиас в основной тип
        resolved_type = self._resolve_attack_type(attack_type)
        
        if resolved_type not in self.attacks:
            logger.error(f"Attack type '{attack_type}' not found in registry")
            return None
        
        return self.attacks[resolved_type]['handler']
    
    def get_attack_metadata(self, attack_type: str) -> Optional[AttackMetadata]:
        """
        Возвращает метаданные для указанного типа атаки.
        
        Args:
            attack_type: Тип атаки или алиас
            
        Returns:
            Метаданные атаки или None если атака не найдена
        """
        resolved_type = self._resolve_attack_type(attack_type)
        
        if resolved_type not in self.attacks:
            return None
        
        return self.attacks[resolved_type]['metadata']
    
    def validate_parameters(self, attack_type: str, params: Dict[str, Any]) -> ValidationResult:
        """
        Валидирует параметры для указанного типа атаки.
        
        Args:
            attack_type: Тип атаки
            params: Словарь параметров для валидации
            
        Returns:
            Результат валидации
        """
        metadata = self.get_attack_metadata(attack_type)
        if not metadata:
            return ValidationResult(
                is_valid=False,
                error_message=f"Unknown attack type: {attack_type}"
            )
        
        # Проверяем обязательные параметры
        for required_param in metadata.required_params:
            if required_param not in params:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Missing required parameter '{required_param}' for attack '{attack_type}'"
                )
        
        # Валидируем значения параметров
        return self._validate_parameter_values(attack_type, params, metadata)
    
    def list_attacks(self, category: Optional[str] = None) -> List[str]:
        """
        Возвращает список всех зарегистрированных атак.
        
        Args:
            category: Опциональная фильтрация по категории
            
        Returns:
            Список типов атак
        """
        if category is None:
            return list(self.attacks.keys())
        
        return [
            attack_type for attack_type, attack_data in self.attacks.items()
            if attack_data['metadata'].category == category
        ]
    
    def get_attack_aliases(self, attack_type: str) -> List[str]:
        """
        Возвращает все алиасы для указанного типа атаки.
        
        Args:
            attack_type: Тип атаки
            
        Returns:
            Список алиасов
        """
        resolved_type = self._resolve_attack_type(attack_type)
        
        if resolved_type not in self.attacks:
            return []
        
        return self.attacks[resolved_type]['metadata'].aliases
    
    def _resolve_attack_type(self, attack_type: str) -> str:
        """Разрешает алиас в основной тип атаки."""
        return self._aliases.get(attack_type, attack_type)
    
    def _register_builtin_attacks(self) -> None:
        """Регистрирует все встроенные атаки из primitives.py."""
        
        # fakeddisorder - основная атака с фейковым пакетом
        self.register_attack(
            "fakeddisorder",
            self._create_primitives_handler("apply_fakeddisorder"),
            AttackMetadata(
                name="Fake Disorder",
                description="Отправляет фейковый пакет с низким TTL, затем реальные части в обратном порядке",
                required_params=["split_pos"],
                optional_params={
                    "ttl": 3,
                    "fooling": ["badsum"],
                    "fake_sni": None,
                    "fake_data": None
                },
                aliases=["fake_disorder", "fakedisorder"],
                category=AttackCategories.FAKE
            )
        )
        
        # seqovl - sequence overlap атака
        self.register_attack(
            "seqovl",
            self._create_seqovl_handler(),
            AttackMetadata(
                name="Sequence Overlap",
                description="Отправляет фейковый пакет с перекрытием, затем полный реальный пакет",
                required_params=["split_pos", "overlap_size"],
                optional_params={
                    "fake_ttl": 3,
                    "fooling_methods": ["badsum"]
                },
                aliases=["seq_overlap", "overlap"],
                category=AttackCategories.OVERLAP
            )
        )
        
        # multidisorder - множественное разделение с disorder
        self.register_attack(
            "multidisorder",
            self._create_multidisorder_handler(),
            AttackMetadata(
                name="Multi Disorder",
                description="Разделяет пакет на несколько частей и отправляет в обратном порядке с фейковым пакетом",
                required_params=[],  # Не требуем обязательных параметров, обработчик сам разберется
                optional_params={
                    "positions": [1, 5, 10],
                    "split_pos": 3,
                    "fake_ttl": 3,
                    "fooling": ["badsum"]
                },
                aliases=["multi_disorder"],
                category=AttackCategories.DISORDER
            )
        )
        
        # disorder - простое разделение без фейкового пакета
        self.register_attack(
            "disorder",
            self._create_primitives_handler("apply_disorder"),
            AttackMetadata(
                name="Simple Disorder",
                description="Разделяет пакет на две части и отправляет в обратном порядке",
                required_params=["split_pos"],
                optional_params={
                    "ack_first": False
                },
                aliases=["simple_disorder"],
                category=AttackCategories.DISORDER
            )
        )
        
        # disorder2 - disorder с ack_first=True
        self.register_attack(
            "disorder2",
            self._create_disorder2_handler(),
            AttackMetadata(
                name="Disorder with ACK First",
                description="Разделяет пакет на две части и отправляет в обратном порядке с ACK флагом первым",
                required_params=["split_pos"],
                optional_params={},
                aliases=["disorder_ack"],
                category=AttackCategories.DISORDER
            )
        )
        
        # multisplit - множественное разделение
        self.register_attack(
            "multisplit",
            self._create_primitives_handler("apply_multisplit"),
            AttackMetadata(
                name="Multi Split",
                description="Разделяет пакет на несколько частей по указанным позициям",
                required_params=["positions"],
                optional_params={
                    "fooling": None
                },
                aliases=["multi_split"],
                category=AttackCategories.SPLIT
            )
        )
        
        # split - простое разделение (алиас для multisplit с одной позицией)
        self.register_attack(
            "split",
            self._create_split_handler(),
            AttackMetadata(
                name="Simple Split",
                description="Разделяет пакет на две части по указанной позиции",
                required_params=["split_pos"],
                optional_params={
                    "fooling": None
                },
                aliases=["simple_split"],
                category=AttackCategories.SPLIT
            )
        )
        
        # fake - фейковый пакет race condition
        self.register_attack(
            "fake",
            self._create_fake_handler(),
            AttackMetadata(
                name="Fake Packet Race",
                description="Отправляет фейковый пакет с низким TTL перед реальным",
                required_params=["ttl"],
                optional_params={
                    "fooling": ["badsum"],
                    "fake_data": None
                },
                aliases=["fake_race", "race"],
                category=AttackCategories.RACE
            )
        )
        
        logger.info("Registered all builtin attacks")
    
    def _create_primitives_handler(self, method_name: str) -> Callable:
        """Создает обработчик для метода из primitives.py."""
        def handler(techniques, payload: bytes, **params):
            method = getattr(techniques, method_name)
            return method(payload, **params)
        return handler
    
    def _create_disorder2_handler(self) -> Callable:
        """Создает специальный обработчик для disorder2."""
        def handler(techniques, payload: bytes, split_pos: int, **params):
            return techniques.apply_disorder(payload, split_pos, ack_first=True)
        return handler
    
    def _create_split_handler(self) -> Callable:
        """Создает обработчик для простого split (конвертирует в multisplit)."""
        def handler(techniques, payload: bytes, split_pos: int, **params):
            return techniques.apply_multisplit(payload, positions=[split_pos], **params)
        return handler
    
    def _create_seqovl_handler(self) -> Callable:
        """Создает специальный обработчик для seqovl с правильными параметрами."""
        def handler(techniques, payload: bytes, split_pos: int, overlap_size: int, **params):
            # Конвертируем параметры в правильный формат
            fake_ttl = params.get('fake_ttl', params.get('ttl', 3))
            fooling_methods = params.get('fooling_methods', params.get('fooling', ['badsum']))
            
            return techniques.apply_seqovl(
                payload, 
                split_pos, 
                overlap_size, 
                fake_ttl, 
                fooling_methods
            )
        return handler
    
    def _create_fake_handler(self) -> Callable:
        """Создает специальный обработчик для fake с правильными параметрами."""
        def handler(techniques, payload: bytes, **params):
            # Конвертируем параметры в правильный формат
            ttl = params.get('ttl', params.get('fake_ttl', 3))
            fooling = params.get('fooling', params.get('fooling_methods', ['badsum']))
            
            return techniques.apply_fake_packet_race(payload, ttl, fooling)
        return handler
    
    def _create_multidisorder_handler(self) -> Callable:
        """Создает специальный обработчик для multidisorder с правильными параметрами."""
        def handler(techniques, payload: bytes, **params):
            # Конвертируем параметры в правильный формат
            positions = params.get('positions')
            
            # Если positions не указан, но есть split_pos, создаем positions из split_pos
            if not positions and 'split_pos' in params:
                split_pos = params['split_pos']
                if isinstance(split_pos, (int, str)):
                    # Создаем несколько позиций на основе split_pos
                    if isinstance(split_pos, str):
                        try:
                            split_pos = int(split_pos)
                        except ValueError:
                            split_pos = len(payload) // 2
                    
                    # Создаем разумные позиции на основе split_pos
                    base_pos = max(1, min(split_pos, len(payload) - 1))
                    positions = []
                    
                    # Добавляем позиции до split_pos
                    if base_pos > 2:
                        positions.append(base_pos // 2)
                    
                    # Добавляем сам split_pos
                    positions.append(base_pos)
                    
                    # Добавляем позицию после split_pos
                    if base_pos < len(payload) - 2:
                        positions.append(min(base_pos + (base_pos // 2), len(payload) - 1))
                    
                    # Убираем дубликаты и сортируем
                    positions = sorted(list(set(positions)))
                    
                    logger.debug(f"Converted split_pos={split_pos} to positions={positions} for payload length {len(payload)}")
                else:
                    positions = [1, 5, 10]  # Значения по умолчанию
            elif not positions:
                positions = [1, 5, 10]  # Значения по умолчанию
            
            fake_ttl = params.get('fake_ttl', params.get('ttl', 3))
            fooling = params.get('fooling', params.get('fooling_methods', ['badsum']))
            
            return techniques.apply_multidisorder(payload, positions, fooling, fake_ttl)
        return handler
    
    def _register_external_attacks(self) -> None:
        """Автоматически обнаруживает и регистрирует внешние атаки."""
        attacks_dir = Path("core/bypass/attacks")
        
        if not attacks_dir.exists():
            logger.warning(f"Attacks directory {attacks_dir} does not exist")
            return
        
        for module_file in attacks_dir.glob("*.py"):
            if module_file.name.startswith("_") or module_file.name in ["attack_registry.py", "metadata.py"]:
                continue
            
            try:
                module_name = f"core.bypass.attacks.{module_file.stem}"
                module = importlib.import_module(module_name)
                
                # Поиск классов атак
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if self._is_attack_class(obj):
                        self._register_attack_class(obj)
                        
            except Exception as e:
                logger.warning(f"Failed to load attack module {module_file}: {e}")
        
        logger.info("Finished registering external attacks")
    
    def _is_attack_class(self, cls) -> bool:
        """Проверяет, является ли класс классом атаки."""
        return (
            hasattr(cls, 'attack_type') and
            hasattr(cls, 'execute') and
            hasattr(cls, 'get_metadata')
        )
    
    def _register_attack_class(self, attack_class) -> None:
        """Регистрирует класс атаки."""
        try:
            instance = attack_class()
            attack_type = instance.attack_type
            metadata = instance.get_metadata()
            
            def handler(techniques, payload: bytes, **params):
                return instance.execute(payload, **params)
            
            self.register_attack(attack_type, handler, metadata)
            logger.debug(f"Registered external attack class: {attack_class.__name__}")
            
        except Exception as e:
            logger.error(f"Failed to register attack class {attack_class.__name__}: {e}")
    
    def _validate_parameter_values(self, 
                                 attack_type: str, 
                                 params: Dict[str, Any], 
                                 metadata: AttackMetadata) -> ValidationResult:
        """Валидирует значения параметров для конкретного типа атаки."""
        
        # Валидация split_pos
        if "split_pos" in params:
            split_pos = params["split_pos"]
            if not isinstance(split_pos, (int, str)):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"split_pos must be int or str, got {type(split_pos)}"
                )
            
            # Проверяем специальные значения
            if isinstance(split_pos, str) and split_pos not in ["cipher", "sni", "midsld"]:
                try:
                    int(split_pos)
                except ValueError:
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Invalid split_pos value: {split_pos}"
                    )
        
        # Валидация positions для multisplit/multidisorder
        if "positions" in params:
            positions = params["positions"]
            if not isinstance(positions, list):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"positions must be a list, got {type(positions)}"
                )
            
            special_values = ["cipher", "sni", "midsld"]
            for pos in positions:
                if isinstance(pos, int):
                    if pos < 1:
                        return ValidationResult(
                            is_valid=False,
                            error_message=f"Position values must be >= 1, got {pos}"
                        )
                elif isinstance(pos, str):
                    if pos not in special_values:
                        try:
                            int(pos)  # Try to convert to int
                        except ValueError:
                            return ValidationResult(
                                is_valid=False,
                                error_message=f"Invalid position value: {pos}. Must be int or one of {special_values}"
                            )
                else:
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"All positions must be int or str, got {type(pos)}"
                    )
        
        # Валидация overlap_size для seqovl
        if "overlap_size" in params:
            overlap_size = params["overlap_size"]
            if not isinstance(overlap_size, int) or overlap_size < 0:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"overlap_size must be non-negative int, got {overlap_size}"
                )
        
        # Валидация ttl
        if "ttl" in params:
            ttl = params["ttl"]
            if not isinstance(ttl, int) or not (1 <= ttl <= 255):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"ttl must be int between 1 and 255, got {ttl}"
                )
        
        # Валидация fooling методов
        if "fooling" in params and params["fooling"] is not None:
            fooling = params["fooling"]
            if not isinstance(fooling, list):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"fooling must be a list, got {type(fooling)}"
                )
            
            valid_fooling_methods = ["badsum", "badseq", "badack", "datanoack", "hopbyhop"]
            for method in fooling:
                if method not in valid_fooling_methods:
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Invalid fooling method '{method}'. Valid methods: {valid_fooling_methods}"
                    )
        
        return ValidationResult(is_valid=True, error_message=None)


# Глобальный экземпляр реестра (singleton pattern)
_global_registry = None


def get_attack_registry() -> AttackRegistry:
    """
    Возвращает глобальный экземпляр AttackRegistry.
    
    Returns:
        Глобальный экземпляр AttackRegistry
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = AttackRegistry()
    return _global_registry


def register_attack(attack_type: str, handler: Callable, metadata: AttackMetadata) -> None:
    """
    Удобная функция для регистрации атаки в глобальном реестре.
    
    Args:
        attack_type: Тип атаки
        handler: Обработчик атаки
        metadata: Метаданные атаки
    """
    registry = get_attack_registry()
    registry.register_attack(attack_type, handler, metadata)


def get_attack_handler(attack_type: str) -> Optional[Callable]:
    """
    Удобная функция для получения обработчика атаки из глобального реестра.
    
    Args:
        attack_type: Тип атаки
        
    Returns:
        Обработчик атаки или None
    """
    registry = get_attack_registry()
    return registry.get_attack_handler(attack_type)


def validate_attack_parameters(attack_type: str, params: Dict[str, Any]) -> ValidationResult:
    """
    Удобная функция для валидации параметров атаки.
    
    Args:
        attack_type: Тип атаки
        params: Параметры для валидации
        
    Returns:
        Результат валидации
    """
    registry = get_attack_registry()
    return registry.validate_parameters(attack_type, params)