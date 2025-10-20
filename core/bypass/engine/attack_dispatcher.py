"""
Диспетчер атак DPI обхода.

Этот модуль содержит AttackDispatcher - центральный компонент для:
- Правильной маршрутизации каждого типа атаки к соответствующему обработчику
- Нормализации параметров атак
- Разрешения специальных значений параметров (cipher, sni, midsld)
- Обработки ошибок диспетчеризации
"""

import logging
import re
from typing import Dict, List, Tuple, Any, Optional

from ..attacks.attack_registry import AttackRegistry, get_attack_registry
from ..attacks.metadata import SpecialParameterValues, ValidationResult
from ..techniques.primitives import BypassTechniques


logger = logging.getLogger(__name__)


class AttackDispatcher:
    """
    Диспетчер для правильной маршрутизации атак DPI обхода.
    
    Заменяет единый блок диспетчеризации в base_engine.py на
    правильную систему с валидацией параметров и обработкой ошибок.
    """
    
    def __init__(self, techniques: BypassTechniques, attack_registry: AttackRegistry = None):
        """
        Инициализирует диспетчер атак.
        
        Args:
            techniques: Экземпляр BypassTechniques для выполнения атак
            attack_registry: Реестр атак (если None, используется глобальный)
        """
        self.techniques = techniques
        self.registry = attack_registry or get_attack_registry()
        
        logger.info("AttackDispatcher initialized")
    
    def dispatch_attack(self, 
                       task_type: str, 
                       params: Dict[str, Any], 
                       payload: bytes, 
                       packet_info: Dict[str, Any]) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Диспетчеризует атаку к правильному обработчику.
        
        Args:
            task_type: Тип атаки
            params: Параметры атаки
            payload: Данные пакета
            packet_info: Информация о пакете (адреса, порты и т.д.)
            
        Returns:
            Список кортежей (данные, смещение, опции) для отправки
            
        Raises:
            ValueError: Если тип атаки неизвестен или параметры невалидны
            RuntimeError: Если выполнение атаки не удалось
        """
        start_time = self._get_current_time()
        
        try:
            # 1. Нормализация типа атаки
            normalized_type = self._normalize_attack_type(task_type)
            
            # 2. Валидация параметров
            validation_result = self.registry.validate_parameters(normalized_type, params)
            if not validation_result.is_valid:
                raise ValueError(f"Invalid parameters for attack '{task_type}': {validation_result.error_message}")
            
            # Логируем предупреждения, если есть
            if validation_result.has_warnings():
                for warning in validation_result.warnings:
                    logger.warning(f"Attack '{task_type}' parameter warning: {warning}")
            
            # 3. Разрешение специальных параметров
            resolved_params = self._resolve_parameters(params, payload, packet_info)
            
            # 4. Получение обработчика
            handler = self.registry.get_attack_handler(normalized_type)
            if not handler:
                raise ValueError(f"No handler found for attack type '{normalized_type}'")
            
            # 5. Выполнение атаки
            recipe = handler(self.techniques, payload, **resolved_params)
            
            # 6. Валидация результата
            if not recipe or not isinstance(recipe, list):
                raise RuntimeError(f"Attack handler for '{normalized_type}' returned invalid recipe")
            
            execution_time = self._get_current_time() - start_time
            logger.info(f"✅ Attack '{task_type}' dispatched successfully in {execution_time:.3f}s, generated {len(recipe)} segments")
            
            return recipe
            
        except Exception as e:
            execution_time = self._get_current_time() - start_time
            logger.error(f"❌ Attack '{task_type}' dispatch failed after {execution_time:.3f}s: {e}")
            raise
    
    def _normalize_attack_type(self, task_type: str) -> str:
        """
        Нормализует тип атаки, разрешая алиасы.
        
        Args:
            task_type: Исходный тип атаки
            
        Returns:
            Нормализованный тип атаки
        """
        # Приводим к нижнему регистру и убираем лишние пробелы
        normalized = task_type.lower().strip()
        
        # Разрешаем алиасы через реестр
        resolved_type = self.registry._resolve_attack_type(normalized)
        
        logger.debug(f"Normalized attack type '{task_type}' -> '{resolved_type}'")
        return resolved_type
    
    def _resolve_parameters(self, 
                          params: Dict[str, Any], 
                          payload: bytes, 
                          packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Разрешает специальные значения параметров.
        
        Args:
            params: Исходные параметры
            payload: Данные пакета для анализа
            packet_info: Информация о пакете
            
        Returns:
            Параметры с разрешенными специальными значениями
        """
        resolved = params.copy()
        
        # Разрешаем split_pos
        if "split_pos" in resolved:
            resolved["split_pos"] = self._resolve_split_position(
                resolved["split_pos"], payload, packet_info
            )
        
        # Разрешаем positions для multisplit/multidisorder
        if "positions" in resolved:
            resolved["positions"] = [
                self._resolve_split_position(pos, payload, packet_info)
                for pos in resolved["positions"]
            ]
        
        # Устанавливаем значения по умолчанию для часто используемых параметров
        if "fake_ttl" not in resolved and "ttl" in resolved:
            resolved["fake_ttl"] = resolved["ttl"]
        elif "ttl" not in resolved and "fake_ttl" in resolved:
            resolved["ttl"] = resolved["fake_ttl"]
        
        if "fooling_methods" not in resolved and "fooling" in resolved:
            resolved["fooling_methods"] = resolved["fooling"]
        
        logger.debug(f"Resolved parameters: {resolved}")
        return resolved
    
    def _resolve_split_position(self, 
                              split_pos: Any, 
                              payload: bytes, 
                              packet_info: Dict[str, Any]) -> int:
        """
        Разрешает позицию разделения, включая специальные значения.
        
        Args:
            split_pos: Позиция разделения (int, str или специальное значение)
            payload: Данные пакета
            packet_info: Информация о пакете
            
        Returns:
            Разрешенная позиция как int
        """
        # Если уже int, возвращаем как есть
        if isinstance(split_pos, int):
            return max(1, min(split_pos, len(payload) - 1))
        
        # Если строка, пытаемся конвертировать в int
        if isinstance(split_pos, str):
            # Проверяем специальные значения
            if split_pos == SpecialParameterValues.CIPHER:
                return self._find_cipher_position(payload)
            elif split_pos == SpecialParameterValues.SNI:
                return self._find_sni_position(payload)
            elif split_pos == SpecialParameterValues.MIDSLD:
                return self._find_midsld_position(payload, packet_info)
            else:
                # Пытаемся конвертировать в int
                try:
                    return max(1, min(int(split_pos), len(payload) - 1))
                except ValueError:
                    logger.warning(f"Invalid split_pos value '{split_pos}', using default")
                    return len(payload) // 2
        
        # Fallback
        logger.warning(f"Unknown split_pos type {type(split_pos)}, using default")
        return len(payload) // 2
    
    def _find_cipher_position(self, payload: bytes) -> int:
        """
        Находит позицию начала TLS cipher suite в ClientHello.
        
        Args:
            payload: Данные пакета
            
        Returns:
            Позиция cipher suite или позицию по умолчанию
        """
        try:
            # Проверяем, что это TLS ClientHello
            if len(payload) < 43 or payload[0] != 0x16:
                return len(payload) // 2
            
            # Пропускаем TLS Record Header (5 bytes)
            # Пропускаем Handshake Header (4 bytes)
            # Пропускаем Version (2 bytes)
            # Пропускаем Random (32 bytes)
            pos = 43
            
            # Пропускаем Session ID
            if pos < len(payload):
                session_id_len = payload[pos]
                pos += 1 + session_id_len
            
            # Позиция Cipher Suites Length
            if pos + 2 <= len(payload):
                logger.debug(f"Found cipher position at {pos}")
                return pos
            
        except Exception as e:
            logger.warning(f"Failed to find cipher position: {e}")
        
        return len(payload) // 2
    
    def _find_sni_position(self, payload: bytes) -> int:
        """
        Находит позицию начала Server Name Indication в ClientHello.
        
        Args:
            payload: Данные пакета
            
        Returns:
            Позиция SNI или позицию по умолчанию
        """
        try:
            # Ищем SNI extension (тип 0x0000)
            sni_pattern = b'\x00\x00'  # SNI extension type
            
            # Ищем в TLS extensions
            pos = payload.find(sni_pattern, 40)  # Начинаем поиск после заголовков
            if pos != -1:
                logger.debug(f"Found SNI position at {pos}")
                return pos
            
        except Exception as e:
            logger.warning(f"Failed to find SNI position: {e}")
        
        return len(payload) // 2
    
    def _find_midsld_position(self, payload: bytes, packet_info: Dict[str, Any]) -> int:
        """
        Находит позицию середины второго уровня домена.
        
        Args:
            payload: Данные пакета
            packet_info: Информация о пакете
            
        Returns:
            Позиция середины SLD или позицию по умолчанию
        """
        try:
            # Пытаемся извлечь доменное имя из SNI
            domain = self._extract_domain_from_sni(payload)
            if not domain:
                return len(payload) // 2
            
            # Находим второй уровень домена
            parts = domain.split('.')
            if len(parts) >= 2:
                sld = parts[-2]  # Второй уровень домена
                mid_pos = len(sld) // 2
                
                # Ищем позицию этого домена в payload
                domain_bytes = domain.encode('utf-8')
                domain_pos = payload.find(domain_bytes)
                if domain_pos != -1:
                    # Вычисляем позицию середины SLD
                    sld_start = domain_pos + domain.rfind(sld)
                    result_pos = sld_start + mid_pos
                    logger.debug(f"Found midsld position at {result_pos} for domain {domain}")
                    return result_pos
            
        except Exception as e:
            logger.warning(f"Failed to find midsld position: {e}")
        
        return len(payload) // 2
    
    def _extract_domain_from_sni(self, payload: bytes) -> Optional[str]:
        """
        Извлекает доменное имя из SNI extension.
        
        Args:
            payload: Данные пакета
            
        Returns:
            Доменное имя или None
        """
        try:
            # Простой поиск SNI в TLS ClientHello
            # Ищем паттерн SNI extension
            for i in range(len(payload) - 10):
                if (payload[i:i+2] == b'\x00\x00' and  # SNI extension type
                    i + 9 < len(payload)):
                    
                    # Пропускаем заголовки extension
                    name_start = i + 9
                    if name_start < len(payload):
                        # Ищем длину имени
                        if name_start + 2 < len(payload):
                            name_len = int.from_bytes(payload[name_start:name_start+2], 'big')
                            if name_start + 2 + name_len <= len(payload):
                                domain = payload[name_start+2:name_start+2+name_len].decode('utf-8')
                                return domain
            
        except Exception as e:
            logger.debug(f"Failed to extract domain from SNI: {e}")
        
        return None
    
    def _get_current_time(self) -> float:
        """Возвращает текущее время для измерения производительности."""
        import time
        return time.time()


def create_attack_dispatcher(techniques: BypassTechniques) -> AttackDispatcher:
    """
    Удобная функция для создания AttackDispatcher.
    
    Args:
        techniques: Экземпляр BypassTechniques
        
    Returns:
        Настроенный AttackDispatcher
    """
    return AttackDispatcher(techniques)