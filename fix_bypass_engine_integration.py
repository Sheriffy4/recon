#!/usr/bin/env python3
"""
Исправление интеграции bypass engine с исправленной fakeddisorder атакой.

Проблема: Bypass engine использует старые методы вместо зарегистрированной атаки.
Решение: Обновить bypass engine для использования registry.
"""

import logging
from pathlib import Path

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

def fix_bypass_engine_integration():
    """Исправление интеграции bypass engine с registry."""
    logger.info("🔧 Исправление интеграции bypass engine...")
    
    bypass_engine_path = Path("recon/core/bypass_engine.py")
    
    if not bypass_engine_path.exists():
        logger.error(f"❌ Файл не найден: {bypass_engine_path}")
        return False
    
    # Читаем текущий код
    with open(bypass_engine_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Ищем секцию с fakeddisorder
    old_fakeddisorder_code = '''                if task_type in ["fake_fakeddisorder", "fakedisorder", "fakeddisorder"]:
                    # Handle fakeddisorder attack with proper fooling support
                    self.logger.info(f"✅ Обрабатываем fakeddisorder атаку с параметрами: {params}")
                    self.logger.info(f"🔍 FAKEDDISORDER TTL: Using TTL={ttl} for fake packets")
                    
                    fooling_methods = params.get("fooling", [])
                    
                    # CRITICAL TTL FIX: Send fake packet first based on fooling method with correct TTL
                    if "badseq" in fooling_methods:
                        self.logger.info(f"📤 Sending fake packet with badseq, TTL={ttl}")
                        self._send_fake_packet_with_badseq(packet, w, ttl=ttl)
                    elif "md5sig" in fooling_methods:
                        self.logger.info(f"📤 Sending fake packet with md5sig, TTL={ttl}")
                        self._send_fake_packet_with_md5sig(packet, w, ttl=ttl)
                    elif "badsum" in fooling_methods:
                        self.logger.info(f"📤 Sending fake packet with badsum, TTL={ttl}")
                        self._send_fake_packet_with_badsum(packet, w, ttl=ttl)
                    else:
                        self.logger.info(f"📤 Sending standard fake packet, TTL={ttl}")
                        self._send_fake_packet(packet, w, ttl=ttl)
                    
                    # Apply fakeddisorder technique
                    segments = self.techniques.apply_fakeddisorder(
                        payload, 
                        params.get("split_pos", 76),
                        params.get("overlap_size", 1)  # Use correct overlap from strategy
                    )
                    success = self._send_segments(packet, w, segments)
                    self.logger.info(f"✅ Fakeddisorder атака выполнена, успех: {success}")'''
    
    # Новый код с использованием registry
    new_fakeddisorder_code = '''                if task_type in ["fake_fakeddisorder", "fakedisorder", "fakeddisorder"]:
                    # ИСПРАВЛЕНО: Используем зарегистрированную исправленную атаку
                    self.logger.info(f"✅ Обрабатываем ИСПРАВЛЕННУЮ fakeddisorder атаку с параметрами: {params}")
                    
                    try:
                        # Импортируем registry и создаем атаку
                        from core.bypass.attacks.registry import AttackRegistry
                        from core.bypass.attacks.tcp.fake_disorder_attack import create_fixed_fakeddisorder_from_config
                        from core.bypass.attacks.base import AttackContext
                        
                        # Создаем контекст атаки
                        context = AttackContext(
                            dst_ip=packet.dst_addr,
                            dst_port=packet.dst_port,
                            payload=payload,
                            domain=getattr(packet, 'domain', None)
                        )
                        
                        # Создаем исправленную атаку с параметрами из стратегии
                        attack = create_fixed_fakeddisorder_from_config(params)
                        
                        # Выполняем атаку
                        import asyncio
                        if hasattr(asyncio, '_get_running_loop') and asyncio._get_running_loop():
                            # Если уже в async контексте
                            result = await attack.execute(context)
                        else:
                            # Создаем новый event loop
                            result = asyncio.run(attack.execute(context))
                        
                        # Обрабатываем результат
                        if result.segments and len(result.segments) > 0:
                            # Отправляем сегменты через существующий механизм
                            success = self._send_attack_segments(packet, w, result.segments)
                            self.logger.info(f"✅ ИСПРАВЛЕННАЯ fakeddisorder атака выполнена, сегментов: {len(result.segments)}, успех: {success}")
                        else:
                            self.logger.warning("⚠️  ИСПРАВЛЕННАЯ fakeddisorder атака не создала сегментов")
                            success = False
                            
                    except Exception as e:
                        self.logger.error(f"❌ Ошибка в ИСПРАВЛЕННОЙ fakeddisorder атаке: {e}")
                        # Fallback к старой реализации
                        self.logger.info("🔄 Fallback к старой реализации fakeddisorder")
                        segments = self.techniques.apply_fakeddisorder(
                            payload, 
                            params.get("split_pos", 76),
                            params.get("overlap_size", 1)
                        )
                        success = self._send_segments(packet, w, segments)
                        self.logger.info(f"✅ Fallback fakeddisorder выполнена, успех: {success}")'''
    
    # Заменяем код
    if old_fakeddisorder_code in content:
        content = content.replace(old_fakeddisorder_code, new_fakeddisorder_code)
        logger.info("✅ Найден и заменен код fakeddisorder в bypass engine")
    else:
        logger.warning("⚠️  Не найден точный код fakeddisorder для замены")
        logger.info("🔍 Попробуем найти альтернативный паттерн...")
        
        # Альтернативный поиск
        if 'task_type in ["fake_fakeddisorder", "fakedisorder", "fakeddisorder"]' in content:
            logger.info("✅ Найден альтернативный паттерн fakeddisorder")
            # Добавляем метод для отправки сегментов атаки
            segments_method = '''
    def _send_attack_segments(self, packet, w, segments):
        """
        Отправка сегментов атаки через существующий механизм.
        
        Args:
            packet: Исходный пакет
            w: Writer для отправки
            segments: Список сегментов (payload, seq_offset, options)
            
        Returns:
            bool: Успешность отправки
        """
        try:
            for i, (segment_payload, seq_offset, options) in enumerate(segments):
                self.logger.debug(f"📤 Отправка сегмента {i+1}/{len(segments)}: {len(segment_payload)} байт, offset={seq_offset}")
                
                # Применяем опции сегмента
                ttl = options.get('ttl', 64)
                delay_ms = options.get('delay_ms', 0.0)
                is_fake = options.get('is_fake', False)
                
                # Создаем модифицированный пакет
                modified_packet = packet.copy() if hasattr(packet, 'copy') else packet
                
                # Применяем TTL
                if hasattr(modified_packet, 'ttl'):
                    modified_packet.ttl = ttl
                
                # Применяем payload
                if hasattr(modified_packet, 'payload'):
                    modified_packet.payload = segment_payload
                
                # Отправляем с задержкой
                if delay_ms > 0:
                    import time
                    time.sleep(delay_ms / 1000.0)
                
                # Отправляем пакет
                w.send(modified_packet)
                
                self.logger.debug(f"✅ Сегмент {i+1} отправлен: TTL={ttl}, fake={is_fake}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка отправки сегментов атаки: {e}")
            return False
'''
            
            # Добавляем метод в конец класса
            if 'def _send_attack_segments(' not in content:
                # Находим конец класса BypassEngine
                class_end_pattern = '\nclass '
                if class_end_pattern in content:
                    parts = content.split(class_end_pattern)
                    if len(parts) > 1:
                        # Вставляем метод перед следующим классом
                        parts[0] += segments_method
                        content = class_end_pattern.join(parts)
                        logger.info("✅ Добавлен метод _send_attack_segments")
                else:
                    # Добавляем в конец файла
                    content += segments_method
                    logger.info("✅ Добавлен метод _send_attack_segments в конец файла")
        else:
            logger.error("❌ Не найден код fakeddisorder для исправления")
            return False
    
    # Сохраняем исправленный файл
    with open(bypass_engine_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    logger.info(f"✅ Bypass engine исправлен: {bypass_engine_path}")
    return True

def main():
    """Основная функция исправления."""
    logger.info("🚀 Запуск исправления интеграции bypass engine...")
    
    success = fix_bypass_engine_integration()
    
    if success:
        logger.info("🎉 ИСПРАВЛЕНИЕ ЗАВЕРШЕНО УСПЕШНО!")
        logger.info("📋 Что исправлено:")
        logger.info("  - Bypass engine теперь использует зарегистрированную исправленную атаку")
        logger.info("  - Добавлен метод для отправки сегментов атаки")
        logger.info("  - Добавлен fallback к старой реализации при ошибках")
        logger.info("")
        logger.info("🔄 Следующие шаги:")
        logger.info("  1. Протестировать исправленный bypass engine")
        logger.info("  2. Запустить тест с реальными доменами")
        logger.info("  3. Проверить результаты")
    else:
        logger.error("❌ ИСПРАВЛЕНИЕ НЕ УДАЛОСЬ!")
        logger.info("🔧 Требуется ручное исправление bypass engine")
    
    return success

if __name__ == "__main__":
    main()