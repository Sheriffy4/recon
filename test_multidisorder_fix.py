#!/usr/bin/env python3
"""
Тест исправления multidisorder с параметром split_pos.
"""

import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def test_multidisorder_with_split_pos():
    """Тест multidisorder с параметром split_pos."""
    logger.info("=== Тестирование multidisorder с split_pos ===")
    
    try:
        from core.bypass.techniques.primitives import BypassTechniques
        from core.bypass.engine.attack_dispatcher import AttackDispatcher
        
        techniques = BypassTechniques()
        dispatcher = AttackDispatcher(techniques)
        
        # Тестовые данные - имитируем реальный случай из лога
        test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '216.58.207.206',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Параметры из реального лога ошибки
        params = {
            'split_pos': 1,
            'fooling': ['badseq'],
            'repeats': 1,
            'fake_ttl': 3,
            'overlap_size': 0,
            'tcp_flags': {'psh': True, 'ack': True},
            'window_div': 8,
            'ipid_step': 2048
        }
        
        logger.info(f"Тестирование multidisorder с параметрами: {params}")
        
        recipe = dispatcher.dispatch_attack(
            'multidisorder',
            params,
            test_payload,
            packet_info
        )
        
        if not recipe:
            logger.error("❌ multidisorder: пустой рецепт")
            return False
        
        if not isinstance(recipe, list):
            logger.error("❌ multidisorder: рецепт не является списком")
            return False
        
        # Проверяем структуру рецепта
        for i, segment in enumerate(recipe):
            if not isinstance(segment, tuple) or len(segment) != 3:
                logger.error(f"❌ multidisorder: неправильная структура сегмента {i}")
                return False
            
            data, offset, options = segment
            if not isinstance(data, bytes):
                logger.error(f"❌ multidisorder: данные сегмента {i} не bytes")
                return False
            
            if not isinstance(offset, int):
                logger.error(f"❌ multidisorder: смещение сегмента {i} не int")
                return False
            
            if not isinstance(options, dict):
                logger.error(f"❌ multidisorder: опции сегмента {i} не dict")
                return False
        
        logger.info(f"✅ multidisorder: {len(recipe)} сегментов сгенерировано успешно")
        
        # Выводим детали рецепта
        for i, (data, offset, options) in enumerate(recipe):
            is_fake = options.get('is_fake', False)
            fake_str = " (FAKE)" if is_fake else ""
            logger.info(f"  Сегмент {i}: {len(data)}b @ offset {offset}{fake_str}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ multidisorder тест не пройден: {e}")
        return False

def test_multidisorder_with_positions():
    """Тест multidisorder с параметром positions."""
    logger.info("=== Тестирование multidisorder с positions ===")
    
    try:
        from core.bypass.techniques.primitives import BypassTechniques
        from core.bypass.engine.attack_dispatcher import AttackDispatcher
        
        techniques = BypassTechniques()
        dispatcher = AttackDispatcher(techniques)
        
        test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '216.58.207.206',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Параметры с positions
        params = {
            'positions': [5, 10, 15],
            'fake_ttl': 3,
            'fooling': ['badseq']
        }
        
        logger.info(f"Тестирование multidisorder с параметрами: {params}")
        
        recipe = dispatcher.dispatch_attack(
            'multidisorder',
            params,
            test_payload,
            packet_info
        )
        
        if recipe:
            logger.info(f"✅ multidisorder с positions: {len(recipe)} сегментов сгенерировано")
            return True
        else:
            logger.error("❌ multidisorder с positions: пустой рецепт")
            return False
        
    except Exception as e:
        logger.error(f"❌ multidisorder с positions тест не пройден: {e}")
        return False

def main():
    """Главная функция тестирования."""
    logger.info("🚀 Запуск тестов исправления multidisorder")
    
    tests = [
        test_multidisorder_with_split_pos,
        test_multidisorder_with_positions
    ]
    
    passed = 0
    total = len(tests)
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                logger.error(f"Тест {test_func.__name__} не пройден")
        except Exception as e:
            logger.error(f"Тест {test_func.__name__} завершился с ошибкой: {e}")
    
    logger.info(f"📊 Результаты: {passed}/{total} тестов пройдено")
    
    if passed == total:
        logger.info("🎉 Все тесты пройдены успешно!")
        return 0
    else:
        logger.error("❌ Некоторые тесты не пройдены")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())