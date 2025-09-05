#!/usr/bin/env python3
"""
Тестирование исправленной реализации fakeddisorder атаки.

Цель: Проверить, что исправления работают корректно и дают результат 27/31 как zapret.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any

# Добавляем путь к модулям recon
sys.path.insert(0, str(Path(__file__).parent))

from core.bypass.attacks.tcp.fake_disorder_attack_fixed import (
    FixedFakeDisorderAttack,
    FixedFakeDisorderConfig,
    create_fixed_fakeddisorder_from_config
)
from core.bypass.attacks.base import AttackContext

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class FixedFakeDisorderTester:
    """Тестер исправленной fakeddisorder атаки."""
    
    def __init__(self):
        self.test_results = []
    
    async def test_basic_functionality(self):
        """Тест базовой функциональности."""
        logger.info("🧪 Тест 1: Базовая функциональность")
        
        # Конфигурация как в рабочем zapret
        config = FixedFakeDisorderConfig(
            split_pos=76,
            split_seqovl=336,
            ttl=1,
            autottl=2,
            fooling_methods=['md5sig', 'badsum', 'badseq'],
            fake_tls='PAYLOADTLS'
        )
        
        attack = FixedFakeDisorderAttack(config=config)
        
        # Тестовый payload (TLS ClientHello)
        test_payload = self._create_test_tls_payload()
        
        # Создаем контекст
        context = AttackContext(
            dst_ip="8.8.8.8",
            dst_port=443,
            payload=test_payload,
            domain="google.com"
        )
        
        # Выполняем атаку
        result = await attack.execute(context)
        
        # Проверяем результат
        success = (
            result.status.name == "SUCCESS" and
            result.packets_sent == 3 and  # fake + part2 + part1
            len(result.segments) == 3
        )
        
        logger.info(f"✅ Тест 1 результат: {'УСПЕХ' if success else 'ПРОВАЛ'}")
        logger.info(f"   Статус: {result.status.name}")
        logger.info(f"   Пакетов: {result.packets_sent}")
        logger.info(f"   Сегментов: {len(result.segments) if result.segments else 0}")
        
        self.test_results.append({
            "test": "basic_functionality",
            "success": success,
            "details": {
                "status": result.status.name,
                "packets_sent": result.packets_sent,
                "segments_count": len(result.segments) if result.segments else 0,
                "metadata": result.metadata
            }
        })
        
        return success
    
    async def test_autottl_functionality(self):
        """Тест AutoTTL функциональности."""
        logger.info("🧪 Тест 2: AutoTTL функциональность")
        
        config = FixedFakeDisorderConfig(
            split_pos=76,
            split_seqovl=336,
            ttl=1,
            autottl=3,  # Тестируем диапазон 1-3
            fooling_methods=['md5sig', 'badsum', 'badseq']
        )
        
        attack = FixedFakeDisorderAttack(config=config)
        test_payload = self._create_test_tls_payload()
        
        context = AttackContext(
            dst_ip="8.8.8.8",
            dst_port=443,
            payload=test_payload,
            domain="google.com"
        )
        
        # Тестируем AutoTTL
        result = await attack.execute_with_zapret_autottl(context)
        
        success = (
            result.status.name == "SUCCESS" and
            "zapret_autottl_tested" in result.metadata and
            "zapret_best_ttl" in result.metadata
        )
        
        logger.info(f"✅ Тест 2 результат: {'УСПЕХ' if success else 'ПРОВАЛ'}")
        if success:
            logger.info(f"   Лучший TTL: {result.metadata.get('zapret_best_ttl')}")
            logger.info(f"   Диапазон: {result.metadata.get('zapret_autottl_range')}")
        
        self.test_results.append({
            "test": "autottl_functionality",
            "success": success,
            "details": {
                "status": result.status.name,
                "best_ttl": result.metadata.get('zapret_best_ttl'),
                "autottl_range": result.metadata.get('zapret_autottl_range'),
                "total_tests": result.metadata.get('zapret_total_tests')
            }
        })
        
        return success
    
    async def test_config_integration(self):
        """Тест интеграции с существующей конфигурацией."""
        logger.info("🧪 Тест 3: Интеграция конфигурации")
        
        # Конфигурация в формате recon
        recon_config = {
            'split_pos': 76,
            'overlap_size': 336,  # Используем overlap_size как в recon
            'ttl': 1,
            'autottl': 2,
            'fooling': ['md5sig', 'badsum', 'badseq'],
            'fake_tls': 'PAYLOADTLS'
        }
        
        # Создаем атаку через функцию интеграции
        attack = create_fixed_fakeddisorder_from_config(recon_config)
        test_payload = self._create_test_tls_payload()
        
        context = AttackContext(
            dst_ip="8.8.8.8",
            dst_port=443,
            payload=test_payload,
            domain="google.com"
        )
        
        result = await attack.execute(context)
        
        success = (
            result.status.name == "SUCCESS" and
            result.metadata.get('attack_type') == 'fixed_fake_disorder_zapret'
        )
        
        logger.info(f"✅ Тест 3 результат: {'УСПЕХ' if success else 'ПРОВАЛ'}")
        logger.info(f"   Тип атаки: {result.metadata.get('attack_type')}")
        
        self.test_results.append({
            "test": "config_integration",
            "success": success,
            "details": {
                "status": result.status.name,
                "attack_type": result.metadata.get('attack_type'),
                "config_used": recon_config
            }
        })
        
        return success
    
    async def test_segment_structure(self):
        """Тест структуры создаваемых сегментов."""
        logger.info("🧪 Тест 4: Структура сегментов")
        
        config = FixedFakeDisorderConfig(
            split_pos=76,
            split_seqovl=336,
            ttl=1,
            fooling_methods=['md5sig', 'badsum', 'badseq']
        )
        
        attack = FixedFakeDisorderAttack(config=config)
        test_payload = self._create_test_tls_payload()
        
        context = AttackContext(
            dst_ip="8.8.8.8",
            dst_port=443,
            payload=test_payload,
            domain="google.com"
        )
        
        result = await attack.execute(context)
        
        # Проверяем структуру сегментов
        segments_valid = False
        if result.segments and len(result.segments) == 3:
            fake_segment = result.segments[0]
            part2_segment = result.segments[1]
            part1_segment = result.segments[2]
            
            # Проверяем fake сегмент
            fake_valid = (
                fake_segment[2].get('is_fake') == True and
                fake_segment[2].get('ttl') in [1, 2] and  # TTL 1 или 2 (autottl)
                'corrupt_tcp_checksum' in fake_segment[2]  # badsum
            )
            
            # Проверяем реальные сегменты
            part2_valid = (
                part2_segment[2].get('is_real') == True and
                part2_segment[2].get('ttl') == 64
            )
            
            part1_valid = (
                part1_segment[2].get('is_real') == True and
                part1_segment[2].get('ttl') == 64
            )
            
            segments_valid = fake_valid and part2_valid and part1_valid
        
        logger.info(f"✅ Тест 4 результат: {'УСПЕХ' if segments_valid else 'ПРОВАЛ'}")
        if segments_valid:
            logger.info(f"   Fake TTL: {result.segments[0][2].get('ttl')}")
            logger.info(f"   Real TTL: {result.segments[1][2].get('ttl')}")
            logger.info(f"   Fooling методы применены: {len([k for k in result.segments[0][2].keys() if 'corrupt' in k or 'md5sig' in k])}")
        
        self.test_results.append({
            "test": "segment_structure",
            "success": segments_valid,
            "details": {
                "segments_count": len(result.segments) if result.segments else 0,
                "fake_segment_valid": segments_valid,
                "segment_details": [
                    {
                        "payload_size": len(seg[0]),
                        "seq_offset": seg[1],
                        "options_keys": list(seg[2].keys())
                    } for seg in result.segments
                ] if result.segments else []
            }
        })
        
        return segments_valid
    
    def _create_test_tls_payload(self) -> bytes:
        """Создание тестового TLS ClientHello payload."""
        return (
            b'\x16\x03\x01\x00\xc4\x01\x00\x00\xc0\x03\x03\x52\x34\x9d\x9b\x6d\xd5\xba\x58'
            b'\x2e\xcc\x47\xb0\x55\x1f\xf6\xb4\x47\x9b\x94\xfc\xc0\x1e\x76\x19\xc6\xd3\x0c'
            b'\x4e\x76\x4d\x83\x5e\x8c\x91\x00\x00\x66\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00'
            b'\x39\x00\x38\x00\x88\x00\x87\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08'
            b'\xc0\x1c\xc0\x1b\x00\x16\x00\x13\xc0\x0d\xc0\x03\x00\x0a\xc0\x13\xc0\x09\xc0'
            b'\x1f\xc0\x1e\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x0e\xc0\x04'
            b'\x00\x2f\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00'
            b'\x15\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x00\xff\x01\x00'
            b'\x00\x49\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x34\x00\x32\x00\x0e\x00'
            b'\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08'
            b'\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00'
            b'\x02\x00\x03\x00\x0f\x00\x10\x00\x11\x00\x23\x00\x00\x00\x0f\x00\x01\x01'
        )
    
    async def run_all_tests(self):
        """Запуск всех тестов."""
        logger.info("🚀 Запуск всех тестов исправленной fakeddisorder атаки...")
        
        tests = [
            self.test_basic_functionality,
            self.test_autottl_functionality,
            self.test_config_integration,
            self.test_segment_structure
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                success = await test()
                if success:
                    passed += 1
            except Exception as e:
                logger.error(f"❌ Ошибка в тесте: {e}")
        
        # Сводка результатов
        logger.info("📊 СВОДКА ТЕСТИРОВАНИЯ:")
        logger.info(f"   Пройдено: {passed}/{total} тестов")
        logger.info(f"   Успешность: {passed/total*100:.1f}%")
        
        if passed == total:
            logger.info("✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ! Исправленная реализация готова.")
        else:
            logger.warning(f"⚠️  {total-passed} тестов провалились. Требуются дополнительные исправления.")
        
        # Сохраняем результаты
        results_path = Path("recon/FIXED_FAKEDDISORDER_TEST_RESULTS.json")
        with open(results_path, 'w', encoding='utf-8') as f:
            json.dump({
                "summary": {
                    "total_tests": total,
                    "passed_tests": passed,
                    "success_rate": passed/total*100,
                    "all_passed": passed == total
                },
                "test_results": self.test_results
            }, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Результаты сохранены: {results_path}")
        
        return passed == total

async def main():
    """Основная функция тестирования."""
    logger.info("🔧 Тестирование исправленной fakeddisorder реализации...")
    
    tester = FixedFakeDisorderTester()
    all_passed = await tester.run_all_tests()
    
    if all_passed:
        logger.info("🎉 ИСПРАВЛЕНИЯ УСПЕШНЫ! Готово к интеграции в основной код.")
        logger.info("📋 Следующие шаги:")
        logger.info("  1. Заменить оригинальную реализацию на исправленную")
        logger.info("  2. Протестировать с реальными доменами")
        logger.info("  3. Сравнить результаты с zapret (ожидается 27/31)")
    else:
        logger.error("❌ Некоторые тесты провалились. Требуются дополнительные исправления.")
    
    return all_passed

if __name__ == "__main__":
    asyncio.run(main())