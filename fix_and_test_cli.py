#!/usr/bin/env python3
"""
Автоматическое исправление и тестирование CLI с fakeddisorder стратегией.
Цель: добиться открытия минимум 15 доменов.
"""

import subprocess
import sys
import os
import time
import logging
from pathlib import Path

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('fix_and_test.log')
    ]
)
logger = logging.getLogger(__name__)

class CLITester:
    def __init__(self):
        self.recon_dir = Path(__file__).parent
        self.sites_file = self.recon_dir / "sites.txt"
        self.pcap_file = self.recon_dir / "out.pcap"
        self.cli_script = self.recon_dir / "cli.py"
        
        # Стратегия из задания
        self.strategy = (
            "--dpi-desync=fake,fakeddisorder "
            "--dpi-desync-split-seqovl=1 "
            "--dpi-desync-autottl=2 "
            "--dpi-desync-fake-http=PAYLOADTLS "
            "--dpi-desync-fake-tls=PAYLOADTLS "
            "--dpi-desync-fooling=badseq,md5sig "
            "--dpi-desync-ttl=64"
        )
        
        self.min_domains = 15
        self.max_attempts = 5
        
    def run_cli_test(self) -> tuple[bool, str, int]:
        """Запускает CLI тест и возвращает результат."""
        logger.info("🚀 Запуск CLI теста...")
        
        # Удаляем старый PCAP файл
        if self.pcap_file.exists():
            self.pcap_file.unlink()
            
        # Формируем команду
        cmd = [
            sys.executable, str(self.cli_script),
            "-d", str(self.sites_file),
            "--strategy", self.strategy,
            "--pcap", str(self.pcap_file)
        ]
        
        logger.info(f"Команда: {' '.join(cmd)}")
        
        try:
            # Запускаем с таймаутом
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 минуты максимум
                cwd=self.recon_dir
            )
            
            logger.info(f"Код возврата: {result.returncode}")
            
            if result.stdout:
                logger.info(f"STDOUT:\n{result.stdout}")
            if result.stderr:
                logger.warning(f"STDERR:\n{result.stderr}")
                
            # Анализируем результат
            opened_domains = self.count_opened_domains(result.stdout, result.stderr)
            
            # Проверяем на ошибки
            has_errors = self.check_for_errors(result.stderr)
            
            return not has_errors and opened_domains >= self.min_domains, result.stderr, opened_domains
            
        except subprocess.TimeoutExpired:
            logger.error("❌ Тест превысил таймаут (120 сек)")
            return False, "Timeout", 0
        except Exception as e:
            logger.error(f"❌ Ошибка запуска теста: {e}")
            return False, str(e), 0
    
    def count_opened_domains(self, stdout: str, stderr: str) -> int:
        """Подсчитывает количество успешно открытых доменов."""
        opened_count = 0
        
        # Ищем в выводе признаки успешного открытия
        output = stdout + stderr
        lines = output.split('\n')
        
        for line in lines:
            # Различные паттерны успешного подключения
            if any(pattern in line.lower() for pattern in [
                'connection successful',
                'successfully connected',
                'bypass successful',
                'открыто успешно',
                'соединение установлено',
                'status: ok',
                'response: 200',
                'tls handshake complete'
            ]):
                opened_count += 1
                
        logger.info(f"📊 Обнаружено успешных подключений: {opened_count}")
        return opened_count
    
    def check_for_errors(self, stderr: str) -> bool:
        """Проверяет наличие критических ошибок."""
        error_patterns = [
            "Неизвестный тип задачи 'fakeddisorder'",
            "'NoneType' object has no attribute 'strip'",
            "Failed to create attack info for zapret_strategy"
        ]
        
        for pattern in error_patterns:
            if pattern in stderr:
                logger.error(f"❌ Обнаружена ошибка: {pattern}")
                return True
                
        return False
    
    def analyze_pcap(self) -> dict:
        """Анализирует PCAP файл для понимания проблем."""
        if not self.pcap_file.exists():
            logger.warning("⚠️ PCAP файл не найден")
            return {}
            
        logger.info("🔍 Анализ PCAP файла...")
        
        try:
            # Простой анализ размера файла
            file_size = self.pcap_file.stat().st_size
            logger.info(f"📁 Размер PCAP файла: {file_size} байт")
            
            if file_size == 0:
                logger.warning("⚠️ PCAP файл пустой - возможно, трафик не перехватывался")
                return {"empty": True}
            elif file_size < 1000:
                logger.warning("⚠️ PCAP файл очень маленький - мало трафика")
                return {"small": True, "size": file_size}
            else:
                logger.info("✅ PCAP файл содержит данные")
                return {"has_data": True, "size": file_size}
                
        except Exception as e:
            logger.error(f"❌ Ошибка анализа PCAP: {e}")
            return {"error": str(e)}
    
    def apply_fixes(self, attempt: int) -> bool:
        """Применяет исправления на основе анализа."""
        logger.info(f"🔧 Применение исправлений (попытка {attempt})...")
        
        fixes_applied = False
        
        # Исправление 1: Проверяем BypassEngine на поддержку fakeddisorder
        bypass_engine_path = self.recon_dir / "core" / "bypass_engine.py"
        if bypass_engine_path.exists():
            with open(bypass_engine_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Проверяем, есть ли обработка fakeddisorder
            if 'task_type == "fakeddisorder"' not in content:
                logger.info("🔧 Добавляем поддержку fakeddisorder в BypassEngine...")
                
                # Находим место для вставки
                if 'elif task_type == "multisplit":' in content:
                    old_code = 'elif task_type == "multisplit":'
                    new_code = '''elif task_type == "fakeddisorder":
                    # Handle fakeddisorder attack
                    fooling_methods = params.get("fooling", [])
                    
                    if "badsum" in fooling_methods:
                        self._send_fake_packet_with_badsum(packet, w, ttl=ttl if ttl else 1)
                    elif "md5sig" in fooling_methods:
                        self._send_fake_packet_with_md5sig(packet, w, ttl=ttl if ttl else 1)
                    else:
                        self._send_fake_packet(packet, w, ttl=ttl if ttl else 1)
                    
                    segments = self.techniques.apply_fakeddisorder(
                        payload, 
                        params.get("split_pos", 76),
                        params.get("overlap_size", 336)
                    )
                    success = self._send_segments(packet, w, segments)
                elif task_type == "multisplit":'''
                    
                    content = content.replace(old_code, new_code)
                    
                    with open(bypass_engine_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    fixes_applied = True
                    logger.info("✅ Поддержка fakeddisorder добавлена")
        
        # Исправление 2: Проверяем attack_mapping на ошибку с strip
        attack_mapping_path = self.recon_dir / "core" / "attack_mapping.py"
        if attack_mapping_path.exists():
            with open(attack_mapping_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Проверяем на проблемную строку
            if "getattr(attack_instance, '__doc__', f'{attack_name} attack').strip()" in content:
                logger.info("🔧 Исправляем ошибку с strip() в attack_mapping...")
                
                old_code = "description = getattr(attack_instance, '__doc__', f'{attack_name} attack').strip()"
                new_code = """doc_string = getattr(attack_instance, '__doc__', None)
            description = (doc_string or f'{attack_name} attack').strip()"""
                
                content = content.replace(old_code, new_code)
                
                with open(attack_mapping_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                fixes_applied = True
                logger.info("✅ Ошибка с strip() исправлена")
        
        return fixes_applied
    
    def run_test_cycle(self) -> bool:
        """Запускает полный цикл тестирования с исправлениями."""
        logger.info("🎯 Начало цикла тестирования...")
        
        for attempt in range(1, self.max_attempts + 1):
            logger.info(f"\n{'='*50}")
            logger.info(f"🔄 ПОПЫТКА {attempt}/{self.max_attempts}")
            logger.info(f"{'='*50}")
            
            # Применяем исправления перед каждой попыткой
            if attempt > 1:
                fixes_applied = self.apply_fixes(attempt)
                if fixes_applied:
                    logger.info("⏳ Ждем 2 секунды после применения исправлений...")
                    time.sleep(2)
            
            # Запускаем тест
            success, error_output, opened_domains = self.run_cli_test()
            
            logger.info(f"📊 Результат попытки {attempt}:")
            logger.info(f"   Успех: {'✅' if success else '❌'}")
            logger.info(f"   Открыто доменов: {opened_domains}/{self.min_domains}")
            
            if success:
                logger.info("🎉 ТЕСТ УСПЕШНО ПРОЙДЕН!")
                return True
            
            # Анализируем PCAP для понимания проблем
            pcap_analysis = self.analyze_pcap()
            logger.info(f"📁 Анализ PCAP: {pcap_analysis}")
            
            # Если не последняя попытка, ждем перед следующей
            if attempt < self.max_attempts:
                logger.info("⏳ Ждем 5 секунд перед следующей попыткой...")
                time.sleep(5)
        
        logger.error(f"❌ Все {self.max_attempts} попыток неудачны")
        return False


def main():
    """Главная функция."""
    logger.info("🚀 Запуск автоматического тестирования и исправления CLI")
    
    tester = CLITester()
    
    # Проверяем наличие необходимых файлов
    if not tester.sites_file.exists():
        logger.error(f"❌ Файл {tester.sites_file} не найден")
        return False
        
    if not tester.cli_script.exists():
        logger.error(f"❌ Файл {tester.cli_script} не найден")
        return False
    
    # Запускаем цикл тестирования
    success = tester.run_test_cycle()
    
    if success:
        logger.info("🎉 ЗАДАЧА ВЫПОЛНЕНА УСПЕШНО!")
        logger.info(f"✅ CLI работает корректно с fakeddisorder стратегией")
        logger.info(f"✅ Открыто минимум {tester.min_domains} доменов")
    else:
        logger.error("❌ ЗАДАЧА НЕ ВЫПОЛНЕНА")
        logger.error("Требуется дополнительный анализ и исправления")
    
    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)