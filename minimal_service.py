#!/usr/bin/env python3
"""
Минимальная служба обхода без зацикливания

Цель: Запустить простейший обход для тестирования CLI vs Service
"""

import sys
import time
import logging
import subprocess
import threading
from pathlib import Path

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)

logger = logging.getLogger("MinimalService")

class MinimalBypassService:
    """Минимальная служба обхода."""
    
    def __init__(self):
        self.running = False
        self.process = None
        
    def start(self):
        """Запуск службы через zapret."""
        
        logger.info("🚀 Запуск минимальной службы обхода...")
        
        try:
            # Проверяем наличие WinDivert
            windivert_dll = Path("WinDivert.dll")
            windivert_sys = Path("WinDivert64.sys")
            
            if not windivert_dll.exists() or not windivert_sys.exists():
                logger.error("❌ WinDivert файлы не найдены!")
                return False
            
            logger.info("✅ WinDivert файлы найдены")
            
            # Читаем стратегию для www.googlevideo.com
            import json
            rules_file = Path("domain_rules.json")
            
            if rules_file.exists():
                with open(rules_file, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
                
                googlevideo_rule = rules.get("domain_rules", {}).get("www.googlevideo.com")
                
                if googlevideo_rule:
                    logger.info(f"📋 Найдена стратегия для www.googlevideo.com:")
                    logger.info(f"   Тип: {googlevideo_rule.get('type', 'unknown')}")
                    logger.info(f"   Атаки: {googlevideo_rule.get('attacks', [])}")
                    logger.info(f"   Параметры: {googlevideo_rule.get('params', {})}")
                else:
                    logger.warning("⚠️ Стратегия для www.googlevideo.com не найдена")
            
            # Запускаем простой WinDivert фильтр
            logger.info("🔄 Запуск WinDivert фильтра...")
            
            # Используем простую команду zapret
            cmd = [
                sys.executable, "zapret.py",
                "--wf-tcp=443",
                "--wf-udp=443", 
                "--filter-tcp=443",
                "--dpi-desync=fake,disorder",
                "--dpi-desync-ttl=1",
                "--dpi-desync-fooling=badsum"
            ]
            
            logger.info(f"🔧 Команда: {' '.join(cmd)}")
            
            # Запускаем процесс
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.running = True
            logger.info("✅ Служба запущена")
            logger.info("🌐 Попробуйте открыть www.googlevideo.com в браузере")
            
            # Мониторим вывод
            def monitor_output():
                try:
                    for line in iter(self.process.stdout.readline, ''):
                        if line.strip():
                            logger.info(f"[ZAPRET] {line.strip()}")
                        if not self.running:
                            break
                except Exception as e:
                    logger.error(f"Ошибка мониторинга: {e}")
            
            # Запускаем мониторинг в отдельном потоке
            monitor_thread = threading.Thread(target=monitor_output, daemon=True)
            monitor_thread.start()
            
            # Ждем
            while self.running:
                time.sleep(1)
                
                # Проверяем что процесс еще жив
                if self.process.poll() is not None:
                    logger.error("❌ Процесс zapret завершился")
                    break
            
            return True
            
        except Exception as e:
            logger.error(f"💥 Ошибка запуска службы: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def stop(self):
        """Остановка службы."""
        logger.info("🛑 Остановка службы...")
        self.running = False
        
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                logger.info("✅ Процесс остановлен")
            except subprocess.TimeoutExpired:
                logger.warning("⚠️ Принудительная остановка процесса")
                self.process.kill()
                self.process.wait()
            except Exception as e:
                logger.error(f"⚠️ Ошибка остановки: {e}")

def main():
    """Main function."""
    
    service = MinimalBypassService()
    
    try:
        success = service.start()
        if not success:
            logger.error("❌ Не удалось запустить службу")
            return 1
    except KeyboardInterrupt:
        logger.info("⌨️ Получен сигнал прерывания")
    finally:
        service.stop()
        logger.info("👋 Служба завершена")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())