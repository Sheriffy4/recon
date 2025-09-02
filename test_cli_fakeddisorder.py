#!/usr/bin/env python3
"""
Тест CLI с fakeddisorder стратегией для проверки исправлений
"""

import subprocess
import sys
import time
import json
from pathlib import Path

def run_cli_test():
    """Запускает CLI тест с fakeddisorder стратегией."""
    
    print("🚀 ЗАПУСК CLI ТЕСТА С FAKEDDISORDER")
    print("=" * 50)
    
    # Команда для тестирования
    cmd = [
        "python", "cli.py", 
        "-d", "sites.txt",
        "--strategy", 
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64",
        "--pcap", "out.pcap"
    ]
    
    print(f"Команда: {' '.join(cmd)}")
    print("\nЗапуск...")
    
    try:
        # Запускаем команду
        result = subprocess.run(
            cmd,
            cwd=Path(__file__).parent,  # Текущая директория (recon)
            capture_output=True,
            text=True,
            timeout=300  # 5 минут максимум
        )
        
        print(f"\nВозвращенный код: {result.returncode}")
        
        if result.stdout:
            print("\nSTDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)
        
        # Проверяем на ошибку fakeddisorder
        if "Неизвестный тип задачи 'fakeddisorder'" in result.stderr:
            print("\n❌ ОШИБКА: Все еще появляется 'Неизвестный тип задачи fakeddisorder'")
            return False
        else:
            print("\n✅ Ошибка 'Неизвестный тип задачи fakeddisorder' НЕ появилась")
        
        # Ищем отчет
        report_files = list(Path(__file__).parent.glob("recon_report_*.json"))
        if report_files:
            latest_report = max(report_files, key=lambda x: x.stat().st_mtime)
            print(f"\nАнализ отчета: {latest_report}")
            
            with open(latest_report, 'r', encoding='utf-8') as f:
                report = json.load(f)
            
            success_rate = report.get('success_rate', 0)
            working_strategies = report.get('working_strategies_found', 0)
            
            print(f"Успешность: {success_rate}%")
            print(f"Рабочих стратегий: {working_strategies}")
            
            # Подсчитываем открытые домены
            domain_status = report.get('domain_status', {})
            working_domains = [domain for domain, status in domain_status.items() if status != 'BLOCKED']
            
            print(f"Открытых доменов: {len(working_domains)}")
            
            if len(working_domains) >= 15:
                print("🎉 ЦЕЛЬ ДОСТИГНУТА: 15+ доменов открыто!")
                return True
            else:
                print(f"⚠️ Цель не достигнута: {len(working_domains)} < 15 доменов")
                print("Открытые домены:", working_domains)
                return False
        else:
            print("❌ Отчет не найден")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ ТАЙМАУТ: Команда выполнялась слишком долго")
        return False
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        return False

if __name__ == "__main__":
    success = run_cli_test()
    sys.exit(0 if success else 1)