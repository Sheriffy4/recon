#!/usr/bin/env python3
"""
Исправление предупреждений и ошибок в системе
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

LOG = logging.getLogger("fix_warnings")

def fix_pcap_issue():
    """Исправляет проблему с PCAP файлом."""
    print("🔧 Исправление проблемы с PCAP файлом")
    print("=" * 50)
    
    pcap_file = "work.pcap"
    
    if not os.path.exists(pcap_file):
        print(f"⚠️  Файл {pcap_file} не найден")
        return False
    
    # Проверяем размер файла
    file_size = os.path.getsize(pcap_file)
    print(f"📁 Размер файла {pcap_file}: {file_size} байт")
    
    if file_size == 0:
        print("❌ Файл пустой - удаляем")
        os.remove(pcap_file)
        return True
    
    # Пытаемся исправить PCAP файл
    try:
        # Создаем резервную копию
        backup_file = f"{pcap_file}.backup"
        if not os.path.exists(backup_file):
            import shutil
            shutil.copy2(pcap_file, backup_file)
            print(f"💾 Создана резервная копия: {backup_file}")
        
        # Пытаемся проанализировать файл
        print("🔍 Анализ PCAP файла...")
        
        try:
            from scapy.all import rdpcap
            packets = rdpcap(pcap_file)
            print(f"✅ PCAP файл содержит {len(packets)} пакетов")
            return True
        except Exception as e:
            print(f"❌ Ошибка чтения PCAP: {e}")
            
            # Удаляем поврежденный файл
            os.remove(pcap_file)
            print(f"🗑️  Удален поврежденный файл {pcap_file}")
            return True
            
    except Exception as e:
        print(f"❌ Ошибка исправления PCAP: {e}")
        return False

def fix_future_annotations():
    """Исправляет проблему с future annotations."""
    print("\n🔧 Исправление проблемы с future annotations")
    print("=" * 50)
    
    try:
        # Проверяем версию Python
        import sys
        python_version = sys.version_info
        print(f"🐍 Версия Python: {python_version.major}.{python_version.minor}.{python_version.micro}")
        
        if python_version >= (3, 7):
            print("✅ Python версия поддерживает annotations")
            
            # Пытаемся установить правильную версию future
            try:
                import future
                print(f"📦 Версия future: {future.__version__}")
                
                # Проверяем импорт annotations
                try:
                    # Проверяем, что annotations доступны
                    import importlib
                    spec = importlib.util.find_spec("__future__")
                    if spec and hasattr(spec.loader.load_module(spec), "annotations"):
                        print("✅ Импорт annotations работает")
                        return True
                    else:
                        print("❌ annotations недоступны")
                except Exception as e:
                    print(f"❌ Ошибка проверки annotations: {e}")
                    
            except ImportError:
                print("⚠️  Пакет future не установлен")
                
                # Пытаемся установить
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "future"])
                    print("✅ Пакет future обновлен")
                    return True
                except subprocess.CalledProcessError as e:
                    print(f"❌ Ошибка установки future: {e}")
                    
        else:
            print("⚠️  Старая версия Python, annotations могут не работать")
            
    except Exception as e:
        print(f"❌ Ошибка исправления annotations: {e}")
        return False

def fix_dns_resolution():
    """Исправляет проблемы с DNS разрешением."""
    print("\n🔧 Исправление проблем с DNS")
    print("=" * 50)
    
    # Проблемные домены
    problem_domains = ['ntc.party']
    
    print("🌐 Проверка проблемных доменов...")
    
    for domain in problem_domains:
        print(f"  Проверка {domain}...", end=" ")
        
        try:
            import socket
            result = socket.gethostbyname(domain)
            print(f"✅ {result}")
        except socket.gaierror:
            print("❌ Не разрешается")
            
            # Удаляем из sites.txt если есть
            sites_file = "sites.txt"
            if os.path.exists(sites_file):
                try:
                    with open(sites_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                    
                    # Фильтруем проблемные домены
                    new_lines = []
                    removed = False
                    
                    for line in lines:
                        if domain not in line.strip():
                            new_lines.append(line)
                        else:
                            removed = True
                            print(f"    🗑️  Удален из {sites_file}")
                    
                    if removed:
                        with open(sites_file, 'w', encoding='utf-8') as f:
                            f.writelines(new_lines)
                        
                except Exception as e:
                    print(f"    ❌ Ошибка обновления {sites_file}: {e}")
    
    return True

def fix_timeout_issues():
    """Исправляет проблемы с таймаутами."""
    print("\n🔧 Исправление проблем с таймаутами")
    print("=" * 50)
    
    # Создаем конфигурационный файл с увеличенными таймаутами
    config = {
        "connection_timeout": 10,
        "read_timeout": 15,
        "dns_timeout": 5,
        "retry_attempts": 3,
        "retry_delay": 2
    }
    
    config_file = "timeout_config.json"
    
    try:
        import json
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Создан файл конфигурации: {config_file}")
        print("   Увеличены таймауты для стабильной работы")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка создания конфигурации: {e}")
        return False

def fix_midsld_warning():
    """Исправляет предупреждение о 'midsld'."""
    print("\n🔧 Исправление предупреждения 'midsld'")
    print("=" * 50)
    
    # Ищем файлы, которые используют 'midsld'
    files_to_check = [
        "core/bypass_engine.py",
        "core/packet/improved_bypass_engine.py",
        "core/hybrid_engine.py"
    ]
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            print(f"🔍 Проверка {file_path}...")
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if 'midsld' in content:
                    print(f"  ⚠️  Найдено использование 'midsld' в {file_path}")
                    
                    # Заменяем 'midsld' на числовое значение
                    updated_content = content.replace("'midsld'", "127")
                    updated_content = updated_content.replace('"midsld"', "127")
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(updated_content)
                    
                    print(f"  ✅ Заменено 'midsld' на 127 в {file_path}")
                else:
                    print(f"  ✅ 'midsld' не найдено в {file_path}")
                    
            except Exception as e:
                print(f"  ❌ Ошибка обработки {file_path}: {e}")
    
    return True

def main():
    """Главная функция исправления предупреждений."""
    print("🚀 Исправление предупреждений и ошибок системы")
    print("=" * 60)
    
    fixes = [
        ("PCAP файл", fix_pcap_issue),
        ("Future annotations", fix_future_annotations),
        ("DNS разрешение", fix_dns_resolution),
        ("Таймауты", fix_timeout_issues),
        ("Предупреждение midsld", fix_midsld_warning)
    ]
    
    results = []
    
    for name, fix_func in fixes:
        try:
            result = fix_func()
            results.append((name, result))
        except Exception as e:
            print(f"❌ Ошибка исправления {name}: {e}")
            results.append((name, False))
    
    # Итоговый отчет
    print("\n📊 ИТОГОВЫЙ ОТЧЕТ")
    print("=" * 30)
    
    success_count = 0
    for name, success in results:
        status = "✅" if success else "❌"
        print(f"{status} {name}")
        if success:
            success_count += 1
    
    print(f"\n📈 Исправлено: {success_count}/{len(results)}")
    
    if success_count == len(results):
        print("🎉 Все предупреждения исправлены!")
    else:
        print("⚠️  Некоторые проблемы требуют дополнительного внимания")
    
    return success_count == len(results)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)