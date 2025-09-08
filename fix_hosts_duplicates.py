#!/usr/bin/env python3
"""
Исправление дублирующихся IP в hosts файле
"""

import platform
import sys
from pathlib import Path

# Добавляем путь к модулям
sys.path.append(str(Path(__file__).parent))

from core.doh_resolver import DoHResolver
import asyncio

async def fix_hosts_duplicates():
    """Исправляет дублирующиеся IP в hosts файле."""
    
    print("🔧 Исправление дублирующихся IP в hosts файле")
    print("=" * 50)
    
    # Проблемные домены с одинаковыми IP
    domains_to_fix = ['rutracker.org', 'nnmclub.to']
    
    # Получаем реальные IP через DoH
    doh_resolver = DoHResolver()
    domain_ips = {}
    
    for domain in domains_to_fix:
        print(f"🌐 Получение реального IP для {domain}...", end=" ")
        
        try:
            ips = await doh_resolver.resolve_all(domain)
            if ips:
                # Берем первый IP, который не является подозрительным
                real_ip = None
                for ip in ips:
                    if not ip.startswith('172.67.182.196'):  # Исключаем подозрительный IP
                        real_ip = ip
                        break
                
                if real_ip:
                    domain_ips[domain] = real_ip
                    print(f"✅ {real_ip}")
                else:
                    print("❌ Только подозрительные IP")
            else:
                print("❌ IP не найден")
        except Exception as e:
            print(f"❌ Ошибка: {e}")
    
    await doh_resolver._cleanup()
    
    if not domain_ips:
        print("⚠️  Нет IP для исправления")
        return False
    
    # Обновляем hosts файл
    if platform.system().lower() == 'windows':
        hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    else:
        hosts_path = '/etc/hosts'
    
    try:
        # Читаем текущий hosts файл
        with open(hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        print(f"\n📝 Обновление hosts файла...")
        
        # Удаляем старые записи с подозрительным IP
        new_lines = []
        removed_count = 0
        
        for line in lines:
            line_stripped = line.strip()
            
            # Пропускаем строки с подозрительным IP для наших доменов
            skip_line = False
            if '172.67.182.196' in line_stripped:
                for domain in domains_to_fix:
                    if domain in line_stripped:
                        skip_line = True
                        removed_count += 1
                        print(f"  ❌ Удалена: {line_stripped}")
                        break
            
            if not skip_line:
                new_lines.append(line)
        
        # Добавляем новые записи с правильными IP
        new_lines.append(f"\n# Fixed duplicates - Real IPs from DoH\n")
        for domain, ip in domain_ips.items():
            entry = f"{ip:<15} {domain}\n"
            new_lines.append(entry)
            print(f"  ✅ Добавлена: {ip:<15} {domain}")
        
        # Записываем обновленный hosts файл
        with open(hosts_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        
        print(f"\n✅ Hosts файл обновлен!")
        print(f"   Удалено записей: {removed_count}")
        print(f"   Добавлено записей: {len(domain_ips)}")
        
        # Очищаем DNS кэш
        if platform.system().lower() == 'windows':
            import subprocess
            try:
                subprocess.run(['ipconfig', '/flushdns'], check=True, capture_output=True)
                print("✅ DNS кэш очищен")
            except:
                print("⚠️  Не удалось очистить DNS кэш")
        
        return True
        
    except PermissionError:
        print("❌ Нет прав для записи в hosts файл")
        print("   Запустите скрипт от имени администратора")
        return False
    except Exception as e:
        print(f"❌ Ошибка обновления hosts файла: {e}")
        return False

async def main():
    """Главная функция."""
    success = await fix_hosts_duplicates()
    
    if success:
        print(f"\n🎉 Исправление завершено успешно!")
        print(f"   Теперь rutracker.org и nnmclub.to используют реальные IP")
        print(f"   Перезапустите браузер для применения изменений")
    else:
        print(f"\n❌ Исправление не удалось")

if __name__ == '__main__':
    asyncio.run(main())