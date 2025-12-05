#!/usr/bin/env python3
"""
Быстрый тест обхода DPI с доступными сайтами.
"""

import sys
import time
import threading
import requests
import subprocess

# Добавляем путь к проекту
sys.path.insert(0, '.')

def test_with_recon_service():
    """Тестирует обход через recon_service."""
    
    print("🚀 Тест через recon_service")
    print("=" * 40)
    
    # Запускаем recon_service в фоне
    print("📡 Запуск recon_service...")
    
    try:
        # Запускаем процесс
        process = subprocess.Popen(
            [sys.executable, "recon_service.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Даем время запуститься
        time.sleep(5)
        
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            print(f"❌ recon_service завершился с кодом {process.returncode}")
            print(f"Вывод: {stdout}")
            print(f"Ошибки: {stderr}")
            return False
        
        print("✅ recon_service запущен")
        
        # Тестируем подключения
        test_sites = [
            "https://httpbin.org/get",
            "https://github.com",
            "https://google.com",
            "https://rutracker.org"
        ]
        
        results = []
        
        for url in test_sites:
            print(f"\n🔍 Тестирование {url}")
            
            try:
                start_time = time.time()
                response = requests.get(url, timeout=10, allow_redirects=False)
                end_time = time.time()
                
                print(f"   ✅ HTTP {response.status_code} ({end_time - start_time:.2f}s)")
                results.append((url, True, response.status_code, end_time - start_time))
                
            except Exception as e:
                end_time = time.time()
                print(f"   ❌ Ошибка: {e} ({end_time - start_time:.2f}s)")
                results.append((url, False, 0, end_time - start_time))
        
        # Останавливаем процесс
        print(f"\n🛑 Остановка recon_service...")
        process.terminate()
        
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        
        # Анализ результатов
        print(f"\n📊 РЕЗУЛЬТАТЫ:")
        successful = 0
        
        for url, success, status, duration in results:
            if success:
                print(f"✅ {url} - HTTP {status} ({duration:.2f}s)")
                successful += 1
            else:
                print(f"❌ {url} - Ошибка ({duration:.2f}s)")
        
        print(f"\nУспешных: {successful}/{len(results)}")
        
        # Специальная проверка rutracker
        rutracker_result = next((r for r in results if 'rutracker' in r[0]), None)
        if rutracker_result:
            if rutracker_result[1]:  # success
                print(f"🎯 RUTRACKER: ✅ Обход работает!")
            else:
                print(f"🎯 RUTRACKER: ❌ Обход не помог")
        
        return successful > 0
        
    except Exception as e:
        print(f"❌ Ошибка запуска recon_service: {e}")
        return False

def test_without_bypass():
    """Тестирует подключения без обхода."""
    
    print("\n🔧 Тест БЕЗ обхода (для сравнения)")
    print("=" * 40)
    
    test_sites = [
        "https://httpbin.org/get",
        "https://github.com", 
        "https://google.com",
        "https://rutracker.org"
    ]
    
    results = []
    
    for url in test_sites:
        print(f"🔍 {url}")
        
        try:
            start_time = time.time()
            response = requests.get(url, timeout=5, allow_redirects=False)
            end_time = time.time()
            
            print(f"   ✅ HTTP {response.status_code} ({end_time - start_time:.2f}s)")
            results.append((url, True, response.status_code))
            
        except Exception as e:
            end_time = time.time()
            print(f"   ❌ Ошибка: {e} ({end_time - start_time:.2f}s)")
            results.append((url, False, 0))
    
    successful = sum(1 for r in results if r[1])
    print(f"\nБез обхода успешных: {successful}/{len(results)}")
    
    return results

def main():
    print("⚡ Быстрый тест обхода DPI")
    print("=" * 50)
    
    # Тест без обхода
    baseline_results = test_without_bypass()
    
    # Тест с обходом
    bypass_success = test_with_recon_service()
    
    # Сравнение
    print(f"\n📋 СРАВНЕНИЕ:")
    print("=" * 30)
    
    baseline_successful = sum(1 for r in baseline_results if r[1])
    
    print(f"Без обхода: {baseline_successful}/4 сайтов")
    print(f"С обходом: {'Улучшение' if bypass_success else 'Без изменений'}")
    
    # Проверяем rutracker конкретно
    rutracker_baseline = next((r for r in baseline_results if 'rutracker' in r[0]), None)
    
    if rutracker_baseline and not rutracker_baseline[1]:
        print(f"\n🎯 RUTRACKER заблокирован без обхода")
        if bypass_success:
            print(f"   Рекомендация: Запустите recon_service и попробуйте снова")
        else:
            print(f"   Проблема: Обход не помогает, возможно нужны другие стратегии")
    elif rutracker_baseline and rutracker_baseline[1]:
        print(f"\n🎯 RUTRACKER доступен без обхода")
    
    print(f"\n💡 РЕКОМЕНДАЦИИ:")
    if baseline_successful == 4:
        print("- Все сайты доступны, DPI блокировка не обнаружена")
    elif baseline_successful < 2:
        print("- Сильная блокировка, попробуйте VPN")
    else:
        print("- Частичная блокировка, recon_service должен помочь")
        print("- Для rutracker попробуйте запустить: python recon_service.py")

if __name__ == "__main__":
    main()