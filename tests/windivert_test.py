# windivert_test.py
import os
import sys
import platform
import threading
import time
import socket

try:
    import pydivert
    import requests
    import ctypes
except ImportError as e:
    print(f"Ошибка: Необходимая библиотека не установлена. {e}")
    print("Пожалуйста, выполните: pip install pydivert requests")
    sys.exit(1)

# --- Вспомогательные функции ---

def is_admin() -> bool:
    """Проверяет права администратора."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() == 1
        return os.geteuid() == 0
    except Exception:
        return False

def generate_traffic(url="http://example.com"):
    """Генерирует простой HTTP трафик в отдельном потоке."""
    def task():
        print(f"   -> Генерирую трафик к {url}...")
        try:
            response = requests.get(url, timeout=5)
            print(f"   <- Трафик сгенерирован (Статус: {response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"   <- Ошибка генерации трафика: {e}")
    
    thread = threading.Thread(target=task, daemon=True)
    thread.start()
    return thread

# --- Тестовые шаги ---

def test_step_1_import_and_admin():
    print("="*50)
    print("ШАГ 1: Проверка импорта и прав администратора")
    print("="*50)
    print(f"Платформа: {platform.system()} {platform.release()}")
    
    if not is_admin():
        print("❌ ОШИБКА: Скрипт должен быть запущен с правами администратора!")
        return False
    
    print("✅ Права администратора: OK")
    print(f"✅ Версия pydivert: {pydivert.__version__}")
    return True

def test_step_2_open_handle(filter_str: str):
    print(f"\n--- Тест: Открытие хендла с фильтром '{filter_str}' ---")
    try:
        with pydivert.WinDivert(filter_str) as w:
            print("✅ УСПЕХ: Хендл WinDivert успешно открыт и закрыт.")
            return True
    except Exception as e:
        print(f"❌ ОШИБКА: Не удалось открыть хендл WinDivert.")
        print(f"   Детали: {e}")
        return False

def test_step_3_capture_packets(filter_str: str, traffic_url: str):
    print(f"\n--- Тест: Перехват пакетов (фильтр: '{filter_str}') ---")
    packets_captured = 0
    
    traffic_thread = generate_traffic(traffic_url)
    time.sleep(0.5) # Даем время на запуск потока

    try:
        with pydivert.WinDivert(filter_str) as w:
            print("   Хендл открыт, ожидание пакетов (3 сек)...")
            start_time = time.time()
            while time.time() - start_time < 3:
                packet = w.recv()
                if packet:
                    packets_captured += 1
                    print(f"   [+] Перехвачен пакет: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
    except Exception as e:
        print(f"❌ ОШИБКА во время перехвата: {e}")
        return False
    finally:
        traffic_thread.join(timeout=2)

    if packets_captured > 0:
        print(f"✅ УСПЕХ: Перехвачено {packets_captured} пакетов.")
        return True
    else:
        print("❌ ОШИБКА: Не перехвачено ни одного пакета. Возможные причины:")
        print("   - Брандмауэр Windows блокирует этот скрипт.")
        print("   - Антивирус блокирует WinDivert.")
        print("   - Другая программа эксклюзивно использует WinDivert.")
        return False

def test_step_4_capture_and_send(filter_str: str, traffic_url: str):
    print(f"\n--- Тест: Перехват и переотправка (фильтр: '{filter_str}') ---")
    
    result_queue = []
    def traffic_task():
        print(f"   -> Генерирую трафик к {traffic_url} для проверки переотправки...")
        try:
            response = requests.get(traffic_url, timeout=5)
            result_queue.append(True)
            print(f"   <- Трафик успешно прошел (Статус: {response.status_code})")
        except requests.exceptions.RequestException as e:
            result_queue.append(False)
            print(f"   <- Ошибка трафика: {e}")

    traffic_thread = threading.Thread(target=traffic_task, daemon=True)
    traffic_thread.start()
    time.sleep(0.5)

    try:
        with pydivert.WinDivert(filter_str) as w:
            print("   Хендл открыт, перехватываем и переотправляем пакеты (3 сек)...")
            start_time = time.time()
            while time.time() - start_time < 3:
                packet = w.recv()
                if packet:
                    w.send(packet)
    except Exception as e:
        print(f"❌ ОШИБКА во время перехвата/переотправки: {e}")
        return False
    finally:
        traffic_thread.join(timeout=5)

    if result_queue and result_queue[0]:
        print("✅ УСПЕХ: Трафик успешно прошел через WinDivert.")
        return True
    else:
        print("❌ ОШИБКА: Трафик не прошел. Переотправка пакетов не работает.")
        print("   Это классический симптом блокировки со стороны антивируса/EDR.")
        return False

def main():
    if not test_step_1_import_and_admin():
        sys.exit(1)

    # Тестируем открытие хендла
    print("\n" + "="*50)
    print("ШАГ 2: Тестирование открытия хендла")
    print("="*50)
    filters_to_test = ["tcp", "udp", "icmp", "tcp.DstPort == 80", "outbound and tcp.DstPort == 443"]
    handle_ok = all(test_step_2_open_handle(f) for f in filters_to_test)
    
    if not handle_ok:
        print("\n[ДИАГНОЗ] Не удалось открыть хендл. Проблема в базовой установке драйвера или правах.")
        sys.exit(1)

    # Тестируем перехват
    print("\n" + "="*50)
    print("ШАГ 3: Тестирование перехвата пакетов")
    print("="*50)
    capture_ok = test_step_3_capture_packets("outbound and tcp.DstPort == 80", "http://example.com")

    # Тестируем перехват и переотправку
    print("\n" + "="*50)
    print("ШАГ 4: Тестирование перехвата и ПЕРЕОТПРАВКИ")
    print("="*50)
    send_ok = test_step_4_capture_and_send("outbound and tcp.DstPort == 80", "http://example.com")

    # Финальный диагноз
    print("\n" + "="*60)
    print("🏥 ФИНАЛЬНЫЙ ДИАГНОЗ")
    print("="*60)
    if handle_ok and capture_ok and send_ok:
        print("✅ [ВЕРДИКТ] WinDivert и pydivert работают корректно!")
        print("   Проблема, скорее всего, находится внутри кода вашего проекта `recon`.")
        print("   Рекомендации:")
        print("   1. Проверьте логику генерации фильтра в `_build_filter()` в `native_pydivert_engine.py`.")
        print("   2. Убедитесь, что в фильтр не попадают некорректные IP или слишком длинные строки.")
        print("   3. Проверьте на возможные race conditions или проблемы с потоками в вашем движке.")
    else:
        print("❌ [ВЕРДИКТ] Обнаружена проблема с WinDivert или его окружением.")
        if not handle_ok:
            print("   - Проблема: Невозможно открыть хендл WinDivert.")
            print("   - Решение: Переустановите драйвер WinDivert, проверьте права администратора.")
        elif not capture_ok:
            print("   - Проблема: Пакеты не перехватываются.")
            print("   - Решение: Проверьте настройки брандмауэра Windows. Добавьте скрипт в исключения. Проверьте, не использует ли другая программа WinDivert.")
        elif not send_ok:
            print("   - Проблема: Пакеты перехватываются, но не доходят до цели после переотправки.")
            print("   - РЕШЕНИЕ: Это НАИБОЛЕЕ ВЕРОЯТНАЯ причина. Временно отключите ваш антивирус/EDR и запустите этот тест снова. Если тест пройдет успешно, добавьте ваш скрипт и/или драйвер WinDivert в исключения антивируса.")

if __name__ == "__main__":
    main()