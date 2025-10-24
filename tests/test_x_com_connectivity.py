#!/usr/bin/env python3
"""
Тест подключения к x.com для диагностики проблемы.
"""
import asyncio
import aiohttp
import ssl
import time
import socket

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}


async def test_direct_connection():
    """Тест прямого подключения к x.com без обхода."""
    print("🔍 Тест 1: Прямое подключение к x.com")

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(ssl=ssl_context)
    timeout = aiohttp.ClientTimeout(total=30.0, connect=10.0, sock_read=15.0)

    try:
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout
        ) as session:
            start_time = time.time()
            async with session.get(
                "https://x.com", headers=HEADERS, allow_redirects=True
            ) as response:
                await response.content.readexactly(1)
                latency = (time.time() - start_time) * 1000
                print(f"  ✅ УСПЕХ: Статус {response.status}, задержка {latency:.1f}ms")
                return True
    except Exception as e:
        latency = (time.time() - start_time) * 1000
        print(f"  ❌ ОШИБКА: {e}, задержка {latency:.1f}ms")
        return False


async def test_dns_resolution():
    """Тест разрешения DNS для x.com."""
    print("\n🔍 Тест 2: Разрешение DNS для x.com")

    try:
        # Разрешаем DNS
        loop = asyncio.get_event_loop()
        result = await loop.getaddrinfo("x.com", 443, family=socket.AF_INET)

        if result:
            ip = result[0][4][0]
            print(f"  ✅ УСПЕХ: x.com -> {ip}")
            return ip
        else:
            print("  ❌ ОШИБКА: DNS не разрешился")
            return None
    except Exception as e:
        print(f"  ❌ ОШИБКА DNS: {e}")
        return None


async def test_ip_connection(ip):
    """Тест подключения к IP напрямую."""
    print(f"\n🔍 Тест 3: Подключение к IP {ip}")

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(ssl=ssl_context)
    timeout = aiohttp.ClientTimeout(total=30.0, connect=10.0, sock_read=15.0)

    try:
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout
        ) as session:
            start_time = time.time()
            # Подключаемся к IP, но с Host заголовком для x.com
            headers = HEADERS.copy()
            headers["Host"] = "x.com"
            async with session.get(
                f"https://{ip}", headers=headers, allow_redirects=True
            ) as response:
                await response.content.readexactly(1)
                latency = (time.time() - start_time) * 1000
                print(f"  ✅ УСПЕХ: Статус {response.status}, задержка {latency:.1f}ms")
                return True
    except Exception as e:
        latency = (time.time() - start_time) * 1000
        print(f"  ❌ ОШИБКА: {e}, задержка {latency:.1f}ms")
        return False


async def test_with_bypass():
    """Тест с запуском движка обхода."""
    print("\n🔍 Тест 4: Подключение с движком обхода")

    try:
        from core.unified_bypass_engine import UnifiedBypassEngine

        # Создаем движок
        engine = UnifiedBypassEngine()

        # Получаем IP для x.com
        ip = await test_dns_resolution()
        if not ip:
            print("  ❌ ОШИБКА: Не удалось получить IP для x.com")
            return False

        # Создаем стратегию
        strategy_str = "fakeddisorder(split_pos=3,ttl=3,fooling=['badsum','badseq'])"
        engine_task = engine._ensure_engine_task(strategy_str)

        if not engine_task:
            print("  ❌ ОШИБКА: Не удалось создать задачу движка")
            return False

        print(f"  ✅ Задача движка: {engine_task}")

        # Запускаем движок
        bypass_engine = engine.engine
        strategy_map = {"default": engine_task}

        bypass_thread = bypass_engine.start(
            target_ips={ip}, strategy_map=strategy_map, strategy_override=engine_task
        )

        # Ждем запуска
        await asyncio.sleep(3.0)
        print("  ✅ Движок запущен, тестируем подключение...")

        # Тестируем подключение
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_context)
        timeout = aiohttp.ClientTimeout(total=30.0, connect=10.0, sock_read=15.0)

        try:
            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout
            ) as session:
                start_time = time.time()
                async with session.get(
                    "https://x.com", headers=HEADERS, allow_redirects=True
                ) as response:
                    await response.content.readexactly(1)
                    latency = (time.time() - start_time) * 1000
                    print(
                        f"  ✅ УСПЕХ С ОБХОДОМ: Статус {response.status}, задержка {latency:.1f}ms"
                    )

                    # Получаем телеметрию
                    if hasattr(bypass_engine, "get_telemetry_snapshot"):
                        telemetry = bypass_engine.get_telemetry_snapshot()
                        print(f"  📊 Телеметрия: {telemetry}")

                    return True
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            print(f"  ❌ ОШИБКА С ОБХОДОМ: {e}, задержка {latency:.1f}ms")

            # Получаем телеметрию даже при ошибке
            if hasattr(bypass_engine, "get_telemetry_snapshot"):
                telemetry = bypass_engine.get_telemetry_snapshot()
                print(f"  📊 Телеметрия: {telemetry}")

            return False
        finally:
            # Останавливаем движок
            bypass_engine.stop()
            if bypass_thread:
                bypass_thread.join(timeout=2.0)
            print("  ✅ Движок остановлен")

    except Exception as e:
        print(f"  ❌ ОШИБКА ДВИЖКА: {e}")
        import traceback

        traceback.print_exc()
        return False


async def main():
    """Основная функция тестирования."""
    print("🚀 ДИАГНОСТИКА ПОДКЛЮЧЕНИЯ К X.COM")
    print("=" * 60)

    results = []

    # Тест 1: Прямое подключение
    results.append(("direct connection", await test_direct_connection()))

    # Тест 2: DNS разрешение
    ip = await test_dns_resolution()
    results.append(("DNS resolution", ip is not None))

    # Тест 3: Подключение к IP
    if ip:
        results.append(("IP connection", await test_ip_connection(ip)))

    # Тест 4: С движком обхода
    results.append(("bypass engine", await test_with_bypass()))

    # Итоги
    print("\n" + "=" * 60)
    print("📊 РЕЗУЛЬТАТЫ ДИАГНОСТИКИ")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"  {status}: {test_name}")

    print(f"\n🎯 Итого: {passed}/{total} тестов прошли успешно")

    if passed == 0:
        print(
            "🚨 x.com полностью недоступен - возможно, проблема с интернетом или блокировкой"
        )
    elif passed < total:
        print("⚠️ Частичная доступность - возможно, DPI блокирует некоторые подключения")
    else:
        print("🎉 x.com полностью доступен")


if __name__ == "__main__":
    asyncio.run(main())
