#!/usr/bin/env python3
"""
Диагностика блокировки ntc.party
Проверяет разные уровни блокировки
"""

import socket
import subprocess
import sys
from pathlib import Path

def check_dns_resolution(domain):
    """Проверка DNS резолвинга"""
    print(f"\n{'='*60}")
    print(f"1. DNS Resolution для {domain}")
    print(f"{'='*60}")
    
    try:
        # Системный DNS
        ip = socket.gethostbyname(domain)
        print(f"✅ Системный DNS: {domain} -> {ip}")
        
        # Проверка через DoH (если доступен)
        try:
            import requests
            response = requests.get(
                f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
                headers={"Accept": "application/dns-json"},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if 'Answer' in data:
                    doh_ips = [a['data'] for a in data['Answer'] if a['type'] == 1]
                    print(f"✅ DoH (Cloudflare): {domain} -> {doh_ips}")
                    
                    if ip not in doh_ips:
                        print(f"⚠️ ВНИМАНИЕ: Системный DNS возвращает другой IP!")
                        print(f"   Возможна подмена DNS (DNS hijacking)")
        except Exception as e:
            print(f"⚠️ DoH проверка недоступна: {e}")
        
        return ip
    except socket.gaierror as e:
        print(f"❌ DNS резолвинг не работает: {e}")
        print(f"   Возможна блокировка DNS")
        return None


def check_ip_connectivity(ip, port=443):
    """Проверка TCP подключения к IP"""
    print(f"\n{'='*60}")
    print(f"2. TCP Connectivity к {ip}:{port}")
    print(f"{'='*60}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            print(f"✅ TCP подключение успешно")
            return True
        else:
            print(f"❌ TCP подключение не удалось (код: {result})")
            print(f"   Возможна блокировка по IP или порту")
            return False
    except Exception as e:
        print(f"❌ Ошибка подключения: {e}")
        return False


def check_http_response(domain):
    """Проверка HTTP/HTTPS ответа"""
    print(f"\n{'='*60}")
    print(f"3. HTTP/HTTPS Response от {domain}")
    print(f"{'='*60}")
    
    try:
        import requests
        
        # Пробуем HTTPS
        try:
            response = requests.get(
                f"https://{domain}",
                timeout=10,
                allow_redirects=False
            )
            print(f"✅ HTTPS ответ: {response.status_code}")
            print(f"   Headers: {dict(list(response.headers.items())[:3])}")
            return True
        except requests.exceptions.SSLError as e:
            print(f"❌ SSL ошибка: {e}")
            print(f"   Возможна блокировка TLS handshake")
        except requests.exceptions.ConnectionError as e:
            print(f"❌ Connection error: {e}")
            print(f"   Возможна блокировка на уровне TCP или DPI")
        except requests.exceptions.Timeout:
            print(f"❌ Timeout")
            print(f"   Возможна блокировка с drop пакетов")
        
        return False
    except ImportError:
        print(f"⚠️ requests не установлен, пропускаем HTTP проверку")
        return None


def check_traceroute(domain):
    """Проверка маршрута до домена"""
    print(f"\n{'='*60}")
    print(f"4. Traceroute к {domain}")
    print(f"{'='*60}")
    
    try:
        # Windows использует tracert
        result = subprocess.run(
            ['tracert', '-h', '10', '-w', '1000', domain],
            capture_output=True,
            text=True,
            timeout=30,
            encoding='cp866'  # Windows console encoding
        )
        
        lines = result.stdout.split('\n')
        print("Маршрут:")
        for line in lines[:15]:  # Первые 15 хопов
            if line.strip():
                print(f"  {line}")
        
        # Проверяем на признаки блокировки
        if 'Request timed out' in result.stdout:
            print(f"\n⚠️ Обнаружены таймауты - возможна блокировка")
        
    except subprocess.TimeoutExpired:
        print(f"❌ Traceroute timeout")
    except Exception as e:
        print(f"⚠️ Traceroute недоступен: {e}")


def check_with_curl(domain):
    """Проверка через curl (если доступен)"""
    print(f"\n{'='*60}")
    print(f"5. Проверка через curl")
    print(f"{'='*60}")
    
    curl_path = Path("curl.exe")
    if not curl_path.exists():
        print(f"⚠️ curl.exe не найден в текущей директории")
        return
    
    try:
        # Пробуем подключиться
        result = subprocess.run(
            [str(curl_path), '-v', '-m', '10', f'https://{domain}'],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        stderr = result.stderr
        
        if 'Connected to' in stderr:
            print(f"✅ curl подключился успешно")
        elif 'Connection refused' in stderr:
            print(f"❌ Connection refused - порт закрыт или IP заблокирован")
        elif 'Connection timed out' in stderr or 'Timeout' in stderr:
            print(f"❌ Timeout - возможна блокировка с drop пакетов")
        elif 'SSL' in stderr or 'TLS' in stderr:
            print(f"❌ SSL/TLS ошибка - возможна блокировка handshake")
        else:
            print(f"⚠️ Неизвестный результат:")
            print(stderr[:500])
        
    except subprocess.TimeoutExpired:
        print(f"❌ curl timeout")
    except Exception as e:
        print(f"⚠️ curl проверка не удалась: {e}")


def main():
    domain = "ntc.party"
    
    print(f"\n{'#'*60}")
    print(f"# Диагностика блокировки {domain}")
    print(f"{'#'*60}")
    
    # 1. DNS
    ip = check_dns_resolution(domain)
    
    # 2. TCP connectivity
    if ip:
        tcp_ok = check_ip_connectivity(ip)
    else:
        tcp_ok = False
    
    # 3. HTTP response
    http_ok = check_http_response(domain)
    
    # 4. Traceroute
    check_traceroute(domain)
    
    # 5. curl
    check_with_curl(domain)
    
    # Итоговый анализ
    print(f"\n{'='*60}")
    print(f"ИТОГОВЫЙ АНАЛИЗ")
    print(f"{'='*60}")
    
    if not ip:
        print(f"\n❌ ТИП БЛОКИРОВКИ: DNS")
        print(f"   Решение: Использовать DoH/DoT или альтернативный DNS")
        print(f"   Наш скрипт: Может помочь если включить DoH")
    elif not tcp_ok:
        print(f"\n❌ ТИП БЛОКИРОВКИ: IP или PORT")
        print(f"   Решение: Нужен VPN, proxy или Tor")
        print(f"   Наш скрипт: НЕ ПОМОЖЕТ (блокировка на уровне маршрутизации)")
    elif not http_ok:
        print(f"\n❌ ТИП БЛОКИРОВКИ: DPI (Deep Packet Inspection)")
        print(f"   Решение: Обход DPI через модификацию пакетов")
        print(f"   Наш скрипт: ДОЛЖЕН ПОМОЧЬ")
    else:
        print(f"\n✅ Сайт доступен!")
    
    print(f"\n{'='*60}")
    print(f"РЕКОМЕНДАЦИИ")
    print(f"{'='*60}")
    print(f"""
1. Если блокировка DNS:
   - Включите DoH в настройках: config/doh_config.json
   - Или используйте альтернативный DNS (1.1.1.1, 8.8.8.8)

2. Если блокировка IP:
   - Используйте VPN или Tor
   - Наш скрипт работает на уровне DPI, не на уровне IP
   - Можно попробовать найти альтернативные IP через CDN

3. Если блокировка DPI:
   - Запустите: python cli.py auto {domain}
   - Система найдёт рабочую стратегию обхода
   - Затем запустите сервис: python cli.py service

4. Комбинированная блокировка:
   - Сначала решите проблему с IP (VPN/Tor)
   - Затем используйте наш скрипт для обхода DPI
    """)


if __name__ == '__main__':
    main()
