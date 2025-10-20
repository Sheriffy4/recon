import socket
from urllib.parse import urlparse

def get_ips_from_sites(filename="sites.txt"):
    ips = set()
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                # Обрабатываем как URL, так и просто домены
                hostname = urlparse(line).hostname or line
                try:
                    # Получаем все IP-адреса для домена
                    addr_info = socket.getaddrinfo(hostname, None)
                    for item in addr_info:
                        # item[4][0] - это IP-адрес
                        ip = item[4][0]
                        if ':' not in ip: # Пропускаем IPv6 для простоты фильтра
                           ips.add(ip)
                except socket.gaierror:
                    print(f"Не удалось разрешить домен: {hostname}")
    return list(ips)

if __name__ == "__main__":
    ip_list = get_ips_from_sites()
    # Генерируем строку для фильтра Wireshark
    filter_string = " or ".join([f"host {ip}" for ip in ip_list])
    print("--- IP адреса ---")
    print("\n".join(ip_list))
    print("\n--- Строка для фильтра захвата Wireshark ---")
    print(f"({filter_string}) and tcp port 443")