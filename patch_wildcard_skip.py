py#!/usr/bin/env python3
"""
Патч для recon_service.py - пропуск wildcard доменов при резолвинге
"""

# Читаем файл
with open('recon_service.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Старый код
old_code = '''            for domain in self.monitored_domains:
                try:
                    # Резолвим домен в IP адреса
                    ip_addresses = socket.getaddrinfo(domain, None)'''

# Новый код
new_code = '''            for domain in self.monitored_domains:
                # Пропускаем wildcard домены - они будут обработаны через domain-based filtering
                if domain.startswith('*.'):
                    self.logger.info(f"⭐ Wildcard domain registered for runtime matching: {domain}")
                    continue
                
                try:
                    # Резолвим домен в IP адреса
                    ip_addresses = socket.getaddrinfo(domain, None)'''

# Проверяем, есть ли уже патч
if "Wildcard domain registered" in content:
    print("✅ Патч уже применен!")
elif old_code in content:
    # Применяем патч
    content = content.replace(old_code, new_code)
    
    # Сохраняем
    with open('recon_service.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("✅ Патч применен успешно!")
    print("Теперь wildcard домены будут пропускаться при резолвинге")
else:
    print("❌ Не найден код для патча")
    print("Возможно, файл уже изменен или имеет другую структуру")
