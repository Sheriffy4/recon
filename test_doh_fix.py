#!/usr/bin/env python3
"""
Тест и исправление DoH resolver
"""

import asyncio
import aiohttp
import json

async def test_doh_servers():
    """Тестирование DoH серверов с правильными заголовками."""
    
    servers = [
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/resolve", 
        "https://9.9.9.9/dns-query"
    ]
    
    hostname = "x.com"
    
    async with aiohttp.ClientSession() as session:
        for server in servers:
            print(f"\n=== Тестирование {server} ===")
            
            try:
                params = {"name": hostname, "type": "A"}
                headers = {"Accept": "application/dns-json"}
                
                async with session.get(server, params=params, headers=headers, timeout=10) as response:
                    print(f"Статус: {response.status}")
                    print(f"Content-Type: {response.headers.get('content-type', 'не указан')}")
                    
                    if response.status == 200:
                        # Получаем текст ответа
                        text = await response.text()
                        print(f"Ответ (первые 200 символов): {text[:200]}")
                        
                        try:
                            # Пытаемся парсить как JSON
                            data = json.loads(text)
                            print(f"JSON успешно распарсен")
                            
                            if data.get("Answer"):
                                ips = [answer["data"] for answer in data["Answer"] if answer.get("data")]
                                print(f"Найденные IP: {ips}")
                            else:
                                print("Нет ответов в JSON")
                                
                        except json.JSONDecodeError as e:
                            print(f"Ошибка парсинга JSON: {e}")
                    
            except Exception as e:
                print(f"Ошибка запроса: {e}")

if __name__ == "__main__":
    asyncio.run(test_doh_servers())