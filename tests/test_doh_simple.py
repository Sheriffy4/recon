#!/usr/bin/env python3
"""
Простой тест DoH с исправленным кодом
"""

import asyncio
import aiohttp
import json

async def test_fixed_doh():
    """Тест исправленного DoH кода."""
    
    async with aiohttp.ClientSession() as session:
        server = "https://1.1.1.1/dns-query"
        hostname = "x.com"
        
        params = {"name": hostname, "type": "A"}
        headers = {"accept": "application/dns-json"}
        
        try:
            async with session.get(server, params=params, headers=headers, timeout=5) as response:
                print(f"Статус: {response.status}")
                
                if response.status == 200:
                    # Get text response and parse as JSON manually
                    text = await response.text()
                    print(f"Получен текст: {text[:100]}...")
                    
                    try:
                        data = json.loads(text)
                        print("JSON успешно распарсен!")
                        
                        if data.get("Answer"):
                            answer = data["Answer"][0]  # Берем первый ответ
                            if answer.get("data"):
                                ip = answer["data"]
                                print(f"Найден IP: {ip}")
                                return ip
                    except json.JSONDecodeError as e:
                        print(f"Ошибка парсинга JSON: {e}")
                        return None
                        
        except Exception as e:
            print(f"Ошибка запроса: {e}")
            return None

if __name__ == "__main__":
    result = asyncio.run(test_fixed_doh())
    print(f"Результат: {result}")