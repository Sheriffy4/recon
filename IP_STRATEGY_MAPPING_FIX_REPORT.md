# IP Strategy Mapping Fix Report

## Дата: 2025-10-03

## Статус
✅ **x.com работает** (после первого исправления)  
❌ **rutracker.org, nnmclub.to, instagram.com не работают**

## Проблема

После исправления маппинга стратегий для fakeddisorder, x.com заработал, но другие домены (rutracker.org, nnmclub.to, instagram.com) всё ещё не открываются.

## Диагностика

### Анализ лога

```
2025-10-03 16:10:18 [INFO] ReconService: Mapped rutracker.org -> fakedisorder(...)
2025-10-03 16:11:47 [INFO] BypassEngine: Applying bypass for 104.21.32.39 -> Type: badsum_race
```

**Проблема**: 
- Сервис мапит `rutracker.org` на `fakedisorder` ✅
- Но bypass_engine применяет `badsum_race` для IP `104.21.32.39` ❌

### Корневая причина

В `recon_service.py` strategy_map создавался **по доменам**:
```python
strategy_map[domain] = strategy_task  # ❌ Неправильно!
```

Но `bypass_engine` работает с **IP адресами**, поэтому он не мог найти стратегию для IP и использовал default стратегию (`badsum_race`).

## Решение

Изменён код в `recon_service.py` для создания strategy_map **по IP адресам**:

```python
# Создаём маппинг IP -> домен
ip_to_domain = {}
for domain in self.monitored_domains:
    ip_addresses = socket.getaddrinfo(domain, None)
    for addr_info in ip_addresses:
        ip = addr_info[4][0]
        if ip not in ip_to_domain:
            ip_to_domain[ip] = domain

# Создаём strategy_map по IP адресам
for ip in target_ips:
    domain = ip_to_domain.get(ip)
    if domain:
        strategy_str = self.get_strategy_for_domain(domain)
        strategy_config = self.parse_strategy_config(strategy_str)
        strategy_task = self._config_to_strategy_task(strategy_config)
        strategy_map[ip] = strategy_task  # ✅ Правильно!
```

## Ожидаемый результат

После применения исправления в логе должно быть:

```
Mapped IP 104.21.32.39 (rutracker.org) -> fakedisorder
Mapped IP 104.21.112.1 (nnmclub.to) -> fakedisorder
Mapped IP 157.240.245.174 (instagram.com) -> multisplit
Mapped IP 172.66.0.227 (x.com) -> fakeddisorder
```

И при применении bypass:

```
Applying bypass for 104.21.32.39 -> Type: fakedisorder  (не badsum_race!)
Applying bypass for 157.240.245.174 -> Type: multisplit  (не badsum_race!)
```

## Затронутые домены

Исправление влияет на **ВСЕ** домены, так как это фундаментальная проблема маппинга:

- rutracker.org (104.21.32.39)
- nnmclub.to (104.21.112.1)
- instagram.com (157.240.245.174)
- facebook.com
- youtube.com
- telegram.org
- И все остальные домены из sites.txt

## Инструкции по применению

1. **Остановить** текущий сервис bypass (Ctrl+C)
2. **Запустить** сервис заново: `python setup.py` → [2]
3. **Проверить** в логе правильный маппинг:
   ```
   Mapped IP 104.21.32.39 (rutracker.org) -> fakedisorder
   ```
4. **Попробовать** открыть заблокированные домены

## Файлы

- **Исправлен**: `recon/recon_service.py` (функция `start_bypass_engine`)
- **Создан тест**: `recon/test_ip_strategy_mapping.py`
- **Документация**: `recon/IP_STRATEGY_MAPPING_FIX_REPORT.md`

## Связь с предыдущим исправлением

Это исправление дополняет предыдущее:

1. **Первое исправление** (STRATEGY_MAPPING_BUG_FIX): Исправлен маппинг `fakeddisorder` → правильная стратегия
2. **Второе исправление** (IP_STRATEGY_MAPPING_FIX): Исправлен маппинг домен → IP → стратегия

Оба исправления необходимы для полной работы bypass!

## Статус

✅ **ИСПРАВЛЕНО** - Готово к тестированию пользователем

---

**Примечание**: Это критическое исправление, без которого bypass не может правильно применять стратегии к IP адресам.
