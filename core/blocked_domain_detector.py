# blocked_domain_detector.py -> переосмыслен как DomainWatchlist

import logging
from typing import Set, List
from pathlib import Path

LOG = logging.getLogger("domain_watchlist")

class DomainWatchlist:
    """
    Управляет списком доменов, для которых требуется обход DPI.
    Загружает домены из файла или использует предопределенный список.
    """
    
    # Список по умолчанию, можно расширять
    DEFAULT_WATCHLIST = {
        'x.com', 'twitter.com', 'instagram.com', 'facebook.com',
        'youtube.com', 'telegram.org', 'discord.com', 'rutracker.org'
    }

    def __init__(self, domains_file_path: Optional[str] = None):
        """
        Args:
            domains_file_path: Путь к файлу со списком доменов (один домен на строку).
        """
        self.watchlist: Set[str] = self.DEFAULT_WATCHLIST.copy()
        if domains_file_path:
            self._load_domains_from_file(domains_file_path)

    def _load_domains_from_file(self, file_path: str):
        """Загружает домены из файла."""
        try:
            path = Path(file_path)
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith('#'):
                            self.watchlist.add(domain)
                LOG.info(f"Загружено {len(self.watchlist)} доменов в список наблюдения.")
        except Exception as e:
            LOG.error(f"Ошибка загрузки файла с доменами: {e}")

    def is_bypass_required(self, domain: str) -> bool:
        """
        Проверяет, требуется ли обход для указанного домена.
        Поддерживает проверку поддоменов.

        Args:
            domain: Домен для проверки (например, 'video.google.com').

        Returns:
            True, если домен или его родительский домен в списке.
        """
        if not domain:
            return False
        
        domain = domain.lower()
        
        # Прямая проверка
        if domain in self.watchlist:
            return True
        
        # Проверка родительских доменов (например, для 'sub.domain.com' проверяем 'domain.com')
        parts = domain.split('.')
        if len(parts) > 2:
            for i in range(1, len(parts) - 1):
                parent_domain = '.'.join(parts[i:])
                if parent_domain in self.watchlist:
                    return True
                    
        return False

    def get_watchlist(self) -> Set[str]:
        """Возвращает текущий список доменов."""
        return self.watchlist