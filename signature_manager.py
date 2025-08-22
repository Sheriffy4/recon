import json
import os
import logging
import time
import requests
import threading
from typing import Dict, Optional, Any, TYPE_CHECKING
from datetime import datetime
try:
    import schedule
    SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False
try:
    import jsonschema
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
if TYPE_CHECKING:
    from recon.fingerprint import Fingerprint
LOG = logging.getLogger('SignatureManager')
SIGNATURE_DB_PATH = 'dpi_signatures.json'
REMOTE_DB_URL = 'https://raw.githubusercontent.com/ValdikSS/Recon/main/dpi_signatures_export.json'
SIGNATURE_SCHEMA = {'type': 'object', 'properties': {'fingerprint_details': {'type': 'object'}, 'working_strategy': {'type': 'object', 'properties': {'strategy': {'type': 'string'}, 'success_rate': {'type': 'number', 'minimum': 0, 'maximum': 1}}, 'required': ['strategy']}, 'metadata': {'type': 'object'}}, 'required': ['working_strategy']}

class SignatureManager:

    def __init__(self, db_path: str=SIGNATURE_DB_PATH):
        self.db_path = db_path
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> Dict[str, Any]:
        if not os.path.exists(self.db_path):
            LOG.info(f"Файл базы данных сигнатур '{self.db_path}' не найден. Будет создан новый.")
            return {}
        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                LOG.info(f"✅ Загружено {len(data)} сигнатур из '{self.db_path}'.")
                return data
        except (json.JSONDecodeError, IOError) as e:
            LOG.error(f'❌ Не удалось загрузить базу данных сигнатур: {e}. Будет использована пустая база.')
            return {}

    def _save_signatures(self):
        try:
            if os.path.exists(self.db_path):
                backup_path = f'{self.db_path}.bak'
                import shutil
                shutil.copy2(self.db_path, backup_path)
            with open(self.db_path, 'w', encoding='utf-8') as f:
                json.dump(self.signatures, f, indent=2, ensure_ascii=False)
            LOG.debug(f"База данных сигнатур сохранена в '{self.db_path}'.")
        except IOError as e:
            LOG.error(f'❌ Не удалось сохранить базу данных сигнатур: {e}')

    def sync_from_remote(self):
        LOG.info(f'Синхронизация с удаленной базой: {REMOTE_DB_URL}')
        try:
            response = requests.get(REMOTE_DB_URL, timeout=10, verify=True)
            response.raise_for_status()
            remote_data = response.json().get('signatures', {})
            new_signatures_count = 0
            for key, entry in remote_data.items():
                if key not in self.signatures:
                    if JSONSCHEMA_AVAILABLE:
                        try:
                            jsonschema.validate(instance=entry, schema=SIGNATURE_SCHEMA)
                        except jsonschema.ValidationError as e:
                            LOG.warning(f'Пропущена невалидная сигнатура {key} из удаленной базы: {e.message}')
                            continue
                    self.signatures[key] = entry
                    new_signatures_count += 1
            if new_signatures_count > 0:
                self._save_signatures()
                LOG.info(f'✅ База синхронизирована: добавлено {new_signatures_count} новых сигнатур.')
            else:
                LOG.info('Локальная база данных сигнатур уже актуальна.')
        except requests.RequestException as e:
            LOG.warning(f'⚠️ Не удалось синхронизировать базу сигнатур: {e}')
        except json.JSONDecodeError:
            LOG.error('⚠️ Не удалось разобрать ответ от удаленного сервера. Возможно, файл поврежден.')

    def start_auto_sync(self, interval_hours: int=24):
        if not SCHEDULE_AVAILABLE:
            LOG.warning("Библиотека 'schedule' не установлена. Автоматическая синхронизация отключена.")
            return

        def job():
            LOG.info('Auto-sync: Проверка обновлений в удаленной базе...')
            self.sync_from_remote()
        job()
        schedule.every(interval_hours).hours.do(job)

        def run_schedule():
            while True:
                schedule.run_pending()
                time.sleep(3600)
        thread = threading.Thread(target=run_schedule, daemon=True)
        thread.start()
        LOG.info(f'✅ Автоматическая синхронизация базы сигнатур запущена (интервал: {interval_hours} ч).')

    def find_strategy_for_fingerprint(self, fp: 'Fingerprint') -> Optional[Dict[str, Any]]:
        fp_hash = fp.short_hash()
        if fp_hash in self.signatures:
            LOG.info(f'🔍 Найдена точная сигнатура DPI в базе (hash: {fp_hash}).')
            return self.signatures[fp_hash]
        if fp.dpi_type:
            for sig_hash, entry in self.signatures.items():
                if entry.get('fingerprint_details', {}).get('dpi_type') == fp.dpi_type:
                    LOG.info(f'🔍 Найдена похожая сигнатура (по типу DPI: {fp.dpi_type})')
                    return entry
        return None

    def update_signature(self, fp: 'Fingerprint', best_strategy_result: Dict[str, Any]):
        fp_hash = fp.short_hash()
        strategy_info = {'strategy': best_strategy_result.get('strategy'), 'success_rate': best_strategy_result.get('success_rate'), 'avg_latency_ms': best_strategy_result.get('avg_latency_ms'), 'successful_sites': best_strategy_result.get('successful_sites', 0), 'total_sites': best_strategy_result.get('total_sites', 0)}
        existing_entry = self.signatures.get(fp_hash, {})
        history = existing_entry.get('strategy_history', [])
        if 'working_strategy' in existing_entry:
            old_entry = existing_entry['working_strategy'].copy()
            old_entry['timestamp'] = existing_entry.get('metadata', {}).get('last_seen')
            history.append(old_entry)
        entry = {'fingerprint_details': fp.to_dict(), 'working_strategy': strategy_info, 'strategy_history': history[-5:], 'metadata': {'first_seen': existing_entry.get('metadata', {}).get('first_seen', time.time()), 'last_seen': time.time(), 'update_count': existing_entry.get('metadata', {}).get('update_count', 0) + 1}}
        self.signatures[fp_hash] = entry
        LOG.info(f'💾 База данных сигнатур обновлена для фингерпринта {fp_hash}.')
        self._save_signatures()

    def update_strategy_for_fingerprint(self, fp_hash: str, new_strategy: str, new_success_rate: float):
        if fp_hash not in self.signatures:
            LOG.warning(f'Попытка обновить стратегию для несуществующего фингерпринта: {fp_hash}')
            return
        entry = self.signatures[fp_hash]
        history = entry.get('strategy_history', [])
        if 'working_strategy' in entry:
            old_entry = entry['working_strategy'].copy()
            old_entry['timestamp'] = entry.get('metadata', {}).get('last_seen')
            history.append(old_entry)
        entry['working_strategy']['strategy'] = new_strategy
        entry['working_strategy']['success_rate'] = new_success_rate
        entry['strategy_history'] = history[-5:]
        entry['metadata']['last_seen'] = time.time()
        entry['metadata']['update_count'] = entry['metadata'].get('update_count', 0) + 1
        self.signatures[fp_hash] = entry
        LOG.info(f'💾 [Монитор] Стратегия для {fp_hash} обновлена на: {new_strategy}')
        self._save_signatures()

    def export_for_sharing(self, export_path: str='dpi_signatures_export.json'):
        export_data = {'version': '2.0', 'exported_at': datetime.now().isoformat(), 'signatures_count': len(self.signatures), 'signatures': {}}
        for fp_hash, entry in self.signatures.items():
            clean_entry = {'fingerprint_details': {'dpi_type': entry.get('fingerprint_details', {}).get('dpi_type'), 'dpi_family': entry.get('fingerprint_details', {}).get('dpi_family')}, 'working_strategy': {'strategy': entry.get('working_strategy', {}).get('strategy'), 'success_rate': entry.get('working_strategy', {}).get('success_rate')}, 'metadata': {'update_count': entry.get('metadata', {}).get('update_count', 0)}}
            export_data['signatures'][fp_hash] = clean_entry
        try:
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            LOG.info(f"📤 База сигнатур экспортирована в '{export_path}' для обмена.")
        except IOError as e:
            LOG.error(f'Ошибка экспорта базы сигнатур: {e}')

    def import_from_community(self, import_path: str):
        if not JSONSCHEMA_AVAILABLE:
            LOG.error("Библиотека 'jsonschema' не установлена. Импорт невозможен.")
            return
        if not os.path.exists(import_path):
            LOG.error(f"Файл для импорта не найден: '{import_path}'")
            return
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            imported_count = 0
            skipped_count = 0
            for fp_hash, entry in import_data.get('signatures', {}).items():
                if fp_hash not in self.signatures:
                    try:
                        jsonschema.validate(instance=entry, schema=SIGNATURE_SCHEMA)
                        self.signatures[fp_hash] = entry
                        self.signatures[fp_hash].setdefault('metadata', {})['imported_from'] = import_path
                        imported_count += 1
                    except jsonschema.ValidationError as e:
                        LOG.warning(f"Пропущена невалидная сигнатура {fp_hash} из '{import_path}': {e.message}")
                        skipped_count += 1
            if imported_count > 0:
                self._save_signatures()
                LOG.info(f"📥 Импортировано {imported_count} новых сигнатур из '{import_path}'.")
            if skipped_count == 0 and imported_count == 0:
                LOG.info('Новых сигнатур для импорта не найдено.')
        except Exception as e:
            LOG.error(f'Ошибка импорта сигнатур: {e}')

    def generate_report(self, output_file: str='dpi_report.txt'):
        stats = self.get_statistics()
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('=' * 30 + '\n')
                f.write(' Recon DPI Signatures Report\n')
                f.write(f" Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write('=' * 30 + '\n\n')
                f.write(f"Total Signatures: {stats['total_signatures']}\n")
                f.write(f"Average Success Rate: {stats['average_success_rate']:.1%}\n")
                f.write(f"Recently Updated (last 7 days): {stats['recent_updates_7d']}\n\n")
                f.write('--- DPI Types Distribution ---\n')
                for dtype, count in sorted(stats['dpi_types'].items(), key=lambda item: item[1], reverse=True):
                    f.write(f'- {dtype:<15}: {count} entries\n')
                f.write('\n--- Top Strategies by DPI Type ---\n')
                for dtype, strategies in sorted(stats['top_strategies_by_dpi'].items()):
                    f.write(f"\nFor '{dtype}':\n")
                    if strategies:
                        for i, strat in enumerate(strategies, 1):
                            f.write(f'  {i}. {strat}\n')
                    else:
                        f.write('  No dominant strategies found.\n')
            LOG.info(f'📊 Отчет по сигнатурам успешно сгенерирован: {output_file}')
        except IOError as e:
            LOG.error(f'Не удалось сгенерировать отчет: {e}')

    def get_statistics(self) -> Dict[str, Any]:
        stats = {'total_signatures': len(self.signatures), 'dpi_types': {}, 'average_success_rate': 0, 'recent_updates_7d': 0, 'stale_signatures_30d': 0, 'top_strategies_by_dpi': {}}
        success_rates = []
        now = time.time()
        for entry in self.signatures.values():
            dpi_type = entry.get('fingerprint_details', {}).get('dpi_type', 'Unknown')
            stats['dpi_types'][dpi_type] = stats['dpi_types'].get(dpi_type, 0) + 1
            if (sr := entry.get('working_strategy', {}).get('success_rate')) is not None:
                success_rates.append(sr)
            last_seen = entry.get('metadata', {}).get('last_seen', 0)
            if now - last_seen < 7 * 24 * 3600:
                stats['recent_updates_7d'] += 1
            if now - last_seen > 30 * 24 * 3600:
                stats['stale_signatures_30d'] += 1
            if (strategy := entry.get('working_strategy', {}).get('strategy')):
                if dpi_type not in stats['top_strategies_by_dpi']:
                    stats['top_strategies_by_dpi'][dpi_type] = {}
                stats['top_strategies_by_dpi'][dpi_type][strategy] = stats['top_strategies_by_dpi'][dpi_type].get(strategy, 0) + 1
        if success_rates:
            stats['average_success_rate'] = sum(success_rates) / len(success_rates)
        for dpi_type, strats in stats['top_strategies_by_dpi'].items():
            sorted_strats = sorted(strats.items(), key=lambda item: item[1], reverse=True)
            stats['top_strategies_by_dpi'][dpi_type] = [s[0] for s in sorted_strats[:3]]
        return stats