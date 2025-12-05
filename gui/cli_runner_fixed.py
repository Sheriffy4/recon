"""
Исправленный CLI runner с неблокирующим чтением
Альтернативная реализация если основная не работает
"""

import sys
import os
import subprocess
import threading
import queue
from PyQt6.QtCore import QThread, pyqtSignal


class NonBlockingCLIWorker(QThread):
    """CLI worker с неблокирующим чтением через отдельный поток"""
    output = pyqtSignal(str)
    error = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    
    def __init__(self, command, args):
        super().__init__()
        self.command = command
        self.args = args
        self.output_queue = queue.Queue()
        self.process = None
    
    def _read_output(self, pipe, queue):
        """Читает вывод в отдельном потоке"""
        try:
            for line in iter(pipe.readline, b''):
                if line:
                    try:
                        decoded = line.decode('utf-8', errors='replace').rstrip()
                        queue.put(('output', decoded))
                    except Exception as e:
                        queue.put(('error', f"Decode error: {e}"))
        except Exception as e:
            queue.put(('error', f"Read error: {e}"))
        finally:
            pipe.close()
    
    def run(self):
        try:
            full_command = [sys.executable, '-u', 'cli.py'] + self.command + self.args
            
            # Переменные окружения
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            env['PYTHONIOENCODING'] = 'utf-8'
            env['PYTHONUTF8'] = '1'
            
            # Запускаем процесс
            self.process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                env=env
            )
            
            # Запускаем поток для чтения вывода
            reader_thread = threading.Thread(
                target=self._read_output,
                args=(self.process.stdout, self.output_queue),
                daemon=True
            )
            reader_thread.start()
            
            # Читаем из очереди и отправляем сигналы
            while True:
                try:
                    # Проверяем очередь с таймаутом
                    msg_type, msg = self.output_queue.get(timeout=0.1)
                    
                    if msg_type == 'output':
                        self.output.emit(msg)
                    elif msg_type == 'error':
                        self.error.emit(msg)
                        
                except queue.Empty:
                    # Проверяем завершился ли процесс
                    if self.process.poll() is not None:
                        # Процесс завершился, читаем остатки
                        while not self.output_queue.empty():
                            try:
                                msg_type, msg = self.output_queue.get_nowait()
                                if msg_type == 'output':
                                    self.output.emit(msg)
                            except queue.Empty:
                                break
                        break
            
            # Ждем завершения потока чтения
            reader_thread.join(timeout=1)
            
            return_code = self.process.wait()
            self.finished_signal.emit(return_code)
            
        except Exception as e:
            self.error.emit(f"Ошибка выполнения: {e}")
            import traceback
            self.error.emit(traceback.format_exc())
            self.finished_signal.emit(-1)
    
    def stop(self):
        """Остановка процесса"""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)


# Для использования в improved_main_window.py:
# from gui.cli_runner_fixed import NonBlockingCLIWorker as CLIWorkerThread
