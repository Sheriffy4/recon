"""
Менеджер службы - интеграция с simple_service.py
"""

import subprocess
import sys
import os
from typing import Optional
from PyQt6.QtCore import QThread, pyqtSignal


class ServiceThread(QThread):
    """Поток для запуска службы"""
    output = pyqtSignal(str)
    error = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.process: Optional[subprocess.Popen] = None
        self._stop_requested = False
    
    def run(self):
        """Запуск simple_service.py"""
        try:
            # Переменные окружения для unbuffered вывода
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            env['PYTHONIOENCODING'] = 'utf-8'
            env['PYTHONUTF8'] = '1'
            
            # Запускаем simple_service.py
            self.process = subprocess.Popen(
                [sys.executable, '-u', 'simple_service.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Объединяем stderr с stdout
                text=False,  # Читаем как bytes
                bufsize=0,  # Без буферизации
                env=env
            )
            
            # Читаем вывод посимвольно (как в CLIWorkerThread)
            buffer = b''
            while not self._stop_requested:
                # Читаем по одному байту
                chunk = self.process.stdout.read(1)
                
                if not chunk:
                    # Процесс завершился
                    if self.process.poll() is not None:
                        break
                    continue
                
                buffer += chunk
                
                # Если встретили перенос строки, выводим
                if chunk == b'\n':
                    try:
                        line = buffer.decode('utf-8', errors='replace').rstrip()
                        if line:
                            self.output.emit(line)
                    except:
                        pass
                    buffer = b''
                # Также выводим если буфер стал большим
                elif len(buffer) > 200:
                    try:
                        line = buffer.decode('utf-8', errors='replace')
                        if line.strip():
                            self.output.emit(line)
                    except:
                        pass
                    buffer = b''
            
            # Выводим остатки буфера
            if buffer:
                try:
                    line = buffer.decode('utf-8', errors='replace').strip()
                    if line:
                        self.output.emit(line)
                except:
                    pass
            
            # Получаем код возврата
            if self.process:
                return_code = self.process.wait()
                self.finished_signal.emit(return_code)
        
        except Exception as e:
            self.error.emit(f"Ошибка запуска службы: {e}")
            import traceback
            self.error.emit(traceback.format_exc())
            self.finished_signal.emit(-1)
    
    def stop(self):
        """Остановка службы"""
        self._stop_requested = True
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except Exception as e:
                print(f"Ошибка остановки службы: {e}")


class ServiceManager:
    """Менеджер службы обхода"""
    
    def __init__(self):
        self.service_thread: Optional[ServiceThread] = None
        self.is_running = False
    
    def start(self, output_callback=None, error_callback=None, finished_callback=None):
        """Запуск службы"""
        if self.is_running:
            return False
        
        self.service_thread = ServiceThread()
        
        if output_callback:
            self.service_thread.output.connect(output_callback)
        if error_callback:
            self.service_thread.error.connect(error_callback)
        if finished_callback:
            self.service_thread.finished_signal.connect(finished_callback)
        
        self.service_thread.start()
        self.is_running = True
        return True
    
    def stop(self):
        """Остановка службы"""
        if not self.is_running or not self.service_thread:
            return False
        
        self.service_thread.stop()
        self.service_thread.wait()
        self.is_running = False
        return True
    
    def get_status(self) -> dict:
        """Получить статус службы"""
        return {
            'running': self.is_running,
            'thread_alive': self.service_thread.isRunning() if self.service_thread else False
        }
