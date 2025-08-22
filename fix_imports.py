import os
import ast
from pathlib import Path

PROJECT_ROOT_NAME = "recon"

class ImportTransformer(ast.NodeTransformer):
    def __init__(self, file_path: Path, project_root: Path):
        self.file_path = file_path
        self.project_root = project_root
        self.changed = False

    def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.ImportFrom:
        if node.level > 0:  # Это относительный импорт (from . import ..., from .. import ...)
            try:
                # Вычисляем абсолютный путь к модулю
                current_dir = self.file_path.parent
                resolve_path = (current_dir / ("../" * (node.level - 1)) / (node.module or "")).resolve()
                
                # Преобразуем в относительный путь от корня проекта
                relative_to_root = resolve_path.relative_to(self.project_root)
                
                # Собираем новый абсолютный путь модуля
                new_module_path_parts = [PROJECT_ROOT_NAME] + list(relative_to_root.parts)
                
                # Если импорт был из __init__.py, убираем лишнюю часть
                if node.module is None:
                    # from . import X -> убираем последний элемент пути
                    if new_module_path_parts[-1] == self.file_path.parent.name:
                         new_module_path_parts.pop()

                new_module_str = ".".join(new_module_path_parts)
                
                print(f"  [FIX] {self.file_path.name}: Rewriting '{'.' * node.level}{node.module or ''}' -> '{new_module_str}'")

                node.module = new_module_str
                node.level = 0  # Устанавливаем уровень в 0 для абсолютного импорта
                self.changed = True
            except Exception as e:
                print(f"  [ERROR] Could not resolve import in {self.file_path.name}: {e}")

        return node

def fix_imports_in_project(root_dir: str):
    project_root = Path(root_dir).resolve()
    print(f"Scanning project at: {project_root}")

    for path in project_root.rglob("*.py"):
        if "venv" in path.parts or ".git" in path.parts:
            continue

        try:
            with open(path, "r", encoding="utf-8") as f:
                source_code = f.read()
            
            tree = ast.parse(source_code)
            transformer = ImportTransformer(path, project_root)
            new_tree = transformer.visit(tree)

            if transformer.changed:
                # Сохраняем изменения
                new_source = ast.unparse(new_tree)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new_source)
                print(f"  -> Patched {path.relative_to(project_root)}")

        except Exception as e:
            print(f"Could not process {path}: {e}")

if __name__ == "__main__":
    fix_imports_in_project(".")
    print("\nImport fixing process complete.")