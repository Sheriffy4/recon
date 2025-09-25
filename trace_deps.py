#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
trace_deps.py — статический трейс импортов для выбранных модулей проекта.

Пример:
  python trace_deps.py --root . --entries core/bypass_engine.py core/hybrid_engine.py --output deps_report.json

Опции:
  --root PATH                      Корень репозитория (по умолчанию текущая директория)
  --entries PATH [PATH ...]        Входные модули (пути к .py файлам или имена модулей "pkg.mod")
  --package-roots NAME [NAME ...]  Топовые пакеты вашего проекта, считаем их "внутренними" (по умолчанию: core)
  --max-depth N                    Лимит рекурсии по зависимостям (по умолчанию: 20)
  --output FILE.json               Путь для JSON-отчета
  --copy-to DIR                    Скопировать все требуемые внутренние файлы в указанную папку
  --zip FILE.zip                   Запаковать все требуемые внутренние файлы в zip
"""

import os
import sys
import ast
import json
import argparse
import shutil
import zipfile
from typing import Dict, List, Set, Tuple, Optional

# Для Python 3.12 есть ast.unparse
HAVE_UNPARSE = hasattr(ast, "unparse")

def normpath(p: str) -> str:
    return os.path.normpath(os.path.abspath(p))

def guess_module_name_from_path(root: str, path: str) -> Optional[str]:
    path = normpath(path)
    root = normpath(root)
    if not path.startswith(root + os.sep):
        return None
    rel = path[len(root)+1:]
    if rel.endswith(".py"):
        rel = rel[:-3]
    parts = rel.split(os.sep)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return None
    return ".".join(parts)

def resolve_module_to_path(root: str, module: str) -> Optional[str]:
    """
    Пытается сопоставить имя модуля с путем в файловой системе в пределах root.
    Ищем module.py или module/__init__.py
    """
    candidate = os.path.join(root, *module.split(".")) + ".py"
    if os.path.isfile(candidate):
        return normpath(candidate)
    candidate = os.path.join(root, *module.split("."), "__init__.py")
    if os.path.isfile(candidate):
        return normpath(candidate)
    return None

class ImportRecord:
    def __init__(self, module: str, names: List[str], is_from: bool,
                 optional: bool, conditional: bool, condition: Optional[str], lineno: int, col: int, note: Optional[str] = None):
        self.module = module              # "package.sub" для import / from
        self.names = names or []          # имена (для "from x import a, b")
        self.is_from = is_from
        self.optional = optional
        self.conditional = conditional
        self.condition = condition
        self.lineno = lineno
        self.col = col
        self.note = note  # для динамических импортов

    def as_dict(self) -> Dict:
        return {
            "module": self.module,
            "names": self.names,
            "is_from": self.is_from,
            "optional": self.optional,
            "conditional": self.conditional,
            "condition": self.condition,
            "lineno": self.lineno,
            "col": self.col,
            "note": self.note,
        }

class ImportCollector(ast.NodeVisitor):
    def __init__(self):
        self.imports: List[ImportRecord] = []
        self.context_stack: List[Tuple[str, object]] = []

    def _current_optional(self) -> bool:
        # optional если внутри try с except ImportError/ModuleNotFoundError/Exception
        for kind, node in reversed(self.context_stack):
            if kind == "try":
                # Если в except ловят ImportError / ModuleNotFoundError / Exception — делаем optional
                try:
                    types = []
                    for h in node.handlers:
                        t = h.type
                        if t is None:
                            # bare except: считаем optional
                            return True
                        try:
                            name = ast.unparse(t) if HAVE_UNPARSE else getattr(t, "id", None) or getattr(getattr(t, "attr", None), "id", None)
                        except Exception:
                            name = None
                        if name:
                            types.append(name)
                    normalized = ",".join(types)
                    if any(x in normalized for x in ("ImportError", "ModuleNotFoundError", "Exception")):
                        return True
                except Exception:
                    return True
        return False

    def _current_condition(self) -> Tuple[bool, Optional[str]]:
        for kind, node in reversed(self.context_stack):
            if kind == "if":
                try:
                    cond = ast.unparse(node.test) if HAVE_UNPARSE else "<if>"
                except Exception:
                    cond = "<if>"
                return True, cond
        return False, None

    def visit_Try(self, node: ast.Try):
        self.context_stack.append(("try", node))
        self.generic_visit(node)
        self.context_stack.pop()

    def visit_If(self, node: ast.If):
        self.context_stack.append(("if", node))
        self.generic_visit(node)
        self.context_stack.pop()

    def visit_Import(self, node: ast.Import):
        opt = self._current_optional()
        cond, cond_expr = self._current_condition()
        for alias in node.names:
            mod = alias.name  # "pkg.sub"
            self.imports.append(ImportRecord(
                module=mod, names=[], is_from=False,
                optional=opt, conditional=cond, condition=cond_expr,
                lineno=node.lineno, col=node.col_offset
            ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        opt = self._current_optional()
        cond, cond_expr = self._current_condition()
        level = node.level or 0
        base = node.module or ""
        # относительные импорты — пометим точками для последующего разворота в анализаторе
        mod = "." * level + base
        self.imports.append(ImportRecord(
            module=mod, names=[a.name for a in node.names], is_from=True,
            optional=opt, conditional=cond, condition=cond_expr,
            lineno=node.lineno, col=node.col_offset
        ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # importlib.import_module("core.xxx")
        # __import__("core.xxx")
        try:
            fn = node.func
            fn_name = None
            if isinstance(fn, ast.Attribute):
                fn_name = f"{ast.unparse(fn.value) if HAVE_UNPARSE else ''}.{fn.attr}"
            elif isinstance(fn, ast.Name):
                fn_name = fn.id

            if fn_name in ("importlib.import_module", "__import__") and node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    mod = arg0.value
                    opt = self._current_optional()
                    cond, cond_expr = self._current_condition()
                    self.imports.append(ImportRecord(
                        module=mod, names=[], is_from=False,
                        optional=opt, conditional=cond, condition=cond_expr,
                        lineno=node.lineno, col=node.col_offset, note="dynamic"
                    ))
        except Exception:
            pass
        self.generic_visit(node)

def is_relative_module(mod: str) -> bool:
    return mod.startswith(".")

def resolve_relative_module(curr_module: str, relative: str) -> Optional[str]:
    # relative вида "..attacks.base" или "." (вместо имени)
    if not curr_module:
        return None
    # Определим базовый пакет
    parts = curr_module.split(".")
    # Посчитаем точки
    dot_count = 0
    for ch in relative:
        if ch == '.':
            dot_count += 1
        else:
            break
    rem = relative[dot_count:]
    if dot_count > len(parts):
        return None
    base = ".".join(parts[:len(parts)-dot_count])
    if rem:
        if base:
            return f"{base}.{rem}"
        return rem
    else:
        return base or None

def collect_deps_for_file(root: str, path: str, package_roots: List[str], max_depth: int,
                          seen_files: Set[str], file_to_module: Dict[str, str],
                          deps_graph: Dict[str, Dict], missing_internal: Set[str]) -> None:
    """
    Обходит файл, парсит импорты и рекурсивно углубляется в "внутренние" модули.
    """
    path = normpath(path)
    if path in seen_files:
        return
    seen_files.add(path)

    try:
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
        tree = ast.parse(code, filename=path)
    except Exception as e:
        deps_graph[path] = {"module": file_to_module.get(path), "imports": [], "error": f"Parse error: {e}"}
        return

    curr_mod = file_to_module.get(path) or guess_module_name_from_path(root, path)
    if curr_mod:
        file_to_module[path] = curr_mod

    collector = ImportCollector()
    collector.visit(tree)

    imports_out = []
    deps_graph[path] = {"module": curr_mod, "imports": imports_out}

    for rec in collector.imports:
        # Нормализация модуля
        target_module = rec.module
        if is_relative_module(target_module):
            # convert relative to absolute using current module
            target_module = resolve_relative_module(curr_mod or "", target_module) or rec.module

        imports_out.append(rec.as_dict())

        # Решаем: внутренний ли это модуль?
        is_internal = False
        for pr in package_roots:
            if str(target_module or "").startswith(pr + ".") or target_module == pr:
                is_internal = True
                break

        # Резолвим путь
        if is_internal and target_module and max_depth > 0:
            tpath = resolve_module_to_path(root, target_module)
            if tpath and os.path.isfile(tpath):
                # Рекурсивно обходим
                if tpath not in seen_files:
                    file_to_module[tpath] = target_module
                    collect_deps_for_file(root, tpath, package_roots, max_depth-1,
                                          seen_files, file_to_module, deps_graph, missing_internal)
            else:
                missing_internal.add(target_module)

def build_report(root: str, entries: List[str], package_roots: List[str], max_depth: int = 20) -> Dict:
    root = normpath(root)
    # Приведем entries к путям
    resolved_entries: List[str] = []
    entry_modules: List[str] = []
    for e in entries:
        if os.path.isfile(e):
            p = normpath(e if os.path.isabs(e) else os.path.join(root, e))
            resolved_entries.append(p)
            mn = guess_module_name_from_path(root, p)
            if mn: entry_modules.append(mn)
        else:
            # пробуем как имя модуля
            t = resolve_module_to_path(root, e)
            if t and os.path.isfile(t):
                resolved_entries.append(t)
                entry_modules.append(e)
            else:
                # попытка относительного разрешения
                t2 = resolve_module_to_path(root, e.replace("/", ".").replace("\\", "."))
                if t2 and os.path.isfile(t2):
                    resolved_entries.append(t2)
                    entry_modules.append(e.replace("/", ".").replace("\\", "."))
                else:
                    print(f"[warn] Не удалось разрешить entry: {e}", file=sys.stderr)

    seen_files: Set[str] = set()
    file_to_module: Dict[str, str] = {}
    deps_graph: Dict[str, Dict] = {}
    missing_internal: Set[str] = set()

    # сначала сопоставим entry файлы с именами модулей
    for p in resolved_entries:
        mn = guess_module_name_from_path(root, p)
        if mn:
            file_to_module[p] = mn

    for p in resolved_entries:
        collect_deps_for_file(root, p, package_roots, max_depth, seen_files, file_to_module, deps_graph, missing_internal)

    # Классифицируем импорты (внутренние/внешние)
    internal_files = sorted(list(seen_files))
    internal_modules = sorted([file_to_module.get(p) for p in internal_files if file_to_module.get(p)])

    # Соберем внешние модули по графу
    external_modules: Set[str] = set()
    stdlib_modules: Set[str] = set()
    for f, info in deps_graph.items():
        for rec in info.get("imports", []):
            mod = rec.get("module") or ""
            if not mod or mod.startswith("."):
                continue
            is_internal = any((mod == pr or mod.startswith(pr + ".")) for pr in package_roots)
            if not is_internal:
                # берем верхний уровень (e.g., aiohttp из aiohttp.client)
                top = mod.split(".")[0]
                external_modules.add(top)

    # Пытаемся классифицировать — входит ли модуль в стандартную библиотеку
    try:
        stdlib_names = set(getattr(sys, "stdlib_module_names", set()))
    except Exception:
        stdlib_names = set()
    for m in list(external_modules):
        if m in stdlib_names:
            stdlib_modules.add(m)

    third_party_modules = sorted([m for m in external_modules if m not in stdlib_modules])

    # Список "что прислать": только файлы внутри package_roots (internal_files)
    # Отмечаем также "missing_internal" — это модули core.*, на которые есть ссылки, но нет файлов (в корне или пакетная структура отличается)
    summary = {
        "project_root": root,
        "entries": entry_modules,
        "package_roots": package_roots,
        "internal_files": internal_files,
        "internal_modules": internal_modules,
        "missing_internal_modules": sorted(list(missing_internal)),
        "external_modules_top_level": sorted(list(external_modules)),
        "stdlib_modules": sorted(list(stdlib_modules)),
        "third_party_modules": third_party_modules,
        "graph": deps_graph,
    }
    return summary

def copy_internal_files(report: Dict, root: str, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    for f in report.get("internal_files", []):
        rel = os.path.relpath(f, root)
        dst = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(f, dst)

def zip_internal_files(report: Dict, root: str, zip_path: str) -> None:
    os.makedirs(os.path.dirname(normpath(zip_path)) or ".", exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in report.get("internal_files", []):
            rel = os.path.relpath(f, root)
            zf.write(f, arcname=rel)

def human_readable_summary(report: Dict) -> str:
    lines = []
    lines.append("=== Dependency Trace Summary ===")
    lines.append(f"Project root: {report['project_root']}")
    lines.append(f"Entries: {', '.join(report.get('entries') or [])}")
    lines.append(f"Package roots (internal): {', '.join(report.get('package_roots') or [])}")
    lines.append("")
    lines.append(f"Internal modules/files to share ({len(report.get('internal_files', []))}):")
    for f in report.get("internal_files", []):
        lines.append(f"  - {os.path.relpath(f, report['project_root'])}")
    if report.get("missing_internal_modules"):
        lines.append("")
        lines.append("Missing internal modules (referenced but not found under root):")
        for m in report["missing_internal_modules"]:
            lines.append(f"  - {m}")
    lines.append("")
    lines.append(f"External top-level modules referenced ({len(report.get('external_modules_top_level', []))}):")
    for m in report.get("external_modules_top_level", []):
        tag = "stdlib" if m in set(report.get("stdlib_modules", [])) else "3rd-party"
        lines.append(f"  - {m} [{tag}]")
    lines.append("")
    lines.append("Tip: share all 'Internal modules/files' above. If 'Missing internal modules' appear,")
    lines.append("     check if your package layout differs, or include those packages as well.")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description="Static dependency tracer for Python modules (no code execution).")
    ap.add_argument("--root", default=".", help="Project root")
    ap.add_argument("--entries", nargs="+", required=True, help="Entry modules (files or dotted module names)")
    ap.add_argument("--package-roots", nargs="+", default=["core"], help="Top-level project packages considered internal (default: core)")
    ap.add_argument("--max-depth", type=int, default=20, help="Max recursion depth for internal deps")
    ap.add_argument("--output", default=None, help="Output JSON report path")
    ap.add_argument("--copy-to", default=None, help="Copy internal files to directory")
    ap.add_argument("--zip", dest="zip_path", default=None, help="Zip internal files to archive")
    args = ap.parse_args()

    root = normpath(args.root)
    report = build_report(root, args.entries, args.package_roots, max_depth=args.max_depth)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    print(human_readable_summary(report))

    if args.copy_to:
        copy_internal_files(report, root, args.copy_to)
        print(f"\n[info] Internal files copied to: {normpath(args.copy_to)}")

    if args.zip_path:
        zip_internal_files(report, root, args.zip_path)
        print(f"\n[info] Internal files zipped to: {normpath(args.zip_path)}")

if __name__ == "__main__":
    main()