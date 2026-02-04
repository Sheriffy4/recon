from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "node_modules",
    ".intellirefactor",
}


IMPORTLIB_RE = re.compile(
    r"""import_module\(\s*['"](?P<mod>[^'"]+)['"]\s*\)""",
    flags=re.IGNORECASE,
)


@dataclass(frozen=True)
class FileInfo:
    path: Path
    sha256: str
    size: int
    import_names: Tuple[str, ...]  # possible module import paths


def iter_python_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        # prune
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                yield Path(dirpath) / fn


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_package_dir(d: Path) -> bool:
    return (d / "__init__.py").exists()


def infer_import_names(root: Path, file_path: Path) -> Tuple[str, ...]:
    """
    Infer likely module import paths for a .py file.
    Examples:
      <root>/real_world_tester.py -> ("real_world_tester",)
      <root>/core/real_world_tester.py -> ("core.real_world_tester",) if core is a package.
    """
    rel = file_path.relative_to(root).as_posix()
    if not rel.endswith(".py"):
        return tuple()

    if rel == "__init__.py":
        # not useful to dedup usually
        return tuple()

    mod_base = rel[:-3].replace("/", ".")  # strip .py
    parts = rel.split("/")

    # If inside package chain, ensure dirs are packages (have __init__.py)
    # e.g. core/x.py -> require core/__init__.py
    # e.g. a/b/c.py -> require a/__init__.py and a/b/__init__.py
    dirs = parts[:-1]
    if not dirs:
        return (mod_base,)

    pkg_ok = True
    cur = root
    for d in dirs:
        cur = cur / d
        if not is_package_dir(cur):
            pkg_ok = False
            break

    if pkg_ok:
        return (mod_base,)

    # Not a package chain; still could be imported if root is on sys.path
    # but dotted name with non-packages is invalid; only allow basename import
    return (parts[-1][:-3],)


def parse_import_refs(py_text: str) -> Set[str]:
    """
    Return set of module names referenced via import statements or importlib.import_module.
    Normalizes:
      - import core.real_world_tester -> "core.real_world_tester"
      - from core import real_world_tester -> "core.real_world_tester"
      - from core.real_world_tester import X -> "core.real_world_tester"
      - import real_world_tester -> "real_world_tester"
    """
    out: Set[str] = set()

    # importlib.import_module("x.y")
    for m in IMPORTLIB_RE.finditer(py_text):
        out.add(m.group("mod"))

    try:
        tree = ast.parse(py_text)
    except Exception:
        return out

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name:
                    out.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                # relative import: hard to resolve without package context; ignore here
                continue
            mod = node.module or ""
            if mod:
                out.add(mod)
                # handle "from core import real_world_tester"
                for alias in node.names:
                    name = alias.name
                    if name and name != "*":
                        out.add(f"{mod}.{name}")
    return out


def scan_project_import_usage(root: Path, candidate_modules: Set[str], max_files: int = 5000) -> Dict[str, List[str]]:
    """
    Scan project for import references. Returns module -> list of "file:line" occurrences.
    We keep it cheap: first match per file.
    """
    hits: Dict[str, List[str]] = {m: [] for m in candidate_modules}
    files = list(iter_python_files(root))[:max_files]

    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        mods = parse_import_refs(text)
        matched = mods.intersection(candidate_modules)
        if not matched:
            continue

        # find first line containing any module token for a crude location
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            for m in matched:
                # very cheap check
                if m in line:
                    hits[m].append(f"{fp.relative_to(root).as_posix()}:{i}")
            # keep scanning few lines only? we can break early for speed
            if i > 200:
                break

    # drop empties
    return {k: v for k, v in hits.items() if v}


def choose_canonical(files: List[FileInfo], usage: Dict[str, List[str]]) -> Tuple[Optional[FileInfo], Dict[str, int]]:
    """
    Decide which file to keep based on import usage counts.
    Returns: (canonical_file or None, per_file_score)
    """
    score_by_path: Dict[str, int] = {f.path.as_posix(): 0 for f in files}

    # sum usages over all import names of each file
    for f in files:
        score = 0
        for name in f.import_names:
            score += len(usage.get(name, []))
        score_by_path[f.path.as_posix()] = score

    # pick max score
    best = max(files, key=lambda f: (score_by_path[f.path.as_posix()], -len(f.path.as_posix())))
    best_score = score_by_path[best.path.as_posix()]

    if best_score == 0:
        return None, score_by_path

    return best, score_by_path


def archive_move(root: Path, src: Path, archive_root: Path) -> Path:
    rel = src.relative_to(root)
    dst = archive_root / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return dst


def main() -> None:
    ap = argparse.ArgumentParser(description="Detect exact duplicate files by SHA256 and archive unused copies.")
    ap.add_argument("--root", required=True, help="Project root")
    ap.add_argument("--apply", action="store_true", help="Actually move duplicates to archive (default: dry-run)")
    ap.add_argument("--archive-dir", default="archive/duplicates", help="Archive directory under root")
    ap.add_argument("--min-bytes", type=int, default=200, help="Ignore tiny files smaller than this")
    ap.add_argument("--max-scan-files", type=int, default=5000, help="Cap files scanned for imports")
    ap.add_argument("--report", default="dedup_exact_report.json", help="Report JSON file path under root")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    archive_base = root / args.archive_dir
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_root = archive_base / ts

    # 1) compute hashes
    infos: List[FileInfo] = []
    for fp in iter_python_files(root):
        try:
            size = fp.stat().st_size
        except Exception:
            continue
        if size < args.min_bytes:
            continue
        try:
            sha = sha256_file(fp)
        except Exception:
            continue
        import_names = infer_import_names(root, fp)
        infos.append(FileInfo(path=fp, sha256=sha, size=size, import_names=import_names))

    groups: Dict[str, List[FileInfo]] = {}
    for fi in infos:
        groups.setdefault(fi.sha256, []).append(fi)

    dup_groups = {h: fs for h, fs in groups.items() if len(fs) > 1}

    # 2) build candidate module set
    candidate_modules: Set[str] = set()
    for fs in dup_groups.values():
        for f in fs:
            candidate_modules.update(f.import_names)

    # 3) scan usage
    usage = scan_project_import_usage(root, candidate_modules, max_files=args.max_scan_files)

    # 4) decisions
    decisions = []
    for h, fs in sorted(dup_groups.items(), key=lambda x: (-sum(f.size for f in x[1]), x[0])):
        canonical, score_by_path = choose_canonical(fs, usage)

        entry = {
            "sha256": h,
            "files": [f.path.relative_to(root).as_posix() for f in fs],
            "sizes": {f.path.relative_to(root).as_posix(): f.size for f in fs},
            "import_names": {f.path.relative_to(root).as_posix(): list(f.import_names) for f in fs},
            "usage_counts": score_by_path,
            "usage_hits": {m: usage.get(m, []) for m in candidate_modules if usage.get(m)},
            "canonical": canonical.path.relative_to(root).as_posix() if canonical else None,
            "action": None,
            "moved": [],
            "notes": [],
        }

        if canonical is None:
            entry["action"] = "no_auto_action"
            entry["notes"].append("No import usage detected for any duplicate; keep as-is (manual review).")
            decisions.append(entry)
            continue

        # move others
        to_move = [f for f in fs if f.path != canonical.path]
        entry["action"] = "archive_non_canonical"
        entry["notes"].append("Canonical chosen by highest import usage count. Others will be archived.")
        if args.apply:
            for f in to_move:
                moved_to = archive_move(root, f.path, archive_root)
                entry["moved"].append(
                    {
                        "from": f.path.relative_to(root).as_posix(),
                        "to": moved_to.relative_to(root).as_posix(),
                    }
                )
        decisions.append(entry)

    report = {
        "root": str(root),
        "timestamp": ts,
        "duplicate_group_count": len(dup_groups),
        "scanned_files": len(infos),
        "decisions": decisions,
    }

    report_path = root / args.report
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Duplicate groups: {len(dup_groups)}")
    print(f"Report written: {report_path}")
    if args.apply and any(d.get("moved") for d in decisions):
        print(f"Archived into: {archive_root}")


if __name__ == "__main__":
    main()