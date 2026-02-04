"""
Safe expression evaluator for YAML spec rules.

Goal: evaluate simple boolean/numeric expressions safely (no attribute calls,
no dunder access, no imports, no comprehensions except generator-expr for all/any).
"""

from __future__ import annotations

import ast
import math
from typing import Any, Dict, Set, Mapping


_ALLOWED_CALLS = {
    "len",
    "all",
    "any",
    "range",
    "min",
    "max",
    "sum",
    "ceil",
    "join_bytes",
    "dict_items",
    "count_nop_options",
    "sorted_by_seq",
    "sorted_by_seq_desc",
    "is_permutation",
}


class _SafeEvalError(ValueError):
    pass


class AttrDict(dict):
    """
    dict с доступом к ключам через атрибуты (params.ttl вместо params['ttl']).
    Рекурсивно оборачивает вложенные dict.
    """

    def __getattr__(self, item: str) -> Any:
        try:
            val = self[item]
        except KeyError as e:
            raise AttributeError(item) from e
        return as_attrdict(val)

    # чтобы не ломать существующий dict-интерфейс:
    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        return as_attrdict(super().get(key, default))


def as_attrdict(value: Any) -> Any:
    """Рекурсивно оборачивает dict -> AttrDict; списки с dict тоже поддерживаются."""
    if isinstance(value, AttrDict):
        return value
    if isinstance(value, Mapping):
        return AttrDict({k: as_attrdict(v) for k, v in value.items()})
    if isinstance(value, list):
        return [as_attrdict(v) for v in value]
    return value


def safe_eval_expr(expr: str, names: Dict[str, Any]) -> Any:
    """
    Evaluate expression safely.

    Allowed:
      - bool ops: and/or/not
      - comparisons: == != < <= > >= in not in is is not
      - arithmetic: + - * // / % (basic)
      - subscripts: params["x"], packets[0]
      - attributes: packet.ttl (no leading underscore)
      - calls: len(...), all(...), any(...)
      - generator expr inside all/any: all(p.ttl in [64,128] for p in packets)
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise _SafeEvalError(f"Syntax error: {e}") from e

    bound: Set[str] = set()

    def check(node: ast.AST) -> None:
        if isinstance(node, ast.Expression):
            check(node.body)
            return

        # Literals / containers
        if isinstance(node, ast.Constant):
            return
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                check(elt)
            return
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if k is not None:
                    check(k)
            for v in node.values:
                check(v)
            return

        # Names
        if isinstance(node, ast.Name):
            if node.id.startswith("__") or node.id.endswith("__"):
                raise _SafeEvalError("Dunder names are not allowed")
            if node.id in bound:
                return
            if node.id in names:
                return
            # allow True/False/None as names in some python versions (usually Constant)
            if node.id in {"True", "False", "None"}:
                return
            raise _SafeEvalError(f"Unknown name: {node.id}")

        # Attribute access: forbid private/dunder
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_") or "__" in node.attr:
                raise _SafeEvalError("Private/dunder attributes are not allowed")
            check(node.value)
            return

        # Subscript
        if isinstance(node, ast.Subscript):
            check(node.value)
            check(node.slice)
            return
        if isinstance(node, ast.Slice):
            if node.lower:
                check(node.lower)
            if node.upper:
                check(node.upper)
            if node.step:
                check(node.step)
            return

        # Boolean / arithmetic
        if isinstance(node, ast.BoolOp):
            for v in node.values:
                check(v)
            return
        if isinstance(node, ast.UnaryOp):
            if not isinstance(node.op, (ast.Not, ast.UAdd, ast.USub)):
                raise _SafeEvalError("Unary op is not allowed")
            check(node.operand)
            return
        if isinstance(node, ast.BinOp):
            if not isinstance(
                node.op,
                (
                    ast.Add,
                    ast.Sub,
                    ast.Mult,
                    ast.Div,
                    ast.FloorDiv,
                    ast.Mod,
                ),
            ):
                raise _SafeEvalError("Binary op is not allowed")
            check(node.left)
            check(node.right)
            return

        # Comparisons
        if isinstance(node, ast.Compare):
            check(node.left)
            for op in node.ops:
                if not isinstance(
                    op,
                    (
                        ast.Eq,
                        ast.NotEq,
                        ast.Lt,
                        ast.LtE,
                        ast.Gt,
                        ast.GtE,
                        ast.In,
                        ast.NotIn,
                        ast.Is,
                        ast.IsNot,
                    ),
                ):
                    raise _SafeEvalError("Compare op is not allowed")
            for c in node.comparators:
                check(c)
            return

        # Ternary expression: a if cond else b
        if isinstance(node, ast.IfExp):
            check(node.test)
            check(node.body)
            check(node.orelse)
            return

        # Calls (only len/all/any)
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise _SafeEvalError("Only simple calls are allowed")
            if node.func.id not in _ALLOWED_CALLS:
                raise _SafeEvalError(f"Call not allowed: {node.func.id}")
            if node.keywords:
                raise _SafeEvalError("Keyword arguments are not allowed")
            for a in node.args:
                check(a)
            return

        # Generator expressions (for all/any)
        if isinstance(node, ast.GeneratorExp):
            # Process generators first to bind variables
            for gen in node.generators:
                check(gen)
            check(node.elt)
            return

        if isinstance(node, ast.comprehension):
            # for p in packets OR for k,v in items(...)
            if isinstance(node.target, ast.Name):
                targets = [node.target]
            elif isinstance(node.target, ast.Tuple) and all(
                isinstance(e, ast.Name) for e in node.target.elts
            ):
                targets = list(node.target.elts)  # type: ignore[assignment]
            else:
                raise _SafeEvalError("Only name or tuple-of-names targets are allowed")

            for t in targets:
                if t.id.startswith("_") or "__" in t.id:
                    raise _SafeEvalError("Bad comprehension target name")
            check(node.iter)
            for t in targets:
                bound.add(t.id)
            for if_ in node.ifs:
                check(if_)
            return

        # Everything else is forbidden
        raise _SafeEvalError(f"AST node not allowed: {node.__class__.__name__}")

    check(tree)

    # Merge names into globals to make them visible in generator expressions
    env = {"__builtins__": {}}
    env.update(names)
    return eval(compile(tree, "<spec-rule>", "eval"), env, {})
