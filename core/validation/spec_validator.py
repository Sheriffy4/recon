"""
Spec Validator - Validates attacks using YAML specifications.

This module provides spec-based validation functionality, applying
validation rules defined in attack specifications to parsed packets.
"""

import re
import math
from typing import List, Dict, Any
from .safe_eval import safe_eval_expr, as_attrdict


class SpecValidator:
    """
    Validates attacks using YAML specifications.

    This validator loads attack specifications and applies their
    validation rules to parsed packets.
    """

    def __init__(self, spec_loader, validation_detail_class, validation_severity_class):
        """
        Initialize SpecValidator.

        Args:
            spec_loader: Attack specification loader
            validation_detail_class: ValidationDetail class for creating details
            validation_severity_class: ValidationSeverity enum for severity levels
        """
        self.spec_loader = spec_loader
        self.ValidationDetail = validation_detail_class
        self.ValidationSeverity = validation_severity_class

    def validate_with_spec(
        self,
        attack_name: str,
        params: Dict[str, Any],
        packets: List,
        result,
    ):
        """
        Validate attack using YAML specification.

        Args:
            attack_name: Name of attack
            params: Attack parameters
            packets: Parsed PacketData objects
            result: ValidationResult to update
        """
        if not self.spec_loader:
            result.passed = False
            result.error = "Spec loader not available"
            return

        # Load attack specification
        spec = self.spec_loader.load_spec(attack_name)
        if not spec:
            result.passed = False
            result.error = f"No specification found for attack: {attack_name}"
            return

        # Validate parameters against spec
        param_errors = self.spec_loader.validate_parameters(attack_name, params)
        if param_errors:
            result.passed = False
            result.error = f"Parameter validation failed: {'; '.join(param_errors)}"
            for error in param_errors:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="parameters",
                        passed=False,
                        message=error,
                        severity=self.ValidationSeverity.CRITICAL,
                    )
                )
            return

        # Apply validation rules from spec
        self.apply_spec_validation_rules(spec, packets, params, result)

    def apply_spec_validation_rules(
        self,
        spec,
        packets: List,
        params: Dict[str, Any],
        result,
    ):
        """
        Apply validation rules from spec to packets.

        Args:
            spec: Attack specification
            packets: Parsed PacketData objects
            params: Attack parameters
            result: ValidationResult to update
        """
        # Import rule evaluators

        # Apply each category of validation rules
        for category, rules in spec.validation_rules.items():
            for rule in rules:
                try:
                    # Evaluate rule
                    rule_passed = self._evaluate_validation_rule(rule, packets, params, spec)

                    severity = self.ValidationSeverity.CRITICAL
                    if rule.severity == "warning":
                        severity = self.ValidationSeverity.WARNING
                    elif rule.severity == "info":
                        severity = self.ValidationSeverity.INFO
                    elif rule.severity == "error":
                        severity = self.ValidationSeverity.ERROR

                    detail = self.ValidationDetail(
                        aspect=category,
                        passed=rule_passed,
                        message=rule.description,
                        severity=severity,
                    )

                    result.add_detail(detail)

                except (AttributeError, KeyError, TypeError) as e:
                    # Rule attribute/structure error
                    result.add_detail(
                        self.ValidationDetail(
                            aspect=category,
                            passed=False,
                            message=f"Rule structure error: {rule.description} - {str(e)}",
                            severity=self.ValidationSeverity.ERROR,
                        )
                    )
                except (ValueError, SyntaxError) as e:
                    # Rule evaluation error
                    result.add_detail(
                        self.ValidationDetail(
                            aspect=category,
                            passed=False,
                            message=f"Rule evaluation error: {rule.description} - {str(e)}",
                            severity=self.ValidationSeverity.ERROR,
                        )
                    )
                except Exception as e:
                    # Unexpected error
                    result.add_detail(
                        self.ValidationDetail(
                            aspect=category,
                            passed=False,
                            message=f"Rule evaluation failed: {rule.description} - {str(e)}",
                            severity=self.ValidationSeverity.ERROR,
                        )
                    )

    def _evaluate_validation_rule(
        self,
        rule,
        packets: List,
        params: Dict[str, Any],
        spec,
    ) -> bool:
        """
        Evaluate a single validation rule.

        Args:
            rule: Validation rule to evaluate
            packets: Parsed PacketData objects
            params: Attack parameters
            spec: Attack specification

        Returns:
            True if rule passes, False otherwise
        """
        rule_str = self._normalize_rule_string(rule.rule)

        params_obj = as_attrdict(params)
        ctx = self._build_spec_context(packets, params_obj)

        names: Dict[str, Any] = {
            "params": params_obj,
            "packets": packets,
            "len": len,
            "all": all,
            "any": any,
            "range": range,
            "min": min,
            "max": max,
            "sum": sum,
            "ceil": math.ceil,
            # helper fns for YAML rules
            "join_bytes": self._join_bytes,
            "dict_items": self._dict_items,
            "count_nop_options": self._count_nop_options,
            "sorted_by_seq": self._sorted_by_seq,
            "sorted_by_seq_desc": self._sorted_by_seq_desc,
            "is_permutation": self._is_permutation,
            # constants
            "True": True,
            "False": False,
            "None": None,
        }

        # inject derived context variables
        names.update(ctx)
        return bool(safe_eval_expr(rule_str, names))

    def _build_spec_context(self, packets: List[Any], params_obj: Any) -> Dict[str, Any]:
        """
        Build variables used by YAML specs:
          - segments / fragments (real payload packets sorted by seq)
          - original_seq / original_payload / payload_length
          - first_part / second_part
          - fake_packet / real_packet / real_part1 / real_part2
          - split_pos / overlap_size / split_seqovl
          - manipulated_packet / restore_packet / modified_packet
        """
        payload_packets = [p for p in packets if getattr(p, "payload_length", 0) > 0]

        fake_packets = [p for p in payload_packets if getattr(p, "is_fake_packet", lambda: False)()]
        real_payload = [p for p in payload_packets if p not in fake_packets]

        segments = sorted(
            (real_payload or payload_packets),
            key=lambda p: getattr(p, "seq", getattr(p, "sequence_num", 0)),
        )
        fragments = segments  # alias

        original_seq = segments[0].seq if segments else None
        original_payload = self._reassemble_payload(segments, original_seq) if segments else b""

        # common named parts
        first_part = segments[0] if len(segments) >= 1 else None
        second_part = segments[1] if len(segments) >= 2 else None

        fake_packet = fake_packets[0] if fake_packets else None
        real_packet = segments[0] if segments else None

        # fakeddisorder naming: real_part1 = low-seq, real_part2 = high-seq
        real_part1 = first_part
        real_part2 = second_part

        split_pos = getattr(params_obj, "split_pos", None) or getattr(
            params_obj, "split_position", None
        )
        split_seqovl = (
            getattr(params_obj, "split_seqovl", None) or getattr(params_obj, "overlap_size", 0) or 0
        )
        overlap_size = getattr(params_obj, "overlap_size", None)
        if overlap_size is None:
            overlap_size = split_seqovl

        # window/tcp-options attacks may refer to these
        manipulated_packet = next((p for p in packets if getattr(p, "payload_length", 0) > 0), None)
        restore_packet = next(
            (
                p
                for p in packets
                if getattr(p, "payload_length", 0) == 0 and ("ACK" in getattr(p, "flags", []))
            ),
            None,
        )
        modified_packet = packets[0] if packets else None

        return {
            "payload_packets": payload_packets,
            "segments": segments,
            "fragments": fragments,
            "original_seq": original_seq,
            "original_payload": original_payload,
            "payload_length": len(original_payload),
            "first_part": first_part,
            "second_part": second_part,
            "fake_packet": fake_packet,
            "real_packet": real_packet,
            "real_part1": real_part1,
            "real_part2": real_part2,
            "split_pos": split_pos,
            "split_seqovl": split_seqovl,
            "overlap_size": overlap_size,
            "manipulated_packet": manipulated_packet,
            "restore_packet": restore_packet,
            "modified_packet": modified_packet,
        }

    def _reassemble_payload(self, segs: List[Any], base_seq: int | None) -> bytes:
        """
        Reassemble payload from TCP segments by sequence number.
        Prefer earlier data on overlaps (typical TCP reassembly behaviour for capture validation).
        """
        if not segs or base_seq is None:
            return b""

        # Determine required length
        max_end = 0
        for p in segs:
            off = (p.seq - base_seq) & 0xFFFFFFFF
            end = off + len(p.payload)
            if end > max_end:
                max_end = end

        buf = bytearray(b"\x00" * max_end)
        filled = bytearray(b"\x00" * max_end)  # 0=empty 1=filled

        for p in segs:
            off = (p.seq - base_seq) & 0xFFFFFFFF
            data = p.payload
            for i, b in enumerate(data):
                pos = off + i
                if pos >= max_end:
                    break
                if filled[pos] == 0:
                    buf[pos] = b
                    filled[pos] = 1

        return bytes(buf)

    # --- helper functions used in YAML expressions ---
    @staticmethod
    def _join_bytes(items) -> bytes:
        return b"".join(items)

    @staticmethod
    def _dict_items(d) -> list:
        try:
            return list(d.items())
        except Exception:
            return []

    @staticmethod
    def _count_nop_options(pkt) -> int:
        try:
            opts = getattr(pkt, "tcp_options", {}) or {}
            return int(opts.get("nop", 0) or 0)
        except Exception:
            return 0

    @staticmethod
    def _sorted_by_seq(items) -> list:
        return sorted(items, key=lambda x: getattr(x, "seq", getattr(x, "sequence_num", 0)))

    @staticmethod
    def _sorted_by_seq_desc(items) -> list:
        return sorted(
            items, key=lambda x: getattr(x, "seq", getattr(x, "sequence_num", 0)), reverse=True
        )

    @staticmethod
    def _is_permutation(order, n: int) -> bool:
        try:
            if order is None:
                return False
            if len(order) != n:
                return False
            return set(order) == set(range(n))
        except Exception:
            return False

    def _normalize_rule_string(self, rule_str: str) -> str:
        """
        Нормализация правил из YAML под Python-expression:

        1) statement-like if:
           "if cond: expr" -> "(not (cond)) or (expr)"
           "if cond: a else b" -> "(a) if (cond) else (b)"

        2) statement-like for:
           "for x in xs: expr" -> "all((expr) for x in xs)"
        """
        s = (rule_str or "").strip()

        # 0) remove common annotations like "(in logical order)" or "(in send order)"
        s = re.sub(r"\s*\(in [^)]+\)\s*", "", s)

        # 0.1) normalize common join patterns: b''.join(...) or ''.join(...)
        s = s.replace("b''.join(", "join_bytes(")
        s = s.replace("''.join(", "join_bytes(")
        s = s.replace('b"".join(', "join_bytes(")
        s = s.replace('"".join(', "join_bytes(")

        # 0.2) normalize sorted(..., key=lambda x: x.seq) patterns (keywords not allowed in safe eval)
        # packets == list(reversed(sorted(packets, key=lambda x: x.seq)))
        s = re.sub(
            r"list\s*\(\s*reversed\s*\(\s*sorted\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*key\s*=\s*lambda\s+\w+\s*:\s*\w+\.seq\s*\)\s*\)\s*\)",
            r"sorted_by_seq_desc(\1)",
            s,
        )
        s = re.sub(
            r"sorted\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*key\s*=\s*lambda\s+\w+\s*:\s*\w+\.seq\s*\)",
            r"sorted_by_seq(\1)",
            s,
        )

        # 0.3) normalize dict.items() usage (attribute calls forbidden)
        s = s.replace("params.modify_options.items()", "dict_items(params.modify_options)")

        # if cond: expr [else expr]
        if s.startswith("if ") and ":" in s:
            after_if = s[3:]
            cond, rest = after_if.split(":", 1)
            cond = cond.strip()
            rest = rest.strip()
            if " else " in rest:
                a, b = rest.split(" else ", 1)
                return f"({a.strip()}) if ({cond}) else ({b.strip()})"
            return f"(not ({cond})) or ({rest})"

        # special-case: for opt, val in dict_items(...): expr
        # -> all((expr) for opt, val in dict_items(...))
        if s.startswith("for ") and ":" in s and " in " in s:
            head, body = s.split(":", 1)
            head = head[4:].strip()
            var, it = head.split(" in ", 1)
            var = var.strip()
            it = it.strip()
            body = body.strip()
            return f"all(({body}) for {var} in ({it}))"

        # for x in xs: expr
        if s.startswith("for ") and ":" in s:
            head, body = s.split(":", 1)
            head = head[4:].strip()  # remove "for "
            if " in " in head:
                var, it = head.split(" in ", 1)
                return f"all(({body.strip()}) for {var.strip()} in ({it.strip()}))"

        return s
