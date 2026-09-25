"""Render Sigma selections and a condition AST into a Splunk search expression."""

from __future__ import annotations

from typing import Any, List, Set, Tuple

from . import condition as cond
from .errors import UnsupportedSigma
from .mapping import Mapping, Resolved
from .sigma import SigmaRule

# Value modifiers we translate. Anything else -> the rule is skipped (honest over wrong).
_STRING_MODS = {"contains", "startswith", "endswith"}
_NUMERIC_OPS = {"lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
_IGNORED_MODS = {"cased", "windash"}  # search is case-insensitive; windash handled by wildcards
_UNSUPPORTED_MODS = {
    "re": "regex modifier (|re)",
    "cidr": "CIDR modifier (|cidr)",
    "base64": "base64 modifier",
    "base64offset": "base64offset modifier",
    "utf16": "utf16 modifier",
    "utf16le": "utf16 modifier",
    "utf16be": "utf16 modifier",
    "wide": "wide modifier",
    "fieldref": "fieldref modifier",
    "expand": "expand modifier",
    "exists": "exists modifier",
}


class Renderer:
    def __init__(self, rule: SigmaRule, mapping: Mapping, resolved: Resolved) -> None:
        self.rule = rule
        self.mapping = mapping
        self.resolved = resolved
        self.notes: Set[str] = set()
        self.used_fields: Set[str] = set()  # mapped field names the condition references

    # -- values ---------------------------------------------------------------

    def _escape_value(self, raw: str) -> str:
        """Sigma string -> the inside of a Splunk double-quoted value, with wildcards."""
        out: List[str] = []
        i = 0
        while i < len(raw):
            ch = raw[i]
            if ch == "\\" and i + 1 < len(raw) and raw[i + 1] in "*?\\":
                nxt = raw[i + 1]
                if nxt == "\\":
                    out.append("\\\\")
                else:
                    out.append(nxt)  # a literal * or ?, which Splunk search can't match precisely
                    self.notes.add("a literal * or ? was approximated")
                i += 2
                continue
            if ch == "*":
                out.append("*")
            elif ch == "?":
                out.append("*")  # Splunk has no single-char wildcard
                self.notes.add("Sigma '?' (single char) approximated as '*'")
            elif ch == '"':
                out.append('\\"')
            elif ch == "\\":
                out.append("\\\\")
            else:
                out.append(ch)
            i += 1
        return "".join(out)

    def _literal(self, value: Any, modifier: str) -> str:
        if isinstance(value, bool):
            return f'"{str(value).lower()}"'
        if isinstance(value, (int, float)):
            return str(value)
        body = self._escape_value(str(value))
        if modifier == "contains":
            body = f"*{body}*"
        elif modifier == "startswith":
            body = f"{body}*"
        elif modifier == "endswith":
            body = f"*{body}"
        return f'"{body}"'

    # -- one field:value entry ------------------------------------------------

    def _field_match(self, raw_key: str, value: Any) -> str:
        parts = raw_key.split("|")
        field = self.mapping.map_field(parts[0], self.resolved)
        mods = [m.lower() for m in parts[1:]]
        for m in mods:
            if m in _UNSUPPORTED_MODS:
                raise UnsupportedSigma(_UNSUPPORTED_MODS[m])
        for m in mods:
            if m in _IGNORED_MODS:
                self.notes.add(f"ignored |{m} (Splunk search is case-insensitive)")

        self.used_fields.add(field)
        numeric = next((m for m in mods if m in _NUMERIC_OPS), None)
        if numeric:
            if isinstance(value, list):
                raise UnsupportedSigma(f"|{numeric} with a list of values")
            return f"{field}{_NUMERIC_OPS[numeric]}{value}"

        string_mod = next((m for m in mods if m in _STRING_MODS), "")

        if value is None:
            return f'NOT {field}="*"'  # Sigma null = field absent
        if isinstance(value, list):
            if not value:
                raise UnsupportedSigma("empty value list")
            terms = [self._one(field, v, string_mod) for v in value]
            joiner = " AND " if "all" in mods else " OR "
            return terms[0] if len(terms) == 1 else "(" + joiner.join(terms) + ")"
        return self._one(field, value, string_mod)

    def _one(self, field: str, value: Any, string_mod: str) -> str:
        if value is None:
            return f'NOT {field}="*"'
        return f"{field}={self._literal(value, string_mod)}"

    # -- a whole selection ----------------------------------------------------

    def _selection(self, name: str) -> str:
        body = self.rule.selections[name]
        if isinstance(body, dict):
            return self._and_map(body)
        if isinstance(body, list):
            if all(isinstance(item, dict) for item in body):
                groups = [self._and_map(item) for item in body]
                return "(" + " OR ".join(groups) + ")" if len(groups) > 1 else groups[0]
            # a list of bare strings = OR of full-text keyword searches
            terms = [self._keyword(item) for item in body]
            return "(" + " OR ".join(terms) + ")" if len(terms) > 1 else terms[0]
        # a bare scalar selection = a single full-text keyword
        return self._keyword(body)

    def _and_map(self, body: dict) -> str:
        if not body:
            raise UnsupportedSigma("empty selection")
        terms = [self._field_match(k, v) for k, v in body.items()]
        return "(" + " AND ".join(terms) + ")" if len(terms) > 1 else terms[0]

    def _keyword(self, value: Any) -> str:
        return f'"{self._escape_value(str(value))}"'

    # -- the condition AST ----------------------------------------------------

    def render_condition(self, node: cond.Node) -> str:
        if isinstance(node, cond.Ref):
            return self._selection(node.name)
        if isinstance(node, cond.Not):
            return f"NOT {self._wrap(node.node)}"
        if isinstance(node, cond.And):
            return "(" + " AND ".join(self.render_condition(n) for n in node.nodes) + ")"
        if isinstance(node, cond.Or):
            return "(" + " OR ".join(self.render_condition(n) for n in node.nodes) + ")"
        raise UnsupportedSigma(f"unhandled condition node {type(node).__name__}")

    def _wrap(self, node: cond.Node) -> str:
        rendered = self.render_condition(node)
        if isinstance(node, cond.Ref) and not rendered.startswith("("):
            return f"({rendered})"
        return rendered


def render_spl(rule: SigmaRule, mapping: Mapping, resolved: Resolved) -> Tuple[str, List[str]]:
    """Return (spl, notes). Raises UnsupportedSigma for features that don't translate."""
    renderer = Renderer(rule, mapping, resolved)
    tree = cond.expand(cond.parse_condition(rule.condition), list(rule.selections))
    body = renderer.render_condition(tree)

    base_terms = []
    if resolved.index:
        base_terms.append(f"index={resolved.index}")
    if resolved.sourcetype:
        base_terms.append(f'sourcetype="{resolved.sourcetype}"')
    if resolved.base:
        base_terms.append(resolved.base)
    base = " ".join(base_terms)
    if not base:
        renderer.notes.add("no index/sourcetype mapped for this logsource; add one to your mapping")

    # If the mapping declares an extract table (dotted JSON -> alias) and this rule uses
    # fields that need it, emit `| spath` stages so the search runs on the raw JSON as-is.
    stages = []
    if resolved.extract and base:
        for alias in sorted(f for f in renderer.used_fields if f in resolved.extract):
            stages.append(f"| spath input=_raw path={resolved.extract[alias]} output={alias}")
        for alias in sorted(f for f in renderer.used_fields if f not in resolved.extract):
            renderer.notes.add(f"no extract path for '{alias}'; it won't be pulled from _raw")
    if stages:
        spl = base + "\n" + "\n".join(stages) + f"\n| search {body}"
    else:
        spl = f"{base} {body}".strip() if base else body
    return spl, sorted(renderer.notes)
